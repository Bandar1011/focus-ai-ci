"""Exercise the real UID boundary using only public fixture code, without secrets."""
import json
import os
from pathlib import Path
import sys

import ci
from isolation import PrivateUser


NATIVE = r'''
import json, os, pathlib, subprocess, time
root = pathlib.Path.cwd()
developer = '/Applications/Xcode_27.0.app/Contents/Developer'
os.environ['DEVELOPER_DIR'] = developer
def run(*args):
    subprocess.run(args, check=True)
inventory = json.loads(subprocess.check_output(['xcrun','simctl','list','devices','available','--json']))['devices']
devices = [d for runtime, group in inventory.items() if runtime.endswith('iOS-27-0') for d in group]
assert devices and all(d['state'] == 'Shutdown' for d in devices)
device = devices[0]['udid']
profile = root / 'simslim.json'
profile.write_text(json.dumps({'name':'public-canary','except':['widgets','store'],'keep':[]}))
try:
    run('simslim','on',device,'--profile',str(profile))
    run('simslim','verify',device,'--profile',str(profile))
    run('xcrun','simctl','bootstatus',device,'-b')
    run('xcodegen','generate')
    command = ['xcodebuild','-project','Canary.xcodeproj','-scheme','Canary','-configuration','Debug',
               '-destination','platform=iOS Simulator,id='+device,'-derivedDataPath',str(root/'build'),
               '-jobs','2','-parallel-testing-enabled','NO','COMPILER_INDEX_STORE_ENABLE=NO',
               'CODE_SIGNING_ALLOWED=NO']
    run(*command, 'build-for-testing')
    command += ['test-without-building']
    process = subprocess.Popen(command)
    saw_service = saw_app = saw_tests = False
    while process.poll() is None:
        rows = subprocess.check_output(['ps','-axo','uid=,comm='],text=True)
        for row in rows.splitlines():
            parts = row.strip().split(None,1)
            if len(parts) != 2: continue
            uid, name = int(parts[0]), parts[1]
            if uid == os.getuid() and 'CoreSimulatorService' in name: saw_service = True
            if '/Canary.app/Canary' in name:
                assert uid == os.getuid()
                saw_app = True
            if 'CanaryUITests-Runner' in name or '/Canary.app/' in name and 'xctest' in name:
                assert uid == os.getuid()
                saw_tests = True
        time.sleep(.2)
    assert process.returncode == 0
    assert saw_service and saw_app and saw_tests, 'Required native process UID evidence is missing'
finally:
    run('xcrun','simctl','shutdown',device)
print('native-uid-canary-ok')
'''


def main():
    root = ci.private_root()
    ci.prepare(root, ci.owner())
    worker = root / "worker"
    (worker / "source").mkdir(parents=True)
    (worker / "evidence").mkdir()
    ci.write_json(root / "evidence/receipt.json", dict(identity="runner-only-canary"))
    env = ci.execution_environment(worker / "evidence")
    if os.environ["RUNNER_OS"] == "macOS":
        source = worker / "source"
        for name in ["App", "Tests", "UITests"]:
            (source / name).mkdir()
        (source / "App/Canary.swift").write_text('''import SwiftUI
@main struct Canary: App { var body: some Scene { WindowGroup {
Text("CI Canary").accessibilityIdentifier("canary") } } }
''')
        (source / "Tests/CanaryTests.swift").write_text('''import XCTest
final class CanaryTests: XCTestCase { func testRuns() { XCTAssertEqual(2 + 2, 4) } }
''')
        (source / "UITests/CanaryUITests.swift").write_text('''import XCTest
final class CanaryUITests: XCTestCase {
func testLaunch() { let app = XCUIApplication(); app.launch()
XCTAssertTrue(app.staticTexts["canary"].waitForExistence(timeout: 10))
Thread.sleep(forTimeInterval: 2) }
}
''')
        (source / "project.yml").write_text('''name: Canary
options:
  deploymentTarget:
    iOS: '27.0'
settings:
  base:
    GENERATE_INFOPLIST_FILE: YES
    CODE_SIGNING_ALLOWED: NO
    SWIFT_VERSION: '6.0'
targets:
  Canary:
    type: application
    platform: iOS
    sources: [App]
    settings:
      base:
        PRODUCT_BUNDLE_IDENTIFIER: com.example.ciprivacycanary
  CanaryTests:
    type: bundle.unit-test
    platform: iOS
    sources: [Tests]
    dependencies:
      - target: Canary
  CanaryUITests:
    type: bundle.ui-testing
    platform: iOS
    sources: [UITests]
    dependencies:
      - target: Canary
schemes:
  Canary:
    build:
      targets:
        Canary: all
    test:
      targets: [CanaryTests, CanaryUITests]
''')
    with PrivateUser(root, ["isolation.log", "canary.log"]) as isolated:
        isolated.probe(env)
        program = ("import os,pathlib; print('::error::PRIVATE_CANARY_OUTPUT'); "
                   "pathlib.Path(os.environ['GITHUB_STEP_SUMMARY']).write_text('private command output')")
        isolated.run([sys.executable, "-c", program],
                     worker / "source", "canary.log", env, 30)
        if os.environ["RUNNER_OS"] == "macOS":
            isolated.run([sys.executable, "-c", NATIVE], worker / "source", "canary.log", env, 600)
    assert "PRIVATE_CANARY_OUTPUT" in (root / "evidence/canary.log").read_text()
    assert "boundary-ok" in (root / "evidence/isolation.log").read_text()
    assert json.loads((root / "evidence/receipt.json").read_text()) == dict(identity="runner-only-canary")
    assert (root / "evidence/worker/github_step_summary.txt").read_text() == "private command output"
    assert not worker.exists(), "Worker source must not return to the runner's trusted tree"
    ci.write_json(root / "evidence/canary.json", dict(status="passed", runner=os.environ["RUNNER_OS"]))
    print("Hosted account isolation canary passed.")


if __name__ == "__main__":
    main()
