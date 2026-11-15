#!/usr/bin/env python3
"""Public scheduling and ciphertext-only execution for a private source repository."""
from __future__ import annotations

import argparse
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import signal
import subprocess
import sys
import tarfile
import traceback
from urllib.parse import quote, urlencode, urlparse
from urllib.error import HTTPError
from urllib.request import Request, urlopen


SHA = re.compile(r"[0-9a-f]{40}\Z")
REPOSITORY = re.compile(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+\Z")
TITLE = re.compile(r"(quick|full):([0-9a-f]{16}):([0-9a-f]{64})\Z")
STATUS_KEY = re.compile(r"request:([0-9a-f]{64}) ([a-z]+)\Z")
WORKFLOW = ".github/workflows/verify.yml"
MAX_PAGES = 20


def request_key(kind, source_sha, control_sha, pipeline_sha, recipient):
    values = ["public-ci-v1", kind, source_sha, control_sha, pipeline_sha, recipient.strip()]
    return hashlib.sha256(json.dumps(values, separators=(",", ":")).encode()).hexdigest()


def slot_key(repository, source_ref):
    return hashlib.sha256((repository.casefold() + "\0" + source_ref).encode()).hexdigest()[:16]


@dataclass(frozen=True)
class Candidate:
    source_sha: str
    control_sha: str
    source_ref: str
    slot: str


class GitHub:
    def __init__(self, repository, token):
        if not REPOSITORY.fullmatch(repository) or not token:
            raise ValueError("Repository identity and scoped authentication are required.")
        self.repository = repository
        self.token = token

    def api(self, method, path, value=None):
        body = None if value is None else json.dumps(value).encode()
        request = Request("https://api.github.com/repos/" + self.repository + "/" + path,
                          data=body, method=method,
                          headers={"Authorization": "Bearer " + self.token,
                                   "Accept": "application/vnd.github+json",
                                   "Content-Type": "application/json",
                                   "X-GitHub-Api-Version": "2022-11-28",
                                   "User-Agent": "public-ci-controller"})
        with urlopen(request, timeout=30) as response:
            raw = response.read()
        return json.loads(raw) if raw else None

    def pages(self, path, field=None, limit=MAX_PAGES):
        separator = "&" if "?" in path else "?"
        for page in range(1, limit + 1):
            value = self.api("GET", path + separator + urlencode({"per_page": 100, "page": page}))
            rows = value[field] if field else value
            yield from rows
            if len(rows) < 100:
                return
        raise RuntimeError("API pagination limit reached; refusing incomplete discovery.")


def discover(source, default_ref):
    if not default_ref or default_ref.startswith("refs/"):
        raise ValueError("The default source branch must be a branch name.")
    commit = source.api("GET", "commits/" + quote(default_ref, safe=""))
    control = commit["sha"]
    if not SHA.fullmatch(control):
        raise ValueError("Invalid control commit identity.")
    ref = "refs/heads/" + default_ref
    candidates = [Candidate(control, control, ref, slot_key(source.repository, ref))]
    seen = {control}
    for pull in source.pages("pulls?state=open"):
        head = pull["head"]
        repository = head.get("repo") or {}
        if repository.get("full_name", "").casefold() != source.repository.casefold():
            continue
        sha = head["sha"]
        if not SHA.fullmatch(sha):
            raise ValueError("Invalid candidate commit identity.")
        if sha in seen:
            continue
        ref = "refs/heads/" + head["ref"]
        candidates.append(Candidate(sha, control, ref, slot_key(source.repository, ref)))
        seen.add(sha)
    return candidates


def latest_statuses(source, sha):
    contexts = {}
    for status in source.pages("commits/" + sha + "/statuses"):
        context = status["context"]
        if context in {"ci/public-quick", "ci/public-full"} and context not in contexts:
            contexts[context] = status
        if len(contexts) == 2:
            break
    return contexts


def trusted_run(run, repository, pipeline_sha, key, kind):
    title = TITLE.fullmatch(run.get("display_title", ""))
    return (title is not None and title[1] == kind and title[3] == key
            and run.get("head_sha") == pipeline_sha
            and run.get("head_branch") == "main"
            and run.get("path") == WORKFLOW
            and run.get("event") == "workflow_dispatch"
            and (run.get("repository") or {}).get("full_name", "").casefold() == repository.casefold()
            and (run.get("head_repository") or {}).get("full_name", "").casefold() == repository.casefold())


def run_id_from_url(url, repository):
    parsed = urlparse(url or "")
    match = re.fullmatch(r"/" + re.escape(repository) + r"/actions/runs/([0-9]+)", parsed.path, re.I)
    return int(match[1]) if parsed.scheme == "https" and parsed.netloc == "github.com" and match else None


def matching_run(public, status, recent, pipeline_sha, key, kind):
    candidates = [run for run in recent
                  if trusted_run(run, public.repository, pipeline_sha, key, kind)]
    run_id = run_id_from_url((status or {}).get("target_url"), public.repository)
    if run_id is not None:
        try:
            known = public.api("GET", "actions/runs/" + str(run_id))
        except HTTPError as error:
            if error.code != 404:
                raise
            known = None
        if known and trusted_run(known, public.repository, pipeline_sha, key, kind):
            candidates.append(known)
    return max(candidates, key=lambda item: (item["id"], item.get("run_attempt", 1)), default=None)


def report_available(public, run, kind, key):
    expected = f"report-{kind}-{key}-attempt-{run.get('run_attempt', 1)}"
    return any(item["name"] == expected and not item["expired"] and item.get("size_in_bytes", 0) > 0
               for item in public.pages(f"actions/runs/{run['id']}/artifacts", "artifacts"))


def publish(source, candidate, kind, key, phase, state, target_url, previous):
    value = dict(context="ci/public-" + kind, state=state,
                 description=f"request:{key} {phase}", target_url=target_url)
    if previous and all(previous.get(name) == content for name, content in value.items()):
        return
    source.api("POST", "statuses/" + candidate.source_sha, value)


def reconcile(source, public, candidate, kind, pipeline_sha, recipient, previous, recent,
              eligible, force=False):
    key = request_key(kind, candidate.source_sha, candidate.control_sha, pipeline_sha, recipient)
    matched = STATUS_KEY.fullmatch((previous or {}).get("description", ""))
    phase = matched[2] if matched and matched[1] == key else None
    run = matching_run(public, previous if phase else None, recent, pipeline_sha, key, kind)
    workflow_url = "https://github.com/" + public.repository + "/actions/workflows/verify.yml"
    if run and run["status"] != "completed":
        publish(source, candidate, kind, key, "running", "pending", run["html_url"], previous)
        return "active"
    if run and not force:
        conclusion = run.get("conclusion")
        if conclusion == "success" and report_available(public, run, kind, key):
            publish(source, candidate, kind, key, "passed", "success", run["html_url"], previous)
            return "passed"
        if conclusion != "success":
            outcome = "failed" if conclusion == "failure" else "incomplete"
            publish(source, candidate, kind, key, outcome,
                    "failure" if outcome == "failed" else "error", run["html_url"], previous)
            return outcome
    if not force and phase in {"failed", "incomplete"} and not run:
        return phase
    if not force and phase in {"queued", "running"} and not run:
        # An accepted dispatch is not permission to dispatch duplicates while API
        # indexing is delayed. Missing history never becomes passing evidence.
        return "unresolved"
    if not eligible:
        publish(source, candidate, kind, key, "scheduled", "pending", workflow_url, previous)
        return "scheduled"
    public.api("POST", "actions/workflows/verify.yml/dispatches",
               dict(ref="main", inputs=dict(kind=kind, request=key, slot=candidate.slot)))
    publish(source, candidate, kind, key, "queued", "pending", workflow_url, previous)
    return "dispatched"


def controller():
    require_main()
    source = GitHub(os.environ["CI_SOURCE_REPOSITORY"], os.environ["CI_SOURCE_TOKEN"])
    public = GitHub(os.environ["GITHUB_REPOSITORY"], os.environ["GH_TOKEN"])
    pipeline = os.environ["GITHUB_SHA"]
    recipient = os.environ["REPORT_RECIPIENT"].strip()
    if not SHA.fullmatch(pipeline) or not recipient:
        raise ValueError("Pipeline identity and report recipient are required.")
    if public.api("GET", "git/ref/heads/main")["object"]["sha"] != pipeline:
        raise RuntimeError("The controller revision is superseded; no stale statuses will be published.")
    candidates = discover(source, os.environ.get("CI_SOURCE_DEFAULT_REF", "development"))
    selected_slot = os.environ.get("CI_SELECTED_SLOT", "") or candidates[0].slot
    selected = next((candidate for candidate in candidates if candidate.slot == selected_slot), None)
    if selected is None:
        raise ValueError("Requested candidate is no longer current.")
    manual = os.environ.get("CI_MANUAL", "false") == "true"
    kind = os.environ.get("CI_SELECTED_KIND", "quick")
    if kind not in {"quick", "full"}:
        raise ValueError("Unsupported verification kind.")
    full_due = os.environ.get("CI_FULL_DUE", "false") == "true"
    force = manual and os.environ.get("CI_FORCE", "false") == "true"
    recent = []
    # This bounded scan bridges a dispatch's 204 response to its first run ID.
    # Established status target URLs are read directly, independent of this window.
    for page in range(1, 4):
        rows = public.api("GET", f"actions/workflows/verify.yml/runs?per_page=100&page={page}")["workflow_runs"]
        recent.extend(rows)
        if len(rows) < 100:
            break
    counts = {}
    for candidate in candidates:
        statuses = latest_statuses(source, candidate.source_sha)
        for check in ["quick", "full"]:
            previous = statuses.get("ci/public-" + check)
            is_selected = manual and candidate == selected and check == kind
            if check == "full" and candidate != candidates[0] and not previous and not is_selected:
                continue
            eligible = check == "quick" or (candidate == candidates[0] and full_due) or is_selected
            result = reconcile(source, public, candidate, check, pipeline, recipient,
                               previous, recent, eligible, force and is_selected)
            counts[result] = counts.get(result, 0) + 1
    print(json.dumps(counts, sort_keys=True))


def require_main():
    if os.environ.get("GITHUB_REF") != "refs/heads/main":
        raise RuntimeError("Credential-bearing workflows are restricted to main.")


def owner():
    return os.environ["GITHUB_RUN_ID"] + "-" + os.environ.get("GITHUB_RUN_ATTEMPT", "1")


def private_root():
    return Path(os.environ["RUNNER_TEMP"]) / "ci-private"


def prepare(root, identity):
    if root.is_symlink():
        raise RuntimeError("Owned workspace must not be a symlink.")
    existing = root.exists()
    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    marker = root / ".owned"
    if marker.is_symlink() or existing and (not marker.is_file() or marker.read_text() != identity):
        raise RuntimeError("Workspace belongs to another execution.")
    marker.write_text(identity)
    if (root / "evidence").is_symlink():
        raise RuntimeError("Private evidence must not be a symlink.")
    (root / "evidence").mkdir(mode=0o700, exist_ok=True)


def owned_workspace(root, identity):
    try:
        return (not root.is_symlink() and not (root / ".owned").is_symlink()
                and (root / ".owned").read_text() == identity
                and (root / "evidence").is_dir() and not (root / "evidence").is_symlink())
    except OSError:
        return False


def clean_private(root, identity):
    if not root.exists():
        return
    if root.is_symlink() or (root / ".owned").is_symlink() or (root / ".owned").read_text() != identity:
        raise RuntimeError("Refusing to remove an unowned workspace.")
    shutil.rmtree(root)


def write_json(path, value):
    path.write_text(json.dumps(value, sort_keys=True, indent=2) + "\n")


def fetch_commit(repository, sha, destination, credentials, log, token):
    if not SHA.fullmatch(sha) or not REPOSITORY.fullmatch(repository):
        raise ValueError("Invalid immutable source identity.")
    credentials.mkdir(mode=0o700, exist_ok=True)
    askpass = credentials / "askpass.py"
    askpass.write_text("#!/usr/bin/env python3\nimport os,sys\n"
                       "print('x-access-token' if 'Username' in sys.argv[1] else os.environ['CI_SOURCE_TOKEN'])\n")
    askpass.chmod(0o700)
    env = dict(os.environ, CI_SOURCE_TOKEN=token, GIT_ASKPASS=str(askpass), GIT_TERMINAL_PROMPT="0",
               GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL=os.devnull,
               GIT_CONFIG_COUNT="3", GIT_CONFIG_KEY_0="credential.helper", GIT_CONFIG_VALUE_0="",
               GIT_CONFIG_KEY_1="core.hooksPath", GIT_CONFIG_VALUE_1=os.devnull,
               GIT_CONFIG_KEY_2="http.followRedirects", GIT_CONFIG_VALUE_2="false")
    destination.mkdir(mode=0o700)
    commands = [["git", "-C", str(destination), "init", "--quiet"],
                ["git", "-C", str(destination), "fetch", "--quiet", "--depth=1", "--no-tags",
                 "https://github.com/" + repository + ".git", sha],
                ["git", "-C", str(destination), "checkout", "--quiet", "--detach", "FETCH_HEAD"]]
    with log.open("ab") as output:
        for command in commands:
            subprocess.run(command, env=env, stdout=output, stderr=subprocess.STDOUT,
                           check=True, timeout=300)
        actual = subprocess.check_output(["git", "-C", str(destination), "rev-parse", "HEAD"],
                                         env=env, stderr=output, text=True).strip()
        if actual != sha:
            raise RuntimeError("Fetched commit does not match the requested immutable identity.")


def checkout():
    require_main()
    root = private_root()
    source = GitHub(os.environ["CI_SOURCE_REPOSITORY"], os.environ["CI_SOURCE_TOKEN"])
    kind, request, slot = (os.environ[name] for name in ["CI_KIND", "CI_REQUEST", "CI_SLOT"])
    if kind not in {"quick", "full"} or not re.fullmatch(r"[0-9a-f]{64}", request):
        raise ValueError("Invalid verification request.")
    pipeline = os.environ["GITHUB_SHA"]
    recipient = os.environ["REPORT_RECIPIENT"].strip()
    candidates = discover(source, os.environ.get("CI_SOURCE_DEFAULT_REF", "development"))
    candidate = next((candidate for candidate in candidates
                      if candidate.slot == slot and request == request_key(
                          kind, candidate.source_sha, candidate.control_sha, pipeline, recipient)), None)
    if candidate is None:
        raise RuntimeError("The immutable request is stale; no newer source will be substituted.")
    receipt = dict(schema=1, kind=kind, request=request, slot=slot,
                   source_sha=candidate.source_sha, control_sha=candidate.control_sha,
                   source_ref=candidate.source_ref, pipeline_sha=pipeline,
                   recipient_sha256=hashlib.sha256(recipient.encode()).hexdigest(),
                   run_id=os.environ["GITHUB_RUN_ID"],
                   run_attempt=int(os.environ.get("GITHUB_RUN_ATTEMPT", "1")), status="incomplete")
    write_json(root / "evidence/receipt.json", receipt)
    credentials = root / "credentials"
    try:
        fetch_commit(source.repository, candidate.source_sha, root / "source", credentials,
                     root / "evidence/checkout.log", source.token)
        control = root / "source"
        if candidate.control_sha != candidate.source_sha:
            control = root / "control"
            fetch_commit(source.repository, candidate.control_sha, control, credentials,
                         root / "evidence/checkout.log", source.token)
        write_json(root / "execution.json", dict(source=str(root / "source"), control=str(control)))
    finally:
        shutil.rmtree(credentials, ignore_errors=True)


def execution_environment(evidence):
    env = {key: value for key, value in os.environ.items()
           if not key.startswith(("ACTIONS_", "CI_SOURCE_", "CI_REQUEST", "CI_SLOT"))
           and key not in {"GH_TOKEN", "GITHUB_TOKEN", "REPORT_RECIPIENT", "GIT_ASKPASS"}
           and not key.startswith("GIT_CONFIG_")}
    for name in ["GITHUB_OUTPUT", "GITHUB_ENV", "GITHUB_PATH", "GITHUB_STATE", "GITHUB_STEP_SUMMARY"]:
        env[name] = str(evidence / (name.lower() + ".txt"))
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    return env


def run_private(command, cwd, log, env, timeout):
    with log.open("ab") as output:
        child = subprocess.Popen(command, cwd=cwd, env=env, stdout=output,
                                 stderr=subprocess.STDOUT, start_new_session=True)
        try:
            result = child.wait(timeout=timeout)
        except BaseException:
            try:
                os.killpg(child.pid, signal.SIGTERM)
                child.wait(timeout=10)
            except (ProcessLookupError, subprocess.TimeoutExpired):
                try:
                    os.killpg(child.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                child.wait()
            raise
    if result:
        raise RuntimeError("Private verification command failed.")


def execute():
    root = private_root()
    evidence = root / "evidence"
    receipt = json.loads((evidence / "receipt.json").read_text())
    paths = json.loads((root / "execution.json").read_text())
    source, control = Path(paths["source"]), Path(paths["control"])
    env = execution_environment(evidence)
    if receipt["kind"] == "quick":
        if list((source / ".github/workflows").glob("*.y*ml")):
            run_private(["actionlint", "-color"], source, evidence / "actionlint.log", env, 120)
        command = [sys.executable, str(control / "scripts/ci.py"), "quick", "--source", str(source),
                   "--output", str(evidence / "checks")]
        timeout = 600
    else:
        config = json.loads((control / "scripts/ci-config.json").read_text())
        if config["runner"] != "xcode-27" or os.environ.get("RUNNER_OS") != "macOS":
            raise RuntimeError("The pinned native runner is unavailable; no implicit substitution.")
        command = [sys.executable, str(control / "scripts/ci_native.py"), "--source", str(source),
                   "--cache", str(root / "native-cache"), "--output", str(evidence / "checks")]
        timeout = 3000
    run_private(command, source, evidence / "execution.log", env, timeout)
    receipt["status"] = "passed"
    write_json(evidence / "receipt.json", receipt)


def seal(evidence, destination, recipient, age="age"):
    destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    partial = destination.with_suffix(destination.suffix + ".partial")
    destination.unlink(missing_ok=True)
    process = None
    try:
        with partial.open("wb") as output, (evidence / "encryption.log").open("ab") as errors:
            process = subprocess.Popen([age, "--encrypt", "--recipient", recipient],
                                       stdin=subprocess.PIPE, stdout=output, stderr=errors)
            with tarfile.open(fileobj=process.stdin, mode="w|gz", dereference=False) as archive:
                for path in sorted(evidence.iterdir()):
                    if path.name != "encryption.log":
                        archive.add(path, arcname="evidence/" + path.name)
            process.stdin.close()
            if process.wait(timeout=120) or partial.stat().st_size == 0:
                raise RuntimeError("Report encryption failed.")
        partial.replace(destination)
    finally:
        if process is not None and process.poll() is None:
            process.kill()
            process.wait()
        partial.unlink(missing_ok=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=["controller", "checkout", "execute", "seal", "cleanup"])
    args = parser.parse_args()
    root = private_root()
    try:
        if args.command == "cleanup":
            clean_private(root, owner())
            return 0
        prepare(root, owner())
        if args.command == "seal":
            seal(root / "evidence", Path(os.environ["RUNNER_TEMP"]) / "ci-encrypted/report.tar.age",
                 os.environ["REPORT_RECIPIENT"].strip())
        else:
            {"controller": controller, "checkout": checkout, "execute": execute}[args.command]()
        return 0
    except Exception:
        # Diagnostics must never create a second public exception or write into
        # another execution's workspace, including failures during preparation.
        try:
            if owned_workspace(root, owner()):
                with (root / "evidence/errors.log").open("a") as errors:
                    traceback.print_exc(file=errors)
                receipt_path = root / "evidence/receipt.json"
                if receipt_path.exists() and args.command in {"checkout", "execute"}:
                    receipt = json.loads(receipt_path.read_text())
                    receipt["status"] = "failed"
                    write_json(receipt_path, receipt)
        except Exception:
            pass
        print("CI operation failed. Private details are available only in the encrypted report.", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
