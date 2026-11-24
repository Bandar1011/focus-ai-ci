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
import stat
import subprocess
import sys
import tarfile
import traceback
from isolation import PrivateUser, run_private
from urllib.parse import quote, urlencode, urlparse
from urllib.error import HTTPError
from urllib.request import Request, urlopen


SHA = re.compile(r"[0-9a-f]{40}\Z")
REPOSITORY = re.compile(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+\Z")
TITLE = re.compile(r"(quick|full):([0-9a-f]{16}):([0-9a-f]{64}):([A-Za-z0-9_=-]{8,256})\Z")
STATUS_KEY = re.compile(r"request:([0-9a-f]{64}) control:([0-9a-f]{40}) (queued|running|passed|failed|incomplete)\Z")
SNAPSHOT = re.compile(r"control:([0-9a-f]{40}) slot:([0-9a-f]{16}) queued\Z")
STATUS_ID = re.compile(r"[A-Za-z0-9_=-]{8,256}\Z")
SLOT = re.compile(r"[0-9a-f]{16}\Z")
WORKFLOW = ".github/workflows/verify.yml"
MAX_PAGES = 20
GITHUB_ACTIONS_BOT_ID = 41898282


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

    def request(self, method, url, value=None):
        body = None if value is None else json.dumps(value).encode()
        request = Request(url,
                          data=body, method=method,
                          headers={"Authorization": "Bearer " + self.token,
                                   "Accept": "application/vnd.github+json",
                                   "Content-Type": "application/json",
                                   "X-GitHub-Api-Version": "2022-11-28",
                                   "User-Agent": "public-ci-controller"})
        with urlopen(request, timeout=30) as response:
            raw = response.read()
        return json.loads(raw) if raw else None

    def api(self, method, path, value=None):
        return self.request(method, "https://api.github.com/repos/" + self.repository + "/" + path, value)

    def status_node(self, node_id):
        if not STATUS_ID.fullmatch(node_id):
            raise ValueError("Invalid opaque status identifier.")
        query = """query($id:ID!){node(id:$id){__typename ... on StatusContext {
          id context description state targetUrl creator{login __typename ... on Bot{databaseId}}
          commit{oid repository{nameWithOwner isPrivate}}
        }}}"""
        result = self.request("POST", "https://api.github.com/graphql",
                              dict(query=query, variables=dict(id=node_id)))
        if result.get("errors") or not result.get("data", {}).get("node"):
            raise RuntimeError("The private request snapshot is unavailable.")
        return result["data"]["node"]

    def pages(self, path, field=None, limit=MAX_PAGES):
        separator = "&" if "?" in path else "?"
        for page in range(1, limit + 1):
            value = self.api("GET", path + separator + urlencode({"per_page": 100, "page": page}))
            rows = value[field] if field else value
            yield from rows
            if len(rows) < 100:
                return
        raise RuntimeError("API pagination limit reached; refusing incomplete discovery.")


def load_snapshot(source, node_id, kind, slot, pipeline_sha, recipient, allow_draft=False):
    if kind not in {"quick", "full"} or not SLOT.fullmatch(slot):
        raise ValueError("Invalid verification kind or opaque branch slot.")
    node = source.status_node(node_id)
    commit = node.get("commit") or {}
    repository = commit.get("repository") or {}
    creator = node.get("creator") or {}
    owner_login = source.repository.split("/")[0].casefold()
    is_owner = creator.get("__typename") == "User" and creator.get("login", "").casefold() == owner_login
    is_actions = creator.get("__typename") == "Bot" and creator.get("databaseId") == GITHUB_ACTIONS_BOT_ID
    if (node.get("__typename") != "StatusContext" or node.get("id") != node_id
            or node.get("context") != "ci/public-" + kind
            or repository.get("nameWithOwner", "").casefold() != source.repository.casefold()
            or repository.get("isPrivate") is not True or not SHA.fullmatch(commit.get("oid", ""))):
        raise ValueError("Private request snapshot does not belong to this source and check.")
    description = node.get("description", "")
    frozen = STATUS_KEY.fullmatch(description)
    draft = SNAPSHOT.fullmatch(description) if allow_draft else None
    if frozen and is_owner:
        control, key = frozen[2], frozen[1]
        if key != request_key(kind, commit["oid"], control, pipeline_sha, recipient):
            raise ValueError("Request does not bind the frozen source, control, pipeline and recipient.")
    elif draft and (is_owner or is_actions) and draft[2] == slot:
        control, key = draft[1], None
    else:
        raise ValueError("Private request has no trusted immutable snapshot.")
    return Candidate(commit["oid"], control, commit["oid"], slot), key


def latest_statuses(source, sha, final_only=False):
    contexts = {}
    for status in source.pages("commits/" + sha + "/statuses"):
        if final_only and (not STATUS_KEY.fullmatch(status.get("description", ""))
                           or (status.get("creator") or {}).get("login", "").casefold()
                           != source.repository.split("/")[0].casefold()):
            continue
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


def report_available(public, run, kind, key):
    expected = f"report-{kind}-{key}-attempt-{run.get('run_attempt', 1)}"
    return any(item["name"] == expected and not item["expired"] and item.get("size_in_bytes", 0) > 0
               for item in public.pages(f"actions/runs/{run['id']}/artifacts", "artifacts"))


def publish(source, candidate, kind, key, phase, state, target_url, previous):
    value = dict(context="ci/public-" + kind, state=state,
                 description=f"request:{key} control:{candidate.control_sha} {phase}", target_url=target_url)
    if previous and all(previous.get(name) == content for name, content in value.items()):
        return previous
    return source.api("POST", "statuses/" + candidate.source_sha, value)


def finish(source, public, run, recipient):
    title = TITLE.fullmatch(run.get("display_title", ""))
    if not title or not trusted_run(run, public.repository, run.get("head_sha"), title[3], title[1]):
        raise ValueError("Completion is not a trusted main-branch verification run.")
    kind, slot, key, node_id = title.groups()
    candidate, _ = load_snapshot(source, node_id, kind, slot, run["head_sha"], recipient)
    previous = latest_statuses(source, candidate.source_sha).get("ci/public-" + kind)
    matched = STATUS_KEY.fullmatch((previous or {}).get("description", ""))
    if not matched:
        try:
            alias, alias_key = load_snapshot(source, (previous or {})["node_id"], kind, slot,
                                             run["head_sha"], recipient, allow_draft=True)
        except (KeyError, ValueError):
            return "superseded"
        if alias_key is not None or alias != candidate:
            return "superseded"
    elif (matched[1] != key or matched[2] != candidate.control_sha
            or (previous.get("creator") or {}).get("login", "").casefold()
            != source.repository.split("/")[0].casefold()
            or run_id_from_url(previous.get("target_url"), public.repository) != run["id"]):
        return "superseded"
    if run["status"] != "completed":
        return "active"
    if run.get("conclusion") == "success" and report_available(public, run, kind, key):
        phase, state = "passed", "success"
    elif run.get("conclusion") == "failure":
        phase, state = "failed", "failure"
    else:
        phase, state = "incomplete", "error"
    publish(source, candidate, kind, key, phase, state, run["html_url"], previous)
    return phase


def dispatch_request(source, public, candidate, kind, pipeline_sha, recipient, force=False):
    key = request_key(kind, candidate.source_sha, candidate.control_sha, pipeline_sha, recipient)
    previous = latest_statuses(source, candidate.source_sha, final_only=True).get("ci/public-" + kind)
    matched = STATUS_KEY.fullmatch((previous or {}).get("description", ""))
    phase = matched[3] if matched and matched[1] == key else None
    workflow_url = "https://github.com/" + public.repository + "/actions/workflows/verify.yml"
    if phase:
        run_id = run_id_from_url(previous.get("target_url"), public.repository)
        if run_id:
            try:
                run = public.api("GET", "actions/runs/" + str(run_id))
            except HTTPError as error:
                if error.code != 404:
                    raise
                run = None
            if run and trusted_run(run, public.repository, pipeline_sha, key, kind):
                if run["status"] != "completed":
                    publish(source, candidate, kind, key, "queued", "pending", run["html_url"], None)
                    return "active"
                if not force:
                    return finish(source, public, run, recipient)
        if not force:
            publish(source, candidate, kind, key, phase if phase in {"failed", "incomplete"} else "incomplete",
                    "failure" if phase == "failed" else "error", workflow_url, None)
            return "incomplete" if phase not in {"failed", "incomplete"} else phase
    pending = publish(source, candidate, kind, key, "queued", "pending", workflow_url, None)
    node_id = pending["node_id"]
    if not STATUS_ID.fullmatch(node_id):
        raise RuntimeError("Private status has no opaque immutable identity.")
    try:
        result = public.api("POST", "actions/workflows/verify.yml/dispatches",
                            dict(ref="main", return_run_details=True,
                                 inputs=dict(kind=kind, request=key, slot=candidate.slot, status=node_id)))
        run_id = result["workflow_run_id"]
        url = result["html_url"]
        if type(run_id) is not int or run_id_from_url(url, public.repository) != run_id:
            raise RuntimeError("Dispatch did not return a valid exact worker identity.")
        publish(source, candidate, kind, key, "queued", "pending", url, pending)
    except Exception:
        publish(source, candidate, kind, key, "incomplete", "error", workflow_url, pending)
        raise
    return "dispatched"


def route():
    event = json.loads(Path(os.environ["GITHUB_EVENT_PATH"]).read_text())
    event_name = os.environ["GITHUB_EVENT_NAME"]
    run_id = ""
    if event_name == "workflow_run":
        run = event["workflow_run"]
        title = TITLE.fullmatch(run.get("display_title", ""))
        if not title or run.get("status") != "completed" or type(run.get("id")) is not int:
            raise ValueError("Invalid verification completion route.")
        kind, slot = title[1], title[2]
        run_id = str(run["id"])
    else:
        inputs = event.get("inputs") or {}
        kind = "full" if event_name == "schedule" else inputs.get("kind", "quick")
        slot = inputs.get("slot") or os.environ.get("CI_DEFAULT_SLOT", "")
        if kind not in {"quick", "full"} or not SLOT.fullmatch(slot):
            raise ValueError("Invalid controller route.")
    group = "full" if kind == "full" else "quick-" + slot
    with open(os.environ["GITHUB_OUTPUT"], "a") as output:
        output.write(f"kind={kind}\nslot={slot}\ngroup={group}\nrun_id={run_id}\n")


def current_candidate(source, selected_slot):
    control = source.api("GET", "commits/development")["sha"]
    if not SHA.fullmatch(control):
        raise ValueError("Invalid current control revision.")
    for branch in source.pages("branches"):
        ref = "refs/heads/" + branch["name"]
        if slot_key(source.repository, ref) == selected_slot:
            sha = branch["commit"]["sha"]
            if not SHA.fullmatch(sha):
                raise ValueError("Invalid current source revision.")
            return Candidate(sha, control, sha, selected_slot)
    return None


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
    run_id = os.environ.get("CI_COMPLETED_RUN_ID", "")
    selected_slot = os.environ["CI_SELECTED_SLOT"]
    kind = os.environ.get("CI_SELECTED_KIND", "quick")
    if kind not in {"quick", "full"} or not SLOT.fullmatch(selected_slot):
        raise ValueError("Unsupported verification kind or branch slot.")
    if run_id:
        if not run_id.isdecimal():
            raise ValueError("Invalid completed worker identity.")
        result = finish(source, public, public.api("GET", "actions/runs/" + run_id), recipient)
        # GitHub retains only one pending controller per branch. A completion
        # may replace a pending push, so converge the surviving actor on the
        # current Quick head. Unchanged failures never trigger another worker.
        if kind == "quick" and (current := current_candidate(source, selected_slot)):
            result = dispatch_request(source, public, current, kind, pipeline, recipient)
        print(json.dumps(dict(result=result)))
        return
    node_id = os.environ.get("CI_REQUEST_STATUS", "")
    if node_id:
        candidate, _ = load_snapshot(source, node_id, kind, selected_slot, pipeline, recipient, allow_draft=True)
    else:
        default_ref = os.environ.get("CI_SOURCE_DEFAULT_REF", "development")
        commit = source.api("GET", "commits/" + quote(default_ref, safe=""))["sha"]
        if not SHA.fullmatch(commit) or selected_slot != slot_key(source.repository, "refs/heads/" + default_ref):
            raise ValueError("Default branch routing does not match the private source.")
        candidate = Candidate(commit, commit, commit, selected_slot)
    force = os.environ.get("GITHUB_EVENT_NAME") == "workflow_dispatch" and os.environ.get("CI_FORCE") == "true"
    result = dispatch_request(source, public, candidate, kind, pipeline, recipient, force)
    if kind == "quick" and (current := current_candidate(source, selected_slot)) and current != candidate:
        result = dispatch_request(source, public, current, kind, pipeline, recipient)
    print(json.dumps(dict(result=result)))


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
    with private_file(path, "w") as output:
        output.write(json.dumps(value, sort_keys=True, indent=2) + "\n")


def private_file(path, mode):
    flags = os.O_WRONLY | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK
    if mode.startswith("a"):
        flags |= os.O_APPEND
    descriptor = os.open(path, flags, 0o600)
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise RuntimeError("Private evidence must be an unlinked regular file.")
        if mode.startswith("w"):
            os.ftruncate(descriptor, 0)
        return os.fdopen(descriptor, mode)
    except BaseException:
        os.close(descriptor)
        raise


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
    with private_file(log, "ab") as output:
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
    node_id = os.environ["CI_STATUS"]
    if kind not in {"quick", "full"} or not re.fullmatch(r"[0-9a-f]{64}", request) or not SLOT.fullmatch(slot):
        raise ValueError("Invalid verification request.")
    pipeline = os.environ["GITHUB_SHA"]
    recipient = os.environ["REPORT_RECIPIENT"].strip()
    candidate, expected = load_snapshot(source, node_id, kind, slot, pipeline, recipient)
    if request != expected:
        raise RuntimeError("The immutable request does not match the private status snapshot.")
    receipt = dict(schema=1, kind=kind, request=request, slot=slot, status_id=node_id,
                   source_sha=candidate.source_sha, control_sha=candidate.control_sha,
                   source_ref=candidate.source_ref, pipeline_sha=pipeline,
                   recipient_sha256=hashlib.sha256(recipient.encode()).hexdigest(),
                   run_id=os.environ["GITHUB_RUN_ID"],
                   run_attempt=int(os.environ.get("GITHUB_RUN_ATTEMPT", "1")), status="incomplete")
    write_json(root / "evidence/receipt.json", receipt)
    worker = root / "worker"
    worker.mkdir(mode=0o700)
    (worker / "evidence").mkdir(mode=0o700)
    credentials = root / "credentials"
    try:
        fetch_commit(source.repository, candidate.source_sha, worker / "source", credentials,
                     root / "evidence/checkout.log", source.token)
        control = worker / "source"
        if candidate.control_sha != candidate.source_sha:
            control = worker / "control"
            fetch_commit(source.repository, candidate.control_sha, control, credentials,
                         root / "evidence/checkout.log", source.token)
        write_json(root / "execution.json", dict(source=str(worker / "source"), control=str(control)))
    finally:
        shutil.rmtree(credentials, ignore_errors=True)


def execution_environment(evidence):
    allowed = {"PATH", "LANG", "LC_ALL", "CI", "GITHUB_ACTIONS", "RUNNER_OS", "RUNNER_ARCH",
               "GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT", "GITHUB_SHA", "GITHUB_REPOSITORY"}
    env = {key: value for key, value in os.environ.items() if key in allowed}
    env.setdefault("PATH", os.defpath)
    for name in ["GITHUB_OUTPUT", "GITHUB_ENV", "GITHUB_PATH", "GITHUB_STATE", "GITHUB_STEP_SUMMARY"]:
        env[name] = str(evidence / (name.lower() + ".txt"))
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    return env


def execute():
    root = private_root()
    evidence = root / "evidence"
    worker_evidence = root / "worker/evidence"
    receipt = json.loads((evidence / "receipt.json").read_text())
    paths = json.loads((root / "execution.json").read_text())
    source, control = Path(paths["source"]), Path(paths["control"])
    env = execution_environment(worker_evidence)
    workflow_files = list((source / ".github/workflows").glob("*.y*ml"))
    if receipt["kind"] == "quick":
        command = [sys.executable, str(control / "scripts/ci.py"), "quick", "--source", str(source),
                   "--output", str(worker_evidence / "checks")]
        timeout = 600
    else:
        config = json.loads((control / "scripts/ci-config.json").read_text())
        if config["runner"] != "xcode-27" or os.environ.get("RUNNER_OS") != "macOS":
            raise RuntimeError("The pinned native runner is unavailable; no implicit substitution.")
        command = [sys.executable, str(control / "scripts/ci_native.py"), "--source", str(source),
                   "--cache", str(root / "worker/native-cache"), "--output", str(worker_evidence / "checks")]
        timeout = 3000
    with PrivateUser(root, ["isolation.log", "actionlint.log", "execution.log"]) as isolated:
        isolated.probe(env)
        if receipt["kind"] == "quick" and workflow_files:
            isolated.run(["actionlint", "-color"], source, "actionlint.log", env, 120)
        isolated.run(command, source, "execution.log", env, timeout)
    receipt["status"] = "passed"
    write_json(evidence / "receipt.json", receipt)


def seal(evidence, destination, recipient, age="age"):
    destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    partial = destination.with_suffix(destination.suffix + ".partial")
    destination.unlink(missing_ok=True)
    process = None
    try:
        for directory, folders, files in os.walk(evidence, followlinks=False):
            for name in folders + files:
                info = (Path(directory) / name).lstat()
                if not (stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode) and info.st_nlink == 1):
                    raise RuntimeError("Report contains a link or a nonregular file.")
        with private_file(partial, "wb") as output, private_file(evidence / "encryption.log", "ab") as errors:
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
    parser.add_argument("command", choices=["route", "controller", "checkout", "execute", "seal", "cleanup"])
    args = parser.parse_args()
    if args.command == "route":
        try:
            route()
            return 0
        except (KeyError, ValueError, OSError):
            print("Invalid CI event route.", file=sys.stderr)
            return 1
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
    except (Exception, KeyboardInterrupt):
        # Diagnostics must never create a second public exception or write into
        # another execution's workspace, including failures during preparation.
        try:
            if owned_workspace(root, owner()):
                with private_file(root / "evidence/errors.log", "a") as errors:
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
    def cancelled(_signal, _frame):
        raise KeyboardInterrupt("CI operation cancelled")
    signal.signal(signal.SIGTERM, cancelled)
    raise SystemExit(main())
