import contextlib
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import sys
import tarfile
import tempfile
import time
import unittest
from unittest.mock import patch
from urllib.error import HTTPError

import ci
import isolation

SOURCE = "owner/private"
PUBLIC = "owner/ci"
PIPELINE = "c" * 40
RECIPIENT = "age1-test-recipient"
NODE = "SC_frozen_request"
CANDIDATE = ci.Candidate("a" * 40, "b" * 40, "a" * 40, "d" * 16)


def key(candidate=CANDIDATE, kind="quick"):
    return ci.request_key(kind, candidate.source_sha, candidate.control_sha, PIPELINE, RECIPIENT)


def status(kind="quick", phase="queued", candidate=CANDIDATE, url=None):
    return dict(node_id=NODE, context="ci/public-"+kind, state="pending", creator=dict(login="owner"),
                description=f"request:{key(candidate,kind)} control:{candidate.control_sha} {phase}",
                target_url=url or f"https://github.com/{PUBLIC}/actions/runs/17")


def node(kind="quick", **changes):
    value = dict(__typename="StatusContext", id=NODE, context="ci/public-"+kind,
                 description=status(kind)["description"], creator=dict(login="owner",__typename="User"),
                 commit=dict(oid=CANDIDATE.source_sha, repository=dict(nameWithOwner=SOURCE, isPrivate=True)))
    value.update(changes)
    return value


def run(kind="quick", request=None, **changes):
    value = dict(id=17, run_attempt=1, display_title=f"{kind}:{CANDIDATE.slot}:{request or key(kind=kind)}:{NODE}",
                 head_sha=PIPELINE, head_branch="main", path=ci.WORKFLOW, event="workflow_dispatch",
                 repository=dict(full_name=PUBLIC), head_repository=dict(full_name=PUBLIC),
                 status="completed", conclusion="success", html_url=f"https://github.com/{PUBLIC}/actions/runs/17")
    value.update(changes)
    return value


class FakeAPI:
    def __init__(self, repository, responses=None, rows=None, nodes=None):
        self.repository = repository
        self.responses = responses or {}
        self.rows = rows or {}
        self.nodes = nodes or {NODE: node()}
        self.writes = []

    def api(self, method, path, value=None):
        if method == "GET":
            response = self.responses[path]
            if isinstance(response, BaseException): raise response
            return response
        self.writes.append((path, value))
        if path.startswith("statuses/"):
            result = dict(value, node_id=NODE, creator=dict(login="owner"))
            self.rows.setdefault("commits/"+path.removeprefix("statuses/")+"/statuses", []).insert(0,result)
            return result
        response = self.responses.get(path, dict(workflow_run_id=17,html_url=run()["html_url"]))
        if isinstance(response, BaseException): raise response
        return response

    def pages(self, path, field=None):
        yield from self.rows.get(path, [])

    def status_node(self, node_id):
        return self.nodes[node_id]


class ControllerTests(unittest.TestCase):
    def source(self, statuses=(), **kwargs):
        return FakeAPI(SOURCE, rows={"commits/"+CANDIDATE.source_sha+"/statuses":list(statuses)}, **kwargs)

    def public(self, worker=None, artifact=True):
        worker = worker or run()
        reports = [dict(name=f"report-quick-{key()}-attempt-{worker['run_attempt']}",
                        expired=False, size_in_bytes=800)] if artifact else []
        return FakeAPI(PUBLIC, {"actions/runs/17":worker}, {"actions/runs/17/artifacts":reports})

    def dispatch(self, source, public, **changes):
        values = dict(candidate=CANDIDATE,kind="quick",pipeline_sha=PIPELINE,recipient=RECIPIENT)
        values.update(changes)
        return ci.dispatch_request(source,public,**values)

    def test_dispatch_freezes_before_starting_and_uses_returned_exact_run_identity(self):
        source, public = self.source(), self.public()
        self.assertEqual(self.dispatch(source,public),"dispatched")
        self.assertEqual(len(public.writes),1)
        payload = public.writes[0][1]
        self.assertTrue(payload["return_run_details"])
        self.assertEqual(payload["inputs"],dict(kind="quick",slot=CANDIDATE.slot,request=key(),status=NODE))
        self.assertNotIn(CANDIDATE.source_sha,json.dumps(payload))
        self.assertEqual(source.writes[0][1]["state"],"pending")
        self.assertEqual(source.writes[-1][1]["target_url"],run()["html_url"])

    def test_active_run_is_reused_despite_new_alias_draft_without_dispatching_again(self):
        draft = dict(context="ci/public-quick",description=f"control:{CANDIDATE.control_sha} slot:{CANDIDATE.slot} queued",
                     creator=dict(login="github-actions[bot]"))
        source = self.source([draft,status()])
        public = self.public(run(status="in_progress",conclusion=None))
        self.assertEqual(self.dispatch(source,public),"active")
        self.assertFalse(public.writes)
        self.assertEqual(source.writes[-1][1]["target_url"],run()["html_url"])

    def test_success_requires_whole_run_and_current_attempt_nonexpired_ciphertext(self):
        for artifact, conclusion, attempt, expected in [(True,"success",1,"passed"),
                (False,"success",1,"incomplete"),(True,"failure",1,"failed"),
                (True,"cancelled",1,"incomplete"),(True,"success",2,"incomplete")]:
            source, public = self.source([status()]), self.public(artifact=artifact)
            with self.subTest(artifact=artifact,conclusion=conclusion,attempt=attempt):
                self.assertEqual(ci.finish(source,public,run(conclusion=conclusion,run_attempt=attempt),RECIPIENT),expected)
                self.assertEqual(source.writes[-1][1]["state"],{"passed":"success","failed":"failure","incomplete":"error"}[expected])
                self.assertFalse(public.writes)
        source, public = self.source([status()]), self.public()
        public.rows["actions/runs/17/artifacts"][0]["expired"] = True
        self.assertEqual(ci.finish(source,public,run(),RECIPIENT),"incomplete")

    def test_old_completion_cannot_overwrite_new_control_or_new_run_on_same_commit(self):
        changed = ci.Candidate(CANDIDATE.source_sha,"e"*40,CANDIDATE.source_ref,CANDIDATE.slot)
        for latest in [status(candidate=changed),status(url=f"https://github.com/{PUBLIC}/actions/runs/18"),
                dict(context="ci/public-quick",description=f"control:{changed.control_sha} slot:{changed.slot} queued")]:
            source = self.source([latest])
            self.assertEqual(ci.finish(source,self.public(),run(),RECIPIENT),"superseded")
            self.assertFalse(source.writes)

    def test_unchanged_failure_and_missing_proof_do_not_automatically_retry(self):
        for previous in [status(phase="failed",url="https://github.com/owner/ci/actions/workflows/verify.yml"),status()]:
            source, public = self.source([previous]),self.public(artifact=False)
            result = self.dispatch(source,public)
            self.assertIn(result,{"failed","incomplete"})
            self.assertFalse(public.writes)
            self.assertNotIn("success",[value["state"] for _,value in source.writes])

    def test_force_reinvestigates_failure_but_never_duplicates_active_work(self):
        source, public = self.source([status(phase="failed")]), self.public(run(conclusion="failure"))
        self.assertEqual(self.dispatch(source,public,force=True),"dispatched")
        source, public = self.source([status()]),self.public(run(status="queued",conclusion=None))
        self.assertEqual(self.dispatch(source,public,force=True),"active")
        self.assertFalse(public.writes)

    def test_dispatch_failure_or_missing_returned_run_id_leaves_error_not_green(self):
        for response in [RuntimeError("indeterminate dispatch"),{},dict(workflow_run_id=17,html_url="https://evil.example/17")]:
            source, public = self.source(),self.public()
            public.responses["actions/workflows/verify.yml/dispatches"] = response
            with self.assertRaises((RuntimeError,KeyError)):
                self.dispatch(source,public)
            self.assertEqual(source.writes[-1][1]["state"],"error")

    def test_each_bound_input_invalidates_proof(self):
        inputs = ["quick",CANDIDATE.source_sha,CANDIDATE.control_sha,PIPELINE,RECIPIENT]
        for index,replacement in enumerate(["full","d"*40,"e"*40,"f"*40,"rotated"]):
            changed = inputs.copy(); changed[index] = replacement
            self.assertNotEqual(key(),ci.request_key(*changed))

    def test_snapshot_is_frozen_without_current_branch_or_pr_discovery(self):
        source = self.source()
        self.assertEqual(ci.load_snapshot(source,NODE,"quick",CANDIDATE.slot,PIPELINE,RECIPIENT),(CANDIDATE,key()))
        draft = node(description=f"control:{CANDIDATE.control_sha} slot:{CANDIDATE.slot} queued",
                     creator=dict(login="github-actions",__typename="Bot",databaseId=41898282))
        source.nodes[NODE] = draft
        self.assertEqual(ci.load_snapshot(source,NODE,"quick",CANDIDATE.slot,PIPELINE,RECIPIENT,True),(CANDIDATE,None))
        with self.assertRaises(ValueError):
            ci.load_snapshot(source,NODE,"quick",CANDIDATE.slot,PIPELINE,RECIPIENT)

    def test_snapshot_rejects_lookalike_users_other_bots_and_bot_frozen_requests(self):
        draft = f"control:{CANDIDATE.control_sha} slot:{CANDIDATE.slot} queued"
        for creator in [dict(login="github-actions",__typename="User",databaseId=41898282),
                        dict(login="github-actions",__typename="Bot",databaseId=42),
                        dict(login="github-actions[bot]"), dict(login="owner",__typename="Bot",databaseId=42)]:
            for description in [draft,status()["description"]]:
                source = self.source(nodes={NODE:node(creator=creator,description=description)})
                with self.subTest(creator=creator,description=description),self.assertRaises(ValueError):
                    ci.load_snapshot(source,NODE,"quick",CANDIDATE.slot,PIPELINE,RECIPIENT,True)
        source = self.source(nodes={NODE:node(creator=dict(login="github-actions",__typename="Bot",databaseId=41898282))})
        with self.assertRaises(ValueError):
            ci.load_snapshot(source,NODE,"quick",CANDIDATE.slot,PIPELINE,RECIPIENT,True)

    def test_foreign_wrong_kind_author_or_revision_cannot_supply_private_snapshot(self):
        invalid = [node(__typename="Commit"),node(id="SC_another"),node(context="ci/public-full"),
                   node(creator=dict(login="stranger")),node(description=status()["description"].replace("b"*40,"e"*40)),
                   node(commit=dict(oid=CANDIDATE.source_sha,repository=dict(nameWithOwner="other/repo",isPrivate=True))),
                   node(commit=dict(oid=CANDIDATE.source_sha,repository=dict(nameWithOwner=SOURCE,isPrivate=False)))]
        for value in invalid:
            with self.subTest(value=value),self.assertRaises(ValueError):
                ci.load_snapshot(self.source(nodes={NODE:value}),NODE,"quick",CANDIDATE.slot,PIPELINE,RECIPIENT)

    def test_foreign_workflow_branch_or_repository_cannot_finish(self):
        for changes in [dict(head_branch="feature"),dict(event="pull_request"),dict(path=".github/workflows/self-test.yml"),
                        dict(head_repository=dict(full_name="other/fork")),dict(repository=dict(full_name="other/fork"))]:
            source = self.source([status()])
            with self.subTest(changes=changes),self.assertRaises(ValueError):
                ci.finish(source,self.public(),run(**changes),RECIPIENT)
            self.assertFalse(source.writes)

    def test_route_serializes_branch_requests_and_their_completion_together(self):
        with tempfile.TemporaryDirectory() as temporary:
            event,output=Path(temporary)/"event.json",Path(temporary)/"output"
            values=dict(GITHUB_EVENT_PATH=str(event),GITHUB_OUTPUT=str(output),CI_DEFAULT_SLOT=CANDIDATE.slot)
            for name,payload in [("workflow_dispatch",dict(inputs=dict(kind="quick",slot=CANDIDATE.slot))),
                                  ("workflow_run",dict(workflow_run=run()))]:
                event.write_text(json.dumps(payload));output.write_text("")
                with patch.dict(os.environ,dict(values,GITHUB_EVENT_NAME=name)):
                    ci.route()
                self.assertIn("group=quick-"+CANDIDATE.slot,output.read_text())
                self.assertIn("run_id="+("17" if name=="workflow_run" else ""),output.read_text())

    def test_surviving_completion_converges_latest_quick_head_without_repeating_full(self):
        latest = ci.Candidate("f"*40,"b"*40,"f"*40,CANDIDATE.slot)
        values=dict(GITHUB_REF="refs/heads/main",GITHUB_SHA=PIPELINE,GITHUB_REPOSITORY=PUBLIC,
                    GITHUB_EVENT_NAME="workflow_run",CI_SOURCE_REPOSITORY=SOURCE,CI_SOURCE_TOKEN="source-token",
                    GH_TOKEN="public-token",REPORT_RECIPIENT=RECIPIENT,CI_SELECTED_SLOT=CANDIDATE.slot,
                    CI_COMPLETED_RUN_ID="17")
        source, public=self.source([status()]), self.public()
        public.responses["git/ref/heads/main"]=dict(object=dict(sha=PIPELINE))
        for kind in ["quick","full"]:
            with patch.dict(os.environ,dict(values,CI_SELECTED_KIND=kind)), \
                    patch.object(ci,"GitHub",side_effect=[source,public]), \
                    patch.object(ci,"finish",return_value="passed"), \
                    patch.object(ci,"current_candidate",return_value=latest), \
                    patch.object(ci,"dispatch_request",return_value="dispatched") as dispatch, \
                    contextlib.redirect_stdout(io.StringIO()):
                ci.controller()
                self.assertEqual(dispatch.call_count,1 if kind=="quick" else 0)
                if kind=="quick":self.assertEqual(dispatch.call_args.args[2],latest)

    def test_pagination_is_complete_or_explicitly_fails(self):
        github=ci.GitHub(SOURCE,"test-token")
        with patch.object(github,"api",side_effect=[list(range(100)),[100]]):
            self.assertEqual(len(list(github.pages("commits/x/statuses"))),101)
        with patch.object(github,"api",return_value=list(range(100))):
            with self.assertRaisesRegex(RuntimeError,"pagination"):
                list(github.pages("commits/x/statuses",limit=1))

    def test_credentials_reject_feature_ref_and_superseded_pipeline(self):
        with patch.dict(os.environ,dict(GITHUB_REF="refs/heads/feature")):
            with self.assertRaises(RuntimeError):ci.require_main()
        values=dict(GITHUB_REF="refs/heads/main",GITHUB_SHA=PIPELINE,GITHUB_REPOSITORY=PUBLIC,
                    CI_SOURCE_REPOSITORY=SOURCE,CI_SOURCE_TOKEN="source-token",GH_TOKEN="public-token",REPORT_RECIPIENT=RECIPIENT)
        with patch.dict(os.environ,values),patch.object(ci.GitHub,"api",return_value=dict(object=dict(sha="e"*40))):
            with self.assertRaisesRegex(RuntimeError,"superseded"):ci.controller()


class ExecutionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def test_source_output_and_workflow_commands_stay_inside_private_evidence(self):
        evidence = self.root / "evidence"
        evidence.mkdir()
        public_output = self.root / "public-output"
        secret = "private-source-detail-739"
        original = dict(CI_SOURCE_TOKEN="credential", GH_TOKEN="public-token", GITHUB_TOKEN="another-token",
                        ACTIONS_RUNTIME_TOKEN="artifact-token", GITHUB_OUTPUT=str(public_output),
                        GITHUB_STEP_SUMMARY=str(public_output), GITHUB_ENV=str(public_output))
        with patch.dict(os.environ, original):
            env = ci.execution_environment(evidence)
        program = ("import os,pathlib,sys; "
                   f"print('::error::{secret}'); print('{secret}',file=sys.stderr); "
                   f"pathlib.Path(os.environ['GITHUB_OUTPUT']).write_text('{secret}'); "
                   f"pathlib.Path(os.environ['GITHUB_STEP_SUMMARY']).write_text('{secret}'); "
                   "assert not any(k in os.environ for k in "
                   "['CI_SOURCE_TOKEN','GH_TOKEN','GITHUB_TOKEN','ACTIONS_RUNTIME_TOKEN'])")
        console = io.StringIO()
        with contextlib.redirect_stdout(console), contextlib.redirect_stderr(console):
            ci.run_private([sys.executable, "-c", program], self.root, evidence / "execution.log", env, 10)
        self.assertEqual(console.getvalue(), "")
        self.assertFalse(public_output.exists())
        self.assertIn(secret, (evidence / "execution.log").read_text())
        self.assertIn(secret, (evidence / "github_step_summary.txt").read_text())

    def test_worker_cannot_redirect_the_trusted_receipt_into_runner_owned_output(self):
        root = self.root / "ci-private"
        ci.prepare(root, "17-1")
        public_file = self.root / "public-output"
        public_file.write_text("unchanged public output")
        values = dict(RUNNER_TEMP=str(self.root), GITHUB_REF="refs/heads/main", GITHUB_SHA=PIPELINE,
                      GITHUB_RUN_ID="17", GITHUB_RUN_ATTEMPT="1", CI_SOURCE_REPOSITORY=SOURCE,
                      CI_SOURCE_TOKEN="test-token", CI_KIND="quick", CI_REQUEST=key(),
                      CI_SLOT=CANDIDATE.slot, CI_STATUS=NODE, REPORT_RECIPIENT=RECIPIENT)
        class HostileWorker:
            def __init__(self, *_): pass
            def __enter__(self): return self
            def __exit__(self, *_): pass
            def probe(self, *_): pass
            def run(self, _command, cwd, *_):
                output = Path(cwd).parent / "evidence"
                output.mkdir(exist_ok=True)
                target = output / "receipt.json"
                target.unlink(missing_ok=True)
                target.symlink_to(public_file)
        def fetch(_repo, _sha, destination, *_):
            destination.mkdir()
        with patch.dict(os.environ, values), patch.object(ci, "load_snapshot", return_value=(CANDIDATE,key())), \
                patch.object(ci,"fetch_commit",side_effect=fetch), patch.object(ci,"PrivateUser",HostileWorker):
            ci.checkout()
            ci.execute()
        self.assertEqual(public_file.read_text(),"unchanged public output")
        self.assertFalse((root / "evidence/receipt.json").is_symlink())
        self.assertEqual(json.loads((root / "evidence/receipt.json").read_text())["status"],"passed")

    def test_failure_details_are_never_printed_to_public_console(self):
        temp = self.root / "runner"
        temp.mkdir()
        with patch.dict(os.environ, dict(RUNNER_TEMP=str(temp), GITHUB_RUN_ID="17", GITHUB_RUN_ATTEMPT="1")), \
                patch.object(sys, "argv", ["ci.py", "controller"]), \
                patch.object(ci, "controller", side_effect=RuntimeError("private-repository-name private-error")):
            console = io.StringIO()
            with contextlib.redirect_stdout(console), contextlib.redirect_stderr(console):
                self.assertEqual(ci.main(), 1)
        self.assertNotIn("private-repository-name", console.getvalue())
        self.assertIn("private-repository-name", (temp / "ci-private/evidence/errors.log").read_text())

    def test_malformed_receipt_error_does_not_escape_to_public_console(self):
        root = self.root / "ci-private"
        ci.prepare(root, "17-1")
        (root / "evidence/receipt.json").write_text("private-source-corrupt-json")
        with patch.dict(os.environ, dict(RUNNER_TEMP=str(self.root), GITHUB_RUN_ID="17", GITHUB_RUN_ATTEMPT="1")), \
                patch.object(sys, "argv", ["ci.py", "execute"]):
            console = io.StringIO()
            with contextlib.redirect_stdout(console), contextlib.redirect_stderr(console):
                self.assertEqual(ci.main(), 1)
        self.assertNotIn("private-source", console.getvalue())
        self.assertNotIn("Traceback", console.getvalue())

    def test_failed_preparation_does_not_write_diagnostics_into_foreign_workspace(self):
        root = self.root / "ci-private"
        ci.prepare(root, "another-execution")
        with patch.dict(os.environ, dict(RUNNER_TEMP=str(self.root), GITHUB_RUN_ID="17", GITHUB_RUN_ATTEMPT="1")), \
                patch.object(sys, "argv", ["ci.py", "execute"]):
            console = io.StringIO()
            with contextlib.redirect_stdout(console), contextlib.redirect_stderr(console):
                self.assertEqual(ci.main(), 1)
        self.assertEqual(list((root / "evidence").iterdir()), [])
        self.assertEqual((root / ".owned").read_text(), "another-execution")

    def test_wrong_request_is_rejected_before_any_source_checkout(self):
        ci.prepare(self.root / "ci-private", "17-1")
        values = dict(RUNNER_TEMP=str(self.root), GITHUB_REF="refs/heads/main", GITHUB_SHA=PIPELINE,
                      CI_SOURCE_REPOSITORY=SOURCE, CI_SOURCE_TOKEN="test-token", CI_KIND="quick",
                      CI_REQUEST="0" * 64, CI_SLOT=CANDIDATE.slot, CI_STATUS=NODE, REPORT_RECIPIENT=RECIPIENT)
        with patch.dict(os.environ, values), patch.object(ci, "load_snapshot", return_value=(CANDIDATE,key())), \
                patch.object(ci, "fetch_commit") as fetch:
            with self.assertRaisesRegex(RuntimeError, "does not match"):
                ci.checkout()
        fetch.assert_not_called()

    def test_checkout_credentials_are_removed_even_when_fetch_fails(self):
        root = self.root / "ci-private"
        ci.prepare(root, "17-1")
        values = dict(RUNNER_TEMP=str(self.root), GITHUB_REF="refs/heads/main", GITHUB_SHA=PIPELINE,
                      GITHUB_RUN_ID="17", GITHUB_RUN_ATTEMPT="1", CI_SOURCE_REPOSITORY=SOURCE,
                      CI_SOURCE_TOKEN="test-token", CI_KIND="quick", CI_REQUEST=key(),
                      CI_SLOT=CANDIDATE.slot, CI_STATUS=NODE, REPORT_RECIPIENT=RECIPIENT)
        def fail(*_args):
            (root / "credentials").mkdir()
            (root / "credentials/key").write_text("credential")
            raise RuntimeError("fetch failed")
        with patch.dict(os.environ, values), patch.object(ci, "load_snapshot", return_value=(CANDIDATE,key())), \
                patch.object(ci, "fetch_commit", side_effect=fail):
            with self.assertRaises(RuntimeError):
                ci.checkout()
        self.assertFalse((root / "credentials").exists())

    def test_timeout_stops_descendant_even_when_leader_exits_on_term(self):
        pidfile = self.root / "child.pid"
        program = ("import os,signal,time,pathlib; pid=os.fork(); "
                   "signal.signal(signal.SIGTERM,signal.SIG_IGN) if pid==0 else None; "
                   f"pathlib.Path({str(pidfile)!r}).write_text(str(os.getpid())) if pid==0 else None; "
                   "time.sleep(60)")
        descendant = None
        try:
            with self.assertRaises(subprocess.TimeoutExpired):
                ci.run_private([sys.executable,"-c",program],self.root,self.root/"timeout.log",dict(os.environ),1)
            descendant = int(pidfile.read_text())
            rows = subprocess.check_output(["ps","-axo","pid=,stat="],text=True)
            self.assertFalse(any(int(parts[0])==descendant and not parts[1].startswith("Z")
                                 for row in rows.splitlines() if len(parts:=row.split())==2))
        finally:
            if descendant is None and pidfile.exists():descendant=int(pidfile.read_text())
            if descendant:
                try:os.kill(descendant,signal.SIGKILL)
                except ProcessLookupError:pass

    def test_privileged_account_setup_is_never_allowed_on_a_developer_machine(self):
        with patch.dict(os.environ,dict(GITHUB_ACTIONS="false")):
            with self.assertRaisesRegex(RuntimeError,"GitHub-hosted"):
                isolation.PrivateUser(self.root,["isolation.log"])

    def test_cleanup_removes_owned_source_evidence_and_cache_but_preserves_ciphertext(self):
        root = self.root / "ci-private"
        ci.prepare(root, "17-1")
        (root / "source").mkdir()
        (root / "native-cache").mkdir()
        ciphertext = self.root / "ci-encrypted/report.tar.age"
        ciphertext.parent.mkdir()
        ciphertext.write_bytes(b"ciphertext")
        ci.clean_private(root, "17-1")
        self.assertFalse(root.exists())
        self.assertEqual(ciphertext.read_bytes(), b"ciphertext")

    def test_cleanup_refuses_other_execution_ownership(self):
        root = self.root / "ci-private"
        ci.prepare(root, "another-run")
        with self.assertRaises(RuntimeError):
            ci.clean_private(root, "17-1")
        self.assertTrue(root.is_dir())

    def test_workspace_preparation_does_not_follow_an_ownership_symlink(self):
        root = self.root / "ci-private"
        root.mkdir()
        outside = self.root / "outside"
        outside.write_text("outside-content")
        (root / ".owned").symlink_to(outside)
        with self.assertRaises(RuntimeError):
            ci.prepare(root, "17-1")
        self.assertEqual(outside.read_text(), "outside-content")


class EncryptionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.evidence = self.root / "private/evidence"
        self.evidence.mkdir(parents=True)
        self.destination = self.root / "encrypted/report.tar.age"
        (self.evidence / "receipt.json").write_text(json.dumps(dict(source_sha="a" * 40, status="passed")))
        (self.evidence / "execution.log").write_text("private source and detailed test output")

    def test_actual_age_round_trip_keeps_only_ciphertext_in_publish_directory(self):
        age = os.environ.get("PUBLIC_CI_AGE") or shutil.which("age")
        self.assertTrue(age, "Install the pinned tools before running encryption tests.")
        keygen = str(Path(age).with_name("age-keygen"))
        identity = self.root / "identity.agekey"
        subprocess.run([keygen, "-o", str(identity)], check=True, capture_output=True)
        recipient = subprocess.check_output([keygen, "-y", str(identity)], text=True).strip()
        ci.seal(self.evidence, self.destination, recipient, age)
        encrypted = self.destination.read_bytes()
        self.assertTrue(encrypted.startswith(b"age-encryption.org/v1"))
        self.assertNotIn(b"private source", encrypted)
        self.assertEqual(list(self.destination.parent.iterdir()), [self.destination])
        raw = subprocess.check_output([age, "--decrypt", "-i", str(identity), str(self.destination)])
        with tarfile.open(fileobj=io.BytesIO(raw), mode="r:gz") as archive:
            self.assertEqual(archive.extractfile("evidence/execution.log").read(),
                             b"private source and detailed test output")
            self.assertEqual(json.load(archive.extractfile("evidence/receipt.json"))["status"], "passed")

    def test_encryption_failure_leaves_no_uploadable_partial_or_old_ciphertext(self):
        self.destination.parent.mkdir()
        self.destination.write_bytes(b"obsolete report")
        fake_age = self.root / "failing-age"
        fake_age.write_text("#!/bin/sh\nprintf partial\nexit 1\n")
        fake_age.chmod(0o700)
        with self.assertRaises((RuntimeError, BrokenPipeError)):
            ci.seal(self.evidence, self.destination, RECIPIENT, str(fake_age))
        self.assertFalse(self.destination.exists())
        self.assertEqual(list(self.destination.parent.iterdir()), [])
        self.assertTrue((self.evidence / "execution.log").is_file())

    def test_report_links_are_rejected_before_starting_encryption(self):
        (self.evidence / "linked-report").symlink_to("/dev/stdout")
        with patch.object(ci.subprocess,"Popen") as encryption, self.assertRaises(RuntimeError):
            ci.seal(self.evidence,self.destination,RECIPIENT)
        encryption.assert_not_called()
        self.assertFalse(self.destination.exists())


class EvidenceBoundaryTests(unittest.TestCase):
    def setUp(self):
        self.temporary=tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root=Path(self.temporary.name)
        self.home=self.root/"worker-home"
        self.evidence=self.home/"work/evidence"
        self.evidence.mkdir(parents=True)
        self.output=self.root/"trusted-copy"

    def collect(self):
        isolation.collect_evidence(self.home,self.output,os.getuid(),os.getuid(),os.getgid())

    def test_regular_worker_reports_are_copied_as_new_nonexecutable_runner_files(self):
        report=self.evidence/"checks/native.json"
        report.parent.mkdir()
        report.write_text('{"status":"passed"}')
        report.chmod(0o777)
        self.collect()
        copied=self.output/"checks/native.json"
        self.assertEqual(copied.read_text(),report.read_text())
        self.assertNotEqual(copied.stat().st_ino,report.stat().st_ino)
        self.assertEqual(copied.stat().st_mode & 0o777,0o600)

    def test_symlinks_hardlinks_and_special_files_cannot_be_imported(self):
        outside=self.root/"runner-owned"
        outside.write_text("unchanged")
        candidate=self.evidence/"receipt.json"
        for kind in ["stdout","runner-file","hardlink","fifo"]:
            with self.subTest(kind=kind):
                if kind=="stdout":candidate.symlink_to("/dev/stdout")
                elif kind=="runner-file":candidate.symlink_to(outside)
                elif kind=="hardlink":os.link(outside,candidate)
                else:os.mkfifo(candidate)
                with self.assertRaises((RuntimeError,OSError)):self.collect()
                self.assertFalse(self.output.exists())
                self.assertEqual(outside.read_text(),"unchanged")
                candidate.unlink()

    def test_worker_cannot_redirect_a_parent_directory_of_the_report_tree(self):
        self.evidence.rmdir()
        (self.home/"work").rmdir()
        (self.home/"work").symlink_to(self.root,target_is_directory=True)
        with self.assertRaises(OSError):self.collect()
        self.assertFalse(self.output.exists())

    def test_trusted_writes_never_follow_links_or_truncate_a_linked_runner_file(self):
        original=self.root/"original"
        original.write_text("keep this")
        output=self.root/"receipt.json"
        output.symlink_to(original)
        with self.assertRaises(OSError):ci.write_json(output,dict(private="data"))
        self.assertEqual(original.read_text(),"keep this")
        output.unlink();os.link(original,output)
        with self.assertRaises(RuntimeError):ci.write_json(output,dict(private="data"))
        self.assertEqual(original.read_text(),"keep this")


if __name__ == "__main__":
    unittest.main()
