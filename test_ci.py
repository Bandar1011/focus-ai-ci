import contextlib
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch
from urllib.error import HTTPError

import ci


SOURCE = "owner/private"
PUBLIC = "owner/ci"
PIPELINE = "c" * 40
RECIPIENT = "age1-test-recipient"
CANDIDATE = ci.Candidate("a" * 40, "b" * 40, "refs/heads/development", "d" * 16)


def key(candidate=CANDIDATE, kind="quick"):
    return ci.request_key(kind, candidate.source_sha, candidate.control_sha, PIPELINE, RECIPIENT)


def run(kind="quick", request=None, **changes):
    value = dict(id=17, run_attempt=1, display_title=f"{kind}:{CANDIDATE.slot}:{request or key(kind=kind)}",
                 head_sha=PIPELINE, head_branch="main", path=ci.WORKFLOW, event="workflow_dispatch",
                 repository=dict(full_name=PUBLIC), head_repository=dict(full_name=PUBLIC),
                 status="completed", conclusion="success", html_url=f"https://github.com/{PUBLIC}/actions/runs/17")
    value.update(changes)
    return value


class FakeAPI:
    def __init__(self, repository, responses=None, rows=None):
        self.repository = repository
        self.responses = responses or {}
        self.rows = rows or {}
        self.writes = []

    def api(self, method, path, value=None):
        if method == "GET":
            return self.responses[path]
        self.writes.append((path, value))

    def pages(self, path, field=None):
        yield from self.rows.get(path, [])


class ControllerTests(unittest.TestCase):
    def source(self):
        return FakeAPI(SOURCE)

    def public(self, worker=None, artifact=True):
        worker = worker or run()
        reports = [dict(name=f"report-quick-{key()}-attempt-{worker['run_attempt']}",
                        expired=False, size_in_bytes=800)] if artifact else []
        return FakeAPI(PUBLIC, {"actions/runs/17": worker},
                       {"actions/runs/17/artifacts": reports})

    def reconcile(self, source, public, **kwargs):
        values = dict(candidate=CANDIDATE, kind="quick", pipeline_sha=PIPELINE, recipient=RECIPIENT,
                      previous=None, recent=[], eligible=True)
        values.update(kwargs)
        return ci.reconcile(source, public, **values)

    def test_active_job_is_reconciled_without_duplicate_dispatch(self):
        source, worker = self.source(), run(status="in_progress", conclusion=None)
        public = self.public(worker)
        result = self.reconcile(source, public, recent=[worker])
        self.assertEqual(result, "active")
        self.assertFalse(public.writes)
        self.assertEqual(source.writes[0][1]["state"], "pending")

    def test_success_requires_current_run_and_ciphertext_from_current_attempt(self):
        source, public = self.source(), self.public()
        self.assertEqual(self.reconcile(source, public, recent=[run()]), "passed")
        self.assertEqual(source.writes[-1][1]["state"], "success")
        public.rows["actions/runs/17/artifacts"][0]["expired"] = True
        source.writes.clear()
        self.assertEqual(self.reconcile(source, public, recent=[run()]), "dispatched")
        self.assertEqual(source.writes[-1][1]["state"], "pending")
        self.assertEqual(len(public.writes), 1)
        public.rows["actions/runs/17/artifacts"][0]["expired"] = False
        self.assertEqual(self.reconcile(self.source(), public, recent=[run(run_attempt=2)]), "dispatched")

    def test_missing_ciphertext_does_not_reuse_a_green_run(self):
        source, public = self.source(), self.public(artifact=False)
        self.assertEqual(self.reconcile(source, public, recent=[run()]), "dispatched")
        self.assertNotIn("success", [value["state"] for _, value in source.writes])

    def test_workflow_cleanup_failure_cannot_become_private_success(self):
        source, public = self.source(), self.public()
        self.assertEqual(self.reconcile(source, public, recent=[run(conclusion="failure")]), "failed")
        self.assertEqual(source.writes[-1][1]["state"], "failure")
        self.assertFalse(public.writes)

    def test_unchanged_failure_is_not_automatically_retried_even_after_history_expires(self):
        source, public = self.source(), self.public()
        previous = dict(description=f"request:{key()} failed", state="failure", target_url="")
        self.assertEqual(self.reconcile(source, public, previous=previous), "failed")
        self.assertFalse(public.writes)
        self.assertFalse(source.writes)

    def test_explicit_force_can_reinvestigate_failure_but_does_not_duplicate_running_work(self):
        source, public = self.source(), self.public()
        self.assertEqual(self.reconcile(source, public, recent=[run(conclusion="failure")], force=True), "dispatched")
        public.writes.clear()
        self.assertEqual(self.reconcile(source, public, recent=[run(status="queued", conclusion=None)], force=True), "active")
        self.assertFalse(public.writes)

    def test_every_bound_identity_and_report_recipient_invalidates_previous_proof(self):
        original = key()
        inputs = ["quick", CANDIDATE.source_sha, CANDIDATE.control_sha, PIPELINE, RECIPIENT]
        for index, replacement in enumerate(["full", "d" * 40, "e" * 40, "f" * 40, "rotated-recipient"]):
            changed = inputs.copy()
            changed[index] = replacement
            self.assertNotEqual(original, ci.request_key(*changed))
        source, public = self.source(), self.public()
        changed = ci.Candidate(CANDIDATE.source_sha, "e" * 40, CANDIDATE.source_ref, CANDIDATE.slot)
        self.assertEqual(self.reconcile(source, public, candidate=changed, recent=[run()]), "dispatched")
        self.assertEqual(source.writes[-1][1]["state"], "pending")

    def test_existing_status_pointer_works_outside_bounded_recent_history(self):
        source, public = self.source(), self.public()
        previous = dict(description=f"request:{key()} running", target_url=run()["html_url"])
        self.assertEqual(self.reconcile(source, public, previous=previous), "passed")

    def test_deleted_run_does_not_preserve_old_green_status(self):
        source, public = self.source(), self.public()
        previous = dict(description=f"request:{key()} passed", target_url=run()["html_url"], state="success")
        with patch.object(public, "api", side_effect=[HTTPError("https://api.github.com/", 404, "Not Found", {}, None), None]):
            self.assertEqual(self.reconcile(source, public, previous=previous), "dispatched")
        self.assertEqual(source.writes[-1][1]["state"], "pending")

    def test_dispatch_indexing_gap_is_not_permission_to_duplicate_or_pass(self):
        source, public = self.source(), self.public()
        previous = dict(description=f"request:{key()} queued", state="pending", target_url="")
        self.assertEqual(self.reconcile(source, public, previous=previous), "unresolved")
        self.assertFalse(public.writes)
        self.assertFalse(source.writes)

    def test_outdated_full_proof_stays_pending_until_a_scheduled_or_manual_start(self):
        source, public = self.source(), self.public()
        self.assertEqual(self.reconcile(source, public, kind="full", eligible=False,
                                        recent=[run(kind="full", head_sha="e" * 40)]), "scheduled")
        self.assertEqual(source.writes[-1][1]["state"], "pending")
        self.assertFalse(public.writes)

    def test_foreign_branch_workflow_and_repository_cannot_supply_proof(self):
        for change in [dict(head_sha="f" * 40), dict(head_branch="feature"), dict(event="pull_request"),
                       dict(path=".github/workflows/self-test.yml"),
                       dict(head_repository=dict(full_name="someone/fork")),
                       dict(repository=dict(full_name="someone/fork"))]:
            with self.subTest(change=change):
                self.assertEqual(self.reconcile(self.source(), self.public(), recent=[run(**change)]), "dispatched")

    def test_status_writes_are_idempotent(self):
        source = self.source()
        previous = dict(context="ci/public-quick", state="success", description=f"request:{key()} passed",
                        target_url=run()["html_url"])
        self.assertEqual(self.reconcile(source, self.public(), previous=previous), "passed")
        self.assertFalse(source.writes)

    def test_default_branch_and_current_same_repo_prs_exclude_forks_and_duplicate_sha(self):
        source = FakeAPI(SOURCE, {"commits/development": {"sha": "b" * 40}}, {
            "pulls?state=open": [dict(head=dict(sha="a" * 40, ref="feature", repo=dict(full_name=SOURCE))),
                                dict(head=dict(sha="d" * 40, ref="fork", repo=dict(full_name="someone/fork"))),
                                dict(head=dict(sha="a" * 40, ref="duplicate", repo=dict(full_name=SOURCE)))]})
        candidates = ci.discover(source, "development")
        self.assertEqual([candidate.source_sha for candidate in candidates], ["b" * 40, "a" * 40])
        self.assertTrue(all(candidate.control_sha == "b" * 40 for candidate in candidates))

    def test_source_discovery_paginates_and_does_not_silently_truncate(self):
        github = ci.GitHub(SOURCE, "test-token")
        with patch.object(github, "api", side_effect=[list(range(100)), [100]]):
            self.assertEqual(len(list(github.pages("pulls?state=open"))), 101)
        with patch.object(github, "api", return_value=list(range(100))):
            with self.assertRaisesRegex(RuntimeError, "pagination"):
                list(github.pages("pulls?state=open", limit=1))

    def test_credential_bearing_commands_reject_feature_refs(self):
        with patch.dict(os.environ, {"GITHUB_REF": "refs/heads/feature"}):
            with self.assertRaises(RuntimeError):
                ci.require_main()

    def test_superseded_controller_does_not_publish_stale_private_statuses(self):
        values = dict(GITHUB_REF="refs/heads/main", GITHUB_SHA=PIPELINE, GITHUB_REPOSITORY=PUBLIC,
                      CI_SOURCE_REPOSITORY=SOURCE, CI_SOURCE_TOKEN="source-token", GH_TOKEN="public-token",
                      REPORT_RECIPIENT=RECIPIENT)
        with patch.dict(os.environ, values), patch.object(ci.GitHub, "api", return_value={"object": {"sha": "d" * 40}}) as api:
            with self.assertRaisesRegex(RuntimeError, "superseded"):
                ci.controller()
        self.assertEqual(api.call_args.args, ("GET", "git/ref/heads/main"))


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

    def test_stale_request_is_rejected_before_any_source_checkout(self):
        ci.prepare(self.root / "ci-private", "17-1")
        values = dict(RUNNER_TEMP=str(self.root), GITHUB_REF="refs/heads/main", GITHUB_SHA=PIPELINE,
                      CI_SOURCE_REPOSITORY=SOURCE, CI_SOURCE_TOKEN="test-token", CI_KIND="quick",
                      CI_REQUEST="0" * 64, CI_SLOT=CANDIDATE.slot, REPORT_RECIPIENT=RECIPIENT)
        with patch.dict(os.environ, values), patch.object(ci, "discover", return_value=[CANDIDATE]), \
                patch.object(ci, "fetch_commit") as fetch:
            with self.assertRaisesRegex(RuntimeError, "stale"):
                ci.checkout()
        fetch.assert_not_called()

    def test_checkout_credentials_are_removed_even_when_fetch_fails(self):
        root = self.root / "ci-private"
        ci.prepare(root, "17-1")
        values = dict(RUNNER_TEMP=str(self.root), GITHUB_REF="refs/heads/main", GITHUB_SHA=PIPELINE,
                      GITHUB_RUN_ID="17", GITHUB_RUN_ATTEMPT="1", CI_SOURCE_REPOSITORY=SOURCE,
                      CI_SOURCE_TOKEN="test-token", CI_KIND="quick", CI_REQUEST=key(),
                      CI_SLOT=CANDIDATE.slot, REPORT_RECIPIENT=RECIPIENT)
        def fail(*_args):
            (root / "credentials").mkdir()
            (root / "credentials/key").write_text("credential")
            raise RuntimeError("fetch failed")
        with patch.dict(os.environ, values), patch.object(ci, "discover", return_value=[CANDIDATE]), \
                patch.object(ci, "fetch_commit", side_effect=fail):
            with self.assertRaises(RuntimeError):
                ci.checkout()
        self.assertFalse((root / "credentials").exists())

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


if __name__ == "__main__":
    unittest.main()
