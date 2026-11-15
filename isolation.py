"""Run private checks as a job-owned, locked account on an ephemeral hosted runner."""
from __future__ import annotations

import os
from contextlib import nullcontext
from pathlib import Path
import platform
import pwd
import shutil
import signal
import subprocess
import sys
import time


PROBE = r'''
import ctypes, json, os, pathlib, subprocess, sys
paths, parent = json.loads(sys.argv[1]), int(sys.argv[2])
assert os.getuid() != int(sys.argv[3]) and os.getuid() != 0
for path in paths:
    try:
        fd = os.open(path, os.O_WRONLY | os.O_APPEND)
    except (PermissionError, FileNotFoundError):
        continue
    os.close(fd)
    raise RuntimeError('Runner file is writable from the private account')
if sys.platform == 'linux':
    for path in [f'/proc/{parent}/environ', f'/proc/{parent}/fd/1']:
        try:
            fd = os.open(path, os.O_RDONLY)
        except (PermissionError, FileNotFoundError):
            continue
        os.close(fd)
        raise RuntimeError('Runner process is accessible from the private account')
else:
    libc = ctypes.CDLL(None, use_errno=True)
    mib = (ctypes.c_int * 3)(1, 49, parent)
    length = ctypes.c_size_t(1024 * 1024)
    data = ctypes.create_string_buffer(length.value)
    assert libc.sysctl(mib, 3, data, ctypes.byref(length), None, 0) != 0, 'Runner environment is accessible'
assert subprocess.run(['sudo', '-n', 'true'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode != 0
print('boundary-ok')
'''


class CleanupError(RuntimeError):
    pass


def active_group(group):
    rows = subprocess.check_output(["ps", "-axo", "pid=,pgid=,stat="], text=True)
    return [int(parts[0]) for row in rows.splitlines() if len(parts := row.split()) == 3
            and int(parts[1]) == group and not parts[2].startswith("Z")]


def run_private(command, cwd, log, env, timeout, privileged=False):
    with log.open("ab") if isinstance(log, Path) else nullcontext(log) as output:
        child = subprocess.Popen(command, cwd=cwd, env=env, stdin=subprocess.DEVNULL,
                                 stdout=output, stderr=subprocess.STDOUT, start_new_session=True)
        try:
            result = child.wait(timeout=timeout)
        except BaseException:
            for sig, grace in [(signal.SIGTERM, 0.5), (signal.SIGKILL, 2)]:
                if privileged:
                    subprocess.run(["sudo", "-n", "/bin/kill", "-" + signal.Signals(sig).name[3:],
                                    "--", "-" + str(child.pid)], stdout=output,
                                   stderr=subprocess.STDOUT, check=False, timeout=10)
                else:
                    try:
                        os.killpg(child.pid, sig)
                    except ProcessLookupError:
                        pass
                deadline = time.monotonic() + grace
                while active_group(child.pid) and time.monotonic() < deadline:
                    time.sleep(0.05)
            child.wait(timeout=5)
            if active_group(child.pid):
                raise CleanupError("Owned command group remains active.")
            raise
    if result:
        raise RuntimeError("Private verification command failed.")


class PrivateUser:
    def __init__(self, root, logs):
        if (os.environ.get("GITHUB_ACTIONS") != "true"
                or os.environ.get("RUNNER_ENVIRONMENT") != "github-hosted"):
            raise RuntimeError("Private account setup is restricted to ephemeral GitHub-hosted runners.")
        self.original = root.resolve()
        self.username, self.uid = "ciworker", 60001
        self.macos = platform.system() == "Darwin"
        self.home = Path("/Users" if self.macos else "/home") / self.username
        self.root = self.home / "work"
        self.original_uid, self.original_gid = os.getuid(), os.getgid()
        self.logs = {name: (root / "evidence" / name).open("ab") for name in logs}
        self.created = False
        self.moved = False

    def sudo(self, *arguments, check=True):
        return subprocess.run(["sudo", "-n", *map(str, arguments)], check=check,
                              stdout=self.logs["isolation.log"], stderr=subprocess.STDOUT,
                              stdin=subprocess.DEVNULL, timeout=30)

    def __enter__(self):
        try:
            try:
                pwd.getpwnam(self.username)
            except KeyError:
                pass
            else:
                raise RuntimeError("Private account already exists; refusing to adopt it.")
            try:
                pwd.getpwuid(self.uid)
            except KeyError:
                pass
            else:
                raise RuntimeError("Private account UID is already allocated.")
            if self.home.exists():
                raise RuntimeError("Private home already exists; refusing to adopt it.")
            if self.macos:
                self.sudo("dscl", ".", "-create", "/Users/" + self.username)
                self.created = True
                for key, value in [("UniqueID", str(self.uid)), ("PrimaryGroupID", "20"),
                                   ("NFSHomeDirectory", str(self.home)), ("UserShell", "/usr/bin/false"),
                                   ("Password", "*"), ("IsHidden", "1")]:
                    self.sudo("dscl", ".", "-create", "/Users/" + self.username, key, value)
            else:
                self.sudo("useradd", "--uid", str(self.uid), "--user-group", "--no-create-home",
                          "--home-dir", self.home, "--shell", "/usr/sbin/nologin", self.username)
                self.created = True
            self.sudo("mkdir", "-m", "700", self.home)
            for path in [Path(os.environ["RUNNER_TEMP"]), Path(os.environ["GITHUB_WORKSPACE"]),
                         Path(os.environ["RUNNER_TEMP"]).parent,
                         Path.home() / "runners", Path.home() / ".ssh", Path.home() / ".config"]:
                if path.exists():
                    path.chmod(0o700)
            self.sudo("mkdir", self.home / "tools", self.home / "tmp")
            for name in ["actionlint", "simslim", "xcodegen"]:
                executable = shutil.which(name)
                if executable:
                    self.sudo("cp", str(Path(executable).resolve()), self.home / "tools" / name)
            self.sudo("mv", self.original, self.root)
            self.moved = True
            self.sudo("chown", "-R", str(self.uid), self.home)
            if self.macos:
                self.sudo("launchctl", "bootstrap", "user/" + str(self.uid))
            return self
        except BaseException:
            self.close()
            raise

    def mapped(self, value):
        value = str(value)
        return str(self.root) + value[len(str(self.original)):] if (
            value == str(self.original) or value.startswith(str(self.original) + "/")) else value

    def run(self, command, cwd, log, env, timeout):
        values = {name: self.mapped(value) for name, value in env.items()}
        values.update(HOME=str(self.home), USER=self.username, LOGNAME=self.username,
                      TMPDIR=str(self.home / "tmp"), RUNNER_TEMP=str(self.home / "tmp"))
        values["PATH"] = str(self.home / "tools") + ":" + values["PATH"]
        prefix = ["sudo", "-n"]
        if self.macos:
            prefix += ["launchctl", "asuser", str(self.uid), "sudo", "-n"]
        prefix += ["-u", self.username, "--", "/usr/bin/env", "-i"]
        arguments = prefix + [name + "=" + value for name, value in values.items()]
        arguments += ["/bin/sh", "-c", 'cd "$1" && shift && exec "$@"', "ci-private",
                      self.mapped(cwd), *[self.mapped(part) for part in command]]
        run_private(arguments, None, self.logs[log], dict(os.environ), timeout, privileged=True)

    def probe(self, env):
        import json
        protected = [str(Path(os.environ["GITHUB_WORKSPACE"]) / "ci.py")]
        protected += [os.environ[name] for name in ["GITHUB_OUTPUT", "GITHUB_ENV", "GITHUB_PATH", "GITHUB_STEP_SUMMARY"]
                      if os.environ.get(name)]
        self.run([sys.executable, "-c", PROBE, json.dumps(protected), str(os.getpid()), str(self.original_uid)],
                 self.original, "isolation.log", env, 30)

    def active(self):
        rows = subprocess.check_output(["ps", "-axo", "uid=,pid=,stat="], text=True)
        return [int(parts[1]) for row in rows.splitlines() if len(parts := row.split()) == 3
                and int(parts[0]) == self.uid and not parts[2].startswith("Z")]

    def close(self):
        try:
            if self.created:
                if self.macos:
                    self.sudo("launchctl", "bootout", "user/" + str(self.uid), check=False)
                for sig, grace in [("-TERM", 1), ("-KILL", 3)]:
                    self.sudo("pkill", sig, "-U", str(self.uid), check=False)
                    deadline = time.monotonic() + grace
                    while self.active() and time.monotonic() < deadline:
                        time.sleep(0.05)
                if self.active():
                    raise CleanupError("Private user processes remain; retain its workspace.")
                self.sudo("chown", "-R", "-P", f"{self.original_uid}:{self.original_gid}", self.home)
                if self.moved:
                    if self.root.is_symlink() or not (self.root / ".owned").is_file():
                        raise CleanupError("Private workspace identity was replaced.")
                    shutil.move(str(self.root), str(self.original))
                    self.moved = False
                self.sudo("dscl", ".", "-delete", "/Users/" + self.username) if self.macos else self.sudo("userdel", self.username)
                self.created = False
                # The parent of this job-created home belongs to root.
                self.sudo("rm", "-rf", self.home)
        finally:
            for output in self.logs.values():
                output.close()

    def __exit__(self, *exception):
        self.close()
