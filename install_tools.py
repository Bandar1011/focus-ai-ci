#!/usr/bin/env python3
"""Install hash-pinned public CI tools into the job-owned temporary directory."""
import hashlib
import os
from pathlib import Path
import platform
import subprocess
import tarfile
from urllib.request import urlopen


PINS = {
    ("Linux", "x86_64"): (
        ("https://github.com/FiloSottile/age/releases/download/v1.3.2/age-v1.3.2-linux-amd64.tar.gz",
         "cbe24006683f8eb669266162894b9a522a1af52f2665fbc63a4bb032ed26ac10", ["age/age", "age/age-keygen"]),
        ("https://github.com/rhysd/actionlint/releases/download/v1.7.12/actionlint_1.7.12_linux_amd64.tar.gz",
         "8aca8db96f1b94770f1b0d72b6dddcb1ebb8123cb3712530b08cc387b349a3d8", ["actionlint"])),
    ("Darwin", "arm64"): (
        ("https://github.com/FiloSottile/age/releases/download/v1.3.2/age-v1.3.2-darwin-arm64.tar.gz",
         "e2020b073c44f692685a24d6abc378817eb81ffaaf49fd0531ef8565f767f2f5", ["age/age", "age/age-keygen"]),
        ("https://github.com/rhysd/actionlint/releases/download/v1.7.12/actionlint_1.7.12_darwin_arm64.tar.gz",
         "aba9ced2dee8d27fecca3dc7feb1a7f9a52caefa1eb46f3271ea66b6e0e6953f", ["actionlint"]))}


def install(url, digest, members, directory):
    archive = directory / "download.tar.gz"
    with urlopen(url, timeout=60) as response, archive.open("wb") as output:
        while chunk := response.read(1024 * 1024):
            output.write(chunk)
    with archive.open("rb") as downloaded:
        actual_digest = hashlib.file_digest(downloaded, "sha256").hexdigest()
    if actual_digest != digest:
        raise RuntimeError("Downloaded tool checksum mismatch.")
    with tarfile.open(archive) as bundle:
        for member in members:
            entry = bundle.getmember(member)
            if not entry.isfile():
                raise RuntimeError("Pinned executable is not a regular file.")
            output = directory / Path(member).name
            with bundle.extractfile(entry) as source, output.open("wb") as target:
                target.write(source.read())
            output.chmod(0o755)
    archive.unlink()


def main():
    directory = Path(os.environ["RUNNER_TEMP"]) / "public-ci-tools"
    directory.mkdir(parents=True, exist_ok=True)
    for pin in PINS[(platform.system(), platform.machine())]:
        install(*pin, directory)
    if os.environ.get("CI_NATIVE_TOOLS") == "true":
        if platform.system() != "Darwin":
            raise RuntimeError("Native tools require the native runner.")
        subprocess.run(["brew", "install", "xcodegen"], check=True)
    with open(os.environ["GITHUB_PATH"], "a") as output:
        output.write(str(directory) + "\n")


if __name__ == "__main__":
    main()
