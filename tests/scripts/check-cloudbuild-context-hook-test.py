#!/usr/bin/env python3
"""Deployment fixtures must not change the repository invoking a Git hook."""

import os
from pathlib import Path
import shutil
import subprocess
import tempfile


source = Path(__file__).resolve().parents[2]
environment = os.environ.copy()
for name in subprocess.check_output(
    ["git", "rev-parse", "--local-env-vars"], cwd=source, text=True
).splitlines():
    environment.pop(name, None)

with tempfile.TemporaryDirectory(prefix="keycast-hook-test-") as directory:
    fixture = Path(directory)
    for relative in (
        "scripts/check-cloudbuild-context.sh",
        "tests/scripts/check-cloudbuild-context-test.sh",
        "tests/fixtures/bin/gcloud",
    ):
        destination = fixture / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source / relative, destination)

    def git(*arguments):
        return subprocess.check_output(
            ["git", *arguments], cwd=fixture, env=environment, text=True
        ).strip()

    git("init", "--quiet")
    git("add", ".")
    git(
        "-c", "user.name=Keycast Tests",
        "-c", "user.email=tests@keycast.invalid",
        "-c", "commit.gpgsign=false", "commit", "--quiet", "-m", "fixture",
    )
    original_head = git("rev-parse", "HEAD")
    original_index = git("write-tree")
    hook_environment = environment | {
        "GIT_DIR": str(fixture / ".git"),
        "GIT_INDEX_FILE": str(fixture / ".git/index"),
    }
    result = subprocess.run(
        ["bash", "tests/scripts/check-cloudbuild-context-test.sh"],
        cwd=fixture, env=hook_environment, check=False,
    )
    assert git("rev-parse", "HEAD") == original_head, "fixture changed the caller's HEAD"
    assert git("write-tree") == original_index, "fixture changed the caller's index"
    assert git("config", "--get", "core.bare") == "false", "fixture changed repository mode"
    assert git("status", "--porcelain") == "", "fixture dirtied its caller"
    result.check_returncode()

print("Cloud Build test fixtures preserve the invoking Git repository.")
