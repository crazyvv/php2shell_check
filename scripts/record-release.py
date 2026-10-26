#!/usr/bin/env python3
"""Persist a non-secret release receipt in a separate branch for Git-only clients."""
import argparse
import datetime
import json
import os
import re
import subprocess
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def git(*args, cwd=ROOT, check=True):
    return subprocess.run(["git", *args], cwd=cwd, capture_output=True, text=True, check=check)


def main(tag):
    if not re.fullmatch(r"v[0-9]+\.[0-9]+\.[0-9]+", tag):
        raise ValueError("Invalid version tag")
    status_path = ROOT / "release-status.json"
    if status_path.is_file():
        status = json.loads(status_path.read_text(encoding="utf-8"))
    else:
        status = {"state": "failed", "tag": tag, "repository": os.environ["GITHUB_REPOSITORY"],
                  "build_result": os.environ.get("BUILD_RESULT", "unknown"),
                  "publish_result": os.environ.get("PUBLISH_RESULT", "unknown"),
                  "source_commit": git("rev-parse", "HEAD").stdout.strip(),
                  "workflow_run": f"https://github.com/{os.environ['GITHUB_REPOSITORY']}/actions/runs/{os.environ['GITHUB_RUN_ID']}"}
    report = ROOT / "release-diagnostics/browser-result.json"
    if report.is_file():
        status["browser_check"] = json.loads(report.read_text(encoding="utf-8"))
    status["recorded_at"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
    fetch = git("fetch", "origin", "refs/heads/release-manifests", check=False)
    with tempfile.TemporaryDirectory() as temp:
        work = Path(temp) / "receipt"
        git("worktree", "add", "--detach", str(work), "FETCH_HEAD" if fetch.returncode == 0 else "HEAD")
        try:
            if fetch.returncode != 0:
                git("checkout", "--orphan", "release-receipt-" + os.environ["GITHUB_RUN_ID"], cwd=work)
                git("rm", "-rf", ".", cwd=work)
            git("config", "user.name", "github-actions[bot]", cwd=work)
            git("config", "user.email", "41898282+github-actions[bot]@users.noreply.github.com", cwd=work)
            filename = tag + ".json"
            (work / filename).write_text(json.dumps(status, indent=2) + "\n", encoding="utf-8")
            git("add", filename, cwd=work)
            if git("diff", "--cached", "--quiet", cwd=work, check=False).returncode != 0:
                git("commit", "-m", f"Release {tag}: {status['state']}", cwd=work)
                git("push", "origin", "HEAD:refs/heads/release-manifests", cwd=work)
        finally:
            git("worktree", "remove", "--force", str(work), check=False)
    print(json.dumps(status, indent=2))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tag", required=True)
    main(parser.parse_args().tag)
