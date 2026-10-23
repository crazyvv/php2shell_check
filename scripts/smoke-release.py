#!/usr/bin/env python3
"""Run a packaged-platform executable locally, without scanning external targets."""
import argparse
import json
import socket
import subprocess
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def run(binary, *args, expected=0):
    result = subprocess.run([str(binary), *args], capture_output=True, text=True,
                            encoding="utf-8", errors="replace", timeout=40)
    if result.returncode != expected:
        raise RuntimeError(f"{args[0]} returned {result.returncode}: {result.stderr}")
    return result


def smoke(binary):
    run(binary, "--version")
    run(binary, "--help")
    with tempfile.TemporaryDirectory() as temp:
        directory = Path(temp)
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            port = sock.getsockname()[1]
        config = json.loads((ROOT / "config.open.example.json").read_text())
        config["public_origin"] = f"http://127.0.0.1:{port}"
        config["database"] = str(directory / "state.sqlite3")
        path = directory / "config.json"
        path.write_text(json.dumps(config), encoding="utf-8")
        denied = run(binary, "check", "http://127.0.0.1", "--config", str(path),
                     "--headers-only", "--json", expected=3)
        assert json.loads(denied.stdout)["patch_status"] == "unknown"
        process = subprocess.Popen([str(binary), "serve", "--config", str(path),
                                    "--port", str(port)], stdout=subprocess.DEVNULL,
                                   stderr=subprocess.DEVNULL)
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        try:
            deadline = time.monotonic() + 20
            while True:
                try:
                    with opener.open(config["public_origin"] + "/api/me", timeout=2) as response:
                        assert json.loads(response.read())["allow_anonymous"] is True
                    break
                except (OSError, urllib.error.URLError):
                    if process.poll() is not None or time.monotonic() > deadline:
                        raise RuntimeError("Web service failed its local smoke check")
                    time.sleep(0.2)
            with opener.open(config["public_origin"] + "/", timeout=2) as response:
                assert "PHP 安全自查台" in response.read().decode("utf-8")
        finally:
            process.terminate()
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)
        if "windows" in binary.name or binary.suffix == ".exe":
            result = run(binary, "collect", expected=1)
            assert "Linux" in result.stderr
        else:
            report = json.loads(run(binary, "collect").stdout)
            assert report["schema"] == "php-selfcheck-host/v1"
            assert report["php_command"]["status"] == "disabled"
    print("Native release smoke checks passed:", binary.name)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    smoke(parser.parse_args().binary.resolve())
