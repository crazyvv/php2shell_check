#!/usr/bin/env python3
"""Upload a draft, download and verify both archives, then publish atomically."""
import argparse
import hashlib
import importlib.util
import json
import os
import subprocess
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("packaging", ROOT / "scripts/package-release.py")
packaging = importlib.util.module_from_spec(spec)
spec.loader.exec_module(packaging)


def command(*args, check=True):
    return subprocess.run(args, check=check, capture_output=True, text=True)


def main(tag, directory):
    packaging.validate_tag(tag)
    repository = os.environ["GITHUB_REPOSITORY"]
    expected = {f"php-selfcheck-{tag}-linux-x86_64.tar.gz",
                f"php-selfcheck-{tag}-windows-x86_64.zip"}
    archives = sorted(path for path in directory.iterdir() if path.name in expected)
    if {path.name for path in archives} != expected:
        raise RuntimeError("Both tested Windows and Linux archives are required")
    hashes = {path.name: hashlib.sha256(path.read_bytes()).hexdigest() for path in archives}
    sums = directory / "SHA256SUMS"
    sums.write_text("".join(f"{digest}  {name}\n" for name, digest in sorted(hashes.items())), encoding="utf-8")
    attachments = archives + [sums]
    notes = directory / "release-notes.md"
    notes.write_text(f"""PHP 安全自查台 {tag}

下载对应系统的程序包，解压后阅读 `START-HERE.txt` 和 `README.md`。

| 附件 | 适用系统 |
| --- | --- |
| `php-selfcheck-{tag}-windows-x86_64.zip` | Windows x86_64，MSVC 构建 |
| `php-selfcheck-{tag}-linux-x86_64.tar.gz` | Linux x86_64，musl 静态构建 |
| `SHA256SUMS` | 两个程序包的 SHA-256 校验值 |

包含独立扫描页面、管理员历史/筛选/删除、SQLite 持久化、轻量响应头模式、CI 检查命令，以及可选 PHP 命令、中间件、进程端口和厂商补丁参考核验。

Windows 支持 Web 服务及 URL 检查；`collect` 主机采集目前仅支持 Linux。Linux 的 HTTPS 检测仍需系统 CA 证书。Windows 如提示缺少运行库，请安装微软官方 Visual C++ 2015–2022 Redistributable x64。

两个平台都须通过测试及本机启动检查后才能发布。发布包不含真实配置、管理员密码、数据库或扫描结果。免密码与无白名单通过 `init --allow-anonymous --allow-without-whitelist` 显式开启。

PHP 版本声明与厂商参考规则匹配不能直接证明已修复；部分厂商参考阈值尚需独立复核。
""", encoding="utf-8")
    existing = command("gh", "release", "view", tag, "--repo", repository,
                       "--json", "url,isDraft,assets,tagName", check=False)
    already_published = False
    if existing.returncode == 0:
        release = json.loads(existing.stdout)
        already_published = not release["isDraft"]
        if release["isDraft"]:
            command("gh", "release", "upload", tag, "--repo", repository,
                    "--clobber", *(str(path) for path in attachments))
    else:
        command("gh", "release", "create", tag, "--repo", repository, "--verify-tag",
                "--draft", "--title", f"PHP 安全自查台 {tag}",
                "--notes-file", str(notes), *(str(path) for path in attachments))
    # Never overwrite an already published release; it may only be verified again.
    with tempfile.TemporaryDirectory() as temp:
        command("gh", "release", "download", tag, "--repo", repository, "--dir", temp)
        for attachment in attachments:
            downloaded = Path(temp) / attachment.name
            if not downloaded.is_file() or hashlib.sha256(downloaded.read_bytes()).digest() != hashlib.sha256(attachment.read_bytes()).digest():
                raise RuntimeError("Uploaded release checksum mismatch: " + attachment.name)
    if not already_published:
        command("gh", "release", "edit", tag, "--repo", repository, "--draft=false", "--latest")
    release = json.loads(command("gh", "release", "view", tag, "--repo", repository,
                                 "--json", "url,isDraft,assets,tagName,publishedAt").stdout)
    if release["isDraft"] or not (expected | {"SHA256SUMS"}).issubset({a["name"] for a in release["assets"]}):
        raise RuntimeError("Published release verification failed")
    status = {"state": "published", "tag": tag, "repository": repository,
              "source_commit": command("git", "rev-parse", "HEAD").stdout.strip(),
              "release_url": release["url"], "published_at": release["publishedAt"],
              "checksums": hashes, "verified_by_download": True,
              "workflow_run": f"https://github.com/{repository}/actions/runs/{os.environ['GITHUB_RUN_ID']}"}
    (ROOT / "release-status.json").write_text(json.dumps(status, indent=2) + "\n", encoding="utf-8")
    print(release["url"])


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tag", required=True)
    parser.add_argument("--directory", type=Path, required=True)
    args = parser.parse_args()
    main(args.tag, args.directory)
