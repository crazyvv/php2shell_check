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
    browser_report = ROOT / "release-diagnostics/browser-result.json"
    if not browser_report.is_file() or json.loads(browser_report.read_text(encoding="utf-8")).get("state") != "passed":
        raise RuntimeError("A successful real-browser verification report is required before publication")
    repository = os.environ["GITHUB_REPOSITORY"]
    expected = {f"x2shell-check-{tag}-linux-x86_64.tar.gz",
                f"x2shell-check-{tag}-windows-x86_64.zip"}
    archives = sorted(path for path in directory.iterdir() if path.name in expected)
    if {path.name for path in archives} != expected:
        raise RuntimeError("Both tested Windows and Linux archives are required")
    script = directory / "x2shell-check.sh"
    if not script.is_file() or script.read_bytes() != (ROOT / "scripts/x2shell-check.sh").read_bytes():
        raise RuntimeError("The tested Bash attachment must match the tagged source")
    files = archives + [script]
    hashes = {path.name: hashlib.sha256(path.read_bytes()).hexdigest() for path in files}
    sums = directory / "SHA256SUMS"
    sums.write_text("".join(f"{digest}  {name}\n" for name, digest in sorted(hashes.items())), encoding="utf-8")
    attachments = files + [sums]
    notes = directory / "release-notes.md"
    notes.write_text(f"""x2shell-check · 服务暴露面自查台 {tag}

| 附件 | 用途 |
| --- | --- |
| `x2shell-check-{tag}-windows-x86_64.zip` | Windows x86_64，网页服务和 URL 检查 |
| `x2shell-check-{tag}-linux-x86_64.tar.gz` | Linux x86_64，musl 静态程序，含主机采集和 Bash 脚本 |
| `x2shell-check.sh` | 独立 Bash 巡检脚本，可分发到目标主机 |
| `SHA256SUMS` | 三个附件的 SHA-256 校验值 |

解压程序包后阅读 `START-HERE.txt`。下载独立脚本后运行 `bash x2shell-check.sh`，默认检查 Java、NGINX 与 Apache。需要批量留档时运行 `bash x2shell-check.sh --all --json > host-audit.json`。

扫描工作台按 Apache、NGINX、Java/JVM 和 PHP 展示各自证据。知识库按组件和 CVE 索引，`/tools` 提供 Bash 下载、批量用法及退出码说明。Linux 的 Rust `collect` 生成可导入网页的主机报告。

## 变更日志（自 v0.8.6）

- **NGINX 逐 CVE 回补证据**。Rust 和 Bash 区分 Debian 官方 DSA-6642-1 与 Hosted Power 的 Debian 8–13 amd64 热修记录，按完整包版本列出覆盖的 CVE。Rust 可用 `collect --package-audit` 启用采集，网页报告会显示回补来源和待核验状态。
- **NGINX 和 Apache 被动 HTTP/2 风险初筛**。网页扫描结合响应协议、版本线索和代理迹象，提示需要优先复核的条目。
- **Bash 主机取证**。支持独立 JRE 路径和 RPM 归属补证，补充 Apache `mod_http2` 的 RPM 版本来源，并增强 NGINX 多行配置、`include`、Lua 块和编译时配置路径的识别。
- **巡检兼容性**。服务停用时仍清点磁盘安装。NGINX 的版本门禁独立于配置线索和回补记录，Java 保留原有报告格式及进程映射覆盖告警。
- **NGINX 知识库**。补充发行版官方修复、第三方热修、包签名核对和升级后运行映像复核指引。

源码提供可选的体积优化构建，执行 `cargo build --profile release-small --locked -j 4` 即可。下方平台附件使用标准 Release 配置。
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
                "--draft", "--title", f"x2shell-check · 服务暴露面自查台 {tag}",
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
    if release["isDraft"] or not (expected | {"x2shell-check.sh", "SHA256SUMS"}).issubset({a["name"] for a in release["assets"]}):
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
