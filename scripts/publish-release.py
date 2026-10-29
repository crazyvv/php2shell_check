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

支持可配置的被动网站特征库：51 条内置规则，支持 CMS/框架、静态生成器、托管平台、中间件、CDN/WAF 与挑战页识别；JSON 扩展/覆盖/禁用、命中证据和规则版本追踪。规则不增加请求，CMS 版本不作为 PHP 版本，外部资源及托管平台线索不作为当前站点已修复证明。本版增加管理员后台逐条编辑、新增、禁用/启用、删除、完整 JSON 校验及保存，持久化到 SQLite 并立即用于新提交的扫描；包含修订冲突保护和审计。关键证据采用等宽粗体与风险色强调，单列下一步。也可使用 `fingerprints export` / `fingerprints validate`，参见 README 和 fingerprints.example.json。

本版新增管理员在线配置面板（JSON、访问与扫描开关、白名单、采集默认选项、SQLite 持久化、校验、冲突保护、审计）。Web multipart 改为管理员允许后，由开发者为本次扫描选择启用。已有任务使用提交时配置快照。另新增已有响应的上传表单入口/文件字段提取、内存耗尽/会话解码/文件包含错误分类，以及可选 PHP/Web 报告的会话序列化配置采集。线索不提升漏洞结论，不新增探测请求、不上传文件或进行故障注入。详见 README 能力对照。

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
