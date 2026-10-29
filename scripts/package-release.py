#!/usr/bin/env python3
"""Package a tested native executable and its public documentation; never include state."""
import argparse
import hashlib
import re
import shutil
import tarfile
import tempfile
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TARGETS = {
    "x86_64-unknown-linux-musl": ("linux-x86_64", "php-selfcheck", ".tar.gz"),
    "x86_64-pc-windows-msvc": ("windows-x86_64", "php-selfcheck.exe", ".zip"),
}
FILES = ["README.md", "THIRD_PARTY_NOTICES.md", "config.open.example.json",
         "collector.options.example.json", "fingerprints.example.json", "nginx.conf.example"]


def version():
    return re.search(r'^version\s*=\s*"([^"]+)"', (ROOT / "Cargo.toml").read_text(), re.M)[1]


def validate_tag(tag):
    if tag != "v" + version() or not re.fullmatch(r"v[0-9]+\.[0-9]+\.[0-9]+", tag):
        raise ValueError("Release tag must match Cargo.toml package version: v" + version())


def package(target, tag, output):
    validate_tag(tag)
    platform, executable, extension = TARGETS[target]
    binary = ROOT / "target" / target / "release" / executable
    if not binary.is_file():
        raise FileNotFoundError(binary)
    name = f"php-selfcheck-{tag}-{platform}"
    output.mkdir(parents=True, exist_ok=True)
    archive = output / (name + extension)
    with tempfile.TemporaryDirectory() as temp:
        directory = Path(temp) / name
        directory.mkdir()
        shutil.copy2(binary, directory / executable)
        for filename in FILES:
            shutil.copy2(ROOT / filename, directory / filename)
        for subdir in ["licenses", "rules", "tools", "docs"]:
            shutil.copytree(ROOT / subdir, directory / subdir)
        prefix = ".\\php-selfcheck.exe" if "windows" in target else "./php-selfcheck"
        (directory / "START-HERE.txt").write_text(
            f"PHP 安全自查台 {tag} / {platform}\n\n"
            f"在解压目录打开终端运行：\n{prefix} init --allow-anonymous --allow-without-whitelist\n"
            f"{prefix} serve\n\n访问 http://127.0.0.1:8080/；管理员入口 /admin。\n"
            "保存 init 输出的管理员随机密码。init 不覆盖已有 config.json。\n"
            "上面的初始化命令允许免密码扫描、不设置白名单；填写非空白名单仍会限制目标。\n"
            "团队部署请按 README 配置 HTTPS 反向代理和准确的 public_origin。\n\n"
            "Windows 包支持 Web 服务及 URL 检查；主机 collect 采集目前仅支持 Linux。\n"
            "Linux 包为 x86_64 musl 静态程序；HTTPS 仍需要系统 CA 证书。\n"
            "Windows 包为 x86_64 MSVC 程序；若系统提示缺少运行库，请安装微软官方\n"
            "Microsoft Visual C++ 2015–2022 Redistributable (x64)。\n"
            "没有默认管理员密码；发布包不包含真实配置、数据库或扫描结果。\n"
            "请用同一 Release 的 SHA256SUMS 校验下载文件。详见 README.md。\n",
            encoding="utf-8",
        )
        if extension == ".zip":
            with zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED) as bundle:
                for path in sorted(directory.rglob("*")):
                    if path.is_file():
                        bundle.write(path, path.relative_to(directory.parent))
        else:
            with tarfile.open(archive, "w:gz") as bundle:
                bundle.add(directory, arcname=name)
    digest = hashlib.sha256(archive.read_bytes()).hexdigest()
    print(f"{digest}  {archive.name}")
    return archive


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", choices=TARGETS)
    parser.add_argument("--tag", required=True)
    parser.add_argument("--output", type=Path, default=ROOT / "dist")
    parser.add_argument("--validate-only", action="store_true")
    args = parser.parse_args()
    validate_tag(args.tag)
    if not args.validate_only:
        if not args.target:
            parser.error("--target is required when packaging")
        package(args.target, args.tag, args.output)
