use anyhow::{Result, ensure};
use clap::{Parser, Subcommand};
use php_selfcheck::{
    collector,
    config::{self, Config},
    evidence_lab, fingerprints, portal, scanner,
};
use std::{collections::BTreeMap, net::IpAddr, path::PathBuf};
#[derive(Parser)]
#[command(version, about = "PHP 安全自查台 · Rust 版")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}
#[derive(Subcommand)]
enum Command {
    /// 导出或校验可配置的网站特征库
    Fingerprints {
        #[command(subcommand)]
        action: FingerprintCommand,
    },
    /// 生成配置和随机个人账号密码，扫描范围默认为空
    Init {
        #[arg(long, default_value = "config.json")]
        config: PathBuf,
        #[arg(long, default_value = "admin")]
        user: String,
        /// 免密码访问，各浏览器会话独立隔离
        #[arg(long)]
        allow_anonymous: bool,
        /// 允许省略网段/端口白名单；非空列表仍生效
        #[arg(long)]
        allow_without_whitelist: bool,
    },
    /// 增加个人账号；配置修改后须重启服务
    AddUser {
        #[arg(long, default_value = "config.json")]
        config: PathBuf,
        #[arg(long)]
        user: String,
    },
    /// 新增独立管理员账号，可查看全站历史；密码随机生成
    AddAdmin {
        #[arg(long, default_value = "config.json")]
        config: PathBuf,
        #[arg(long, default_value = "admin")]
        user: String,
    },
    /// 启动 Web 自查台
    Serve {
        #[arg(long, default_value = "config.json")]
        config: PathBuf,
        #[arg(long, default_value = "127.0.0.1")]
        bind: IpAddr,
        #[arg(long, default_value_t = 8080)]
        port: u16,
        #[arg(long)]
        fingerprints: Option<PathBuf>,
    },
    /// 检测单个 URL，退出码 0=达到上游基线，1=疑似受影响，2=参数/配置错误，3=未知
    Check {
        #[arg(value_parser = check_target)]
        target: String,
        #[arg(long, default_value = "config.json")]
        config: PathBuf,
        #[arg(long)]
        headers_only: bool,
        /// 覆盖 config.json 中的特征库文件（相对当前目录）
        #[arg(long)]
        fingerprints: Option<PathBuf>,
        #[arg(long)]
        json: bool,
    },
    /// 在当前 Linux 主机执行只读采集，JSON 输出至 stdout
    Collect(collector::CollectArgs),
    /// 使用内置合成数据离线验证六项证据规则；不连接目标、不执行 PHP
    OfflinePoc {
        /// 输出完整 JSON，而不是人类可读摘要
        #[arg(long)]
        json: bool,
    },
    /// 离线比较两份主机运行时报告，严格区分 Web 与 CLI
    CompareReports {
        /// 修复前的 php-selfcheck-host/v1 JSON
        #[arg(long)]
        before: PathBuf,
        /// 修复后的 php-selfcheck-host/v1 JSON
        #[arg(long)]
        after: PathBuf,
        /// 输出完整 JSON，而不是人类可读摘要
        #[arg(long)]
        json: bool,
    },
}
#[derive(Subcommand)]
enum FingerprintCommand {
    /// 将内置完整特征库导出为可编辑 JSON，不覆盖已有文件
    Export {
        #[arg(long, default_value = "fingerprints.json")]
        output: PathBuf,
    },
    /// 校验 JSON、规则 ID、正则和资源上限，输出有效库信息
    Validate {
        #[arg(long)]
        file: PathBuf,
    },
}
fn fingerprint_override(cfg: &mut Config, file: Option<PathBuf>) -> Result<()> {
    if let Some(file) = file {
        cfg.fingerprint_file = Some(std::fs::canonicalize(file)?.to_string_lossy().into_owned());
    }
    Ok(())
}
fn check_target(value: &str) -> std::result::Result<String, String> {
    scanner::normalize(value)
        .map(|u| u.to_string())
        .map_err(|e| e.to_string())
}
#[tokio::main]
async fn main() -> Result<()> {
    match Cli::parse().command {
        Command::Fingerprints { action } => match action {
            FingerprintCommand::Export { output } => {
                use std::io::Write;
                let mut file = std::fs::OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .open(&output)?;
                file.write_all(fingerprints::BUILTIN.as_bytes())?;
                println!("内置特征库已导出：{}", output.display());
            }
            FingerprintCommand::Validate { file } => {
                let library = fingerprints::Library::load(&file)?;
                println!("{}", serde_json::to_string_pretty(library.metadata())?);
            }
        },
        Command::Init {
            config: path,
            user,
            allow_anonymous,
            allow_without_whitelist,
        } => {
            ensure!(
                config::valid_user(&user),
                "账号仅允许 1–64 位字母、数字、下划线、点和横线"
            );
            let password = config::token(20);
            let cfg = Config {
                collection_defaults: Default::default(),
                public_origin: "http://127.0.0.1:8080".into(),
                admins: BTreeMap::from([(user.clone(), config::password_hash(&password, None)?)]),
                allow_anonymous,
                probe_multipart: false,
                probe_upload_progress: false,
                headers_only: false,
                fingerprint_file: None,
                fingerprint_library: None,
                allow_without_whitelist,
                allowed_networks: vec![],
                allowed_domains: vec![],
                allowed_ports: if allow_without_whitelist {
                    vec![]
                } else {
                    vec![80, 443, 8080, 8443]
                },
                database: "data/selfcheck.sqlite3".into(),
                users: if allow_anonymous {
                    BTreeMap::new()
                } else {
                    BTreeMap::from([(user.clone(), config::password_hash(&password, None)?)])
                },
            };
            config::write_config(&path, &cfg, true)?;
            if allow_anonymous {
                println!(
                    "配置已生成。免密码扫描已启用，各浏览器会话独立隔离。\n管理员账号: {user}\n管理员随机密码: {password}\n管理员入口: /admin"
                );
            } else {
                println!(
                    "配置已生成。首次账号: {user}\n随机密码: {password}\n请保存密码。管理员入口: /admin。"
                );
            }
            if allow_without_whitelist {
                println!("允许不配置白名单；已填写的限制仍生效。");
            } else {
                println!("扫描范围为空，需配置 allowed_networks 后检测。");
            }
        }
        Command::AddUser { config: path, user } => {
            ensure!(config::valid_user(&user), "账号格式错误");
            let mut cfg = config::load(&path)?;
            ensure!(!cfg.users.contains_key(&user), "账号已存在，不覆盖");
            let password = config::token(20);
            cfg.users
                .insert(user.clone(), config::password_hash(&password, None)?);
            config::write_config(&path, &cfg, false)?;
            println!("账号: {user}\n随机密码: {password}\n重启服务后生效。");
        }
        Command::AddAdmin { config: path, user } => {
            ensure!(config::valid_user(&user), "管理员账号格式错误");
            let mut cfg = config::load(&path)?;
            ensure!(!cfg.admins.contains_key(&user), "管理员账号已存在，不覆盖");
            let password = config::token(20);
            cfg.admins
                .insert(user.clone(), config::password_hash(&password, None)?);
            config::write_config(&path, &cfg, false)?;
            println!("管理员账号: {user}\n随机密码: {password}\n重启后访问 /admin 登录。");
        }
        Command::Serve {
            config: path,
            bind,
            port,
            fingerprints,
        } => {
            let path = std::fs::canonicalize(path)?;
            let mut cfg = config::load(&path)?;
            fingerprint_override(&mut cfg, fingerprints)?;
            cfg.validate(&path, bind)?;
            portal::serve(cfg, std::net::SocketAddr::new(bind, port)).await?;
        }
        Command::Check {
            target,
            config: path,
            headers_only,
            json: as_json,
            fingerprints,
        } => {
            let loaded: Result<config::Config> = (|| {
                let mut cfg = config::load(&path)?;
                fingerprint_override(&mut cfg, fingerprints.clone())?;
                cfg.validate(&path, "127.0.0.1".parse()?)?;
                if let Some(file) = fingerprints {
                    cfg.fingerprint_library = Some(fingerprints::Library::load(&file)?);
                }
                cfg.headers_only |= headers_only;
                Ok(cfg)
            })();
            let cfg = match loaded {
                Ok(c) => c,
                Err(e) => {
                    eprintln!("配置错误: {e}");
                    std::process::exit(2);
                }
            };
            let mut result = scanner::scan(&target, &cfg).await;
            let code = scanner::check_exit_code(&result);
            result["exit_code"] = serde_json::json!(code);
            result["patch_status"] = serde_json::json!(match code {
                0 => "ok",
                1 => "potentially_vulnerable",
                _ => "unknown",
            });
            if as_json {
                println!("{}", serde_json::to_string_pretty(&result)?);
            } else {
                println!(
                    "{}: {}\n{}",
                    result["verdict"].as_str().unwrap_or("无法判断"),
                    target,
                    result["reason"].as_str().unwrap_or("")
                );
            }
            std::process::exit(code.into());
        }
        Command::Collect(args) => {
            let options = args.resolve()?;
            ensure!(cfg!(target_os = "linux"), "主机采集目前仅支持 Linux");
            println!(
                "{}",
                serde_json::to_string_pretty(&collector::collect_with_options(&options).await)?
            );
        }
        Command::OfflinePoc { json: as_json } => {
            let result = evidence_lab::offline_poc()?;
            if as_json {
                println!("{}", serde_json::to_string_pretty(&result)?);
            } else {
                println!("{}", evidence_lab::human_poc(&result));
            }
            ensure!(
                result["summary"]["all_passed"] == true,
                "离线证据规则验证失败"
            );
        }
        Command::CompareReports {
            before,
            after,
            json: as_json,
        } => {
            let before = evidence_lab::read_report(&before)?;
            let after = evidence_lab::read_report(&after)?;
            let result = evidence_lab::compare_reports(&before, &after)?;
            if as_json {
                println!("{}", serde_json::to_string_pretty(&result)?);
            } else {
                println!("{}", evidence_lab::human_comparison(&result));
            }
        }
    }
    Ok(())
}
