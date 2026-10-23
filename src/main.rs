use anyhow::{Result, ensure};
use clap::{Parser, Subcommand};
use php_selfcheck::{
    collector,
    config::{self, Config},
    portal,
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
    /// 生成配置和随机个人账号密码，扫描范围默认为空
    Init {
        #[arg(long, default_value = "config.json")]
        config: PathBuf,
        #[arg(long, default_value = "admin")]
        user: String,
    },
    /// 增加个人账号；配置修改后须重启服务
    AddUser {
        #[arg(long, default_value = "config.json")]
        config: PathBuf,
        #[arg(long)]
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
    },
    /// 在当前 Linux 主机执行只读采集，JSON 输出至 stdout
    Collect,
}
#[tokio::main]
async fn main() -> Result<()> {
    match Cli::parse().command {
        Command::Init { config: path, user } => {
            ensure!(
                config::valid_user(&user),
                "账号仅允许 1–64 位字母、数字、下划线、点和横线"
            );
            let password = config::token(20);
            let cfg = Config {
                public_origin: "http://127.0.0.1:8080".into(),
                allowed_networks: vec![],
                allowed_domains: vec![],
                allowed_ports: vec![80, 443, 8080, 8443],
                database: "data/selfcheck.sqlite3".into(),
                users: BTreeMap::from([(user.clone(), config::password_hash(&password, None)?)]),
            };
            config::write_config(&path, &cfg, true)?;
            println!(
                "配置已生成。首次账号: {user}\n随机密码: {password}\n请保存密码；扫描范围为空，需配置 allowed_networks 后检测。"
            );
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
        Command::Serve {
            config: path,
            bind,
            port,
        } => {
            let path = std::fs::canonicalize(path)?;
            let mut cfg = config::load(&path)?;
            cfg.validate(&path, bind)?;
            portal::serve(cfg, std::net::SocketAddr::new(bind, port)).await?;
        }
        Command::Collect => {
            ensure!(cfg!(target_os = "linux"), "主机采集目前仅支持 Linux");
            println!(
                "{}",
                serde_json::to_string_pretty(&collector::collect().await)?
            );
        }
    }
    Ok(())
}
