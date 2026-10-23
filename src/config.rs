use anyhow::{Context, Result, bail};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    fs::{self, OpenOptions},
    io::Write,
    path::Path,
};
use subtle::ConstantTimeEq;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Config {
    pub public_origin: String,
    pub allowed_networks: Vec<String>,
    #[serde(default)]
    pub allowed_domains: Vec<String>,
    pub allowed_ports: Vec<u16>,
    pub database: String,
    pub users: BTreeMap<String, String>,
}
pub fn token(bytes: usize) -> String {
    let mut buf = vec![0; bytes];
    rand::rngs::OsRng.fill_bytes(&mut buf);
    hex::encode(buf)
}
pub fn password_hash(password: &str, salt: Option<&str>) -> Result<String> {
    let salt = salt.map(str::to_owned).unwrap_or_else(|| token(16));
    let decoded = hex::decode(&salt)?;
    anyhow::ensure!(decoded.len() == 16, "密码盐格式错误");
    let mut hash = [0; 32];
    pbkdf2::pbkdf2_hmac::<sha2::Sha256>(password.as_bytes(), &decoded, 260_000, &mut hash);
    Ok(format!("{salt}:{}", hex::encode(hash)))
}
pub fn verify(password: &str, stored: &str) -> bool {
    let Some((salt, _)) = stored.split_once(':') else {
        return false;
    };
    password_hash(password, Some(salt))
        .map(|h| bool::from(h.as_bytes().ct_eq(stored.as_bytes())))
        .unwrap_or(false)
}
pub fn valid_user(user: &str) -> bool {
    !user.is_empty()
        && user.len() <= 64
        && user
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || b"_.-".contains(&c))
}
pub fn write_config(path: &Path, config: &Config, create: bool) -> Result<()> {
    // Exclusive creation prevents init from overwriting existing configuration.
    let mut options = OpenOptions::new();
    options.write(true);
    if create {
        options.create_new(true);
    } else {
        options.truncate(true);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(fs::Permissions::from_mode(0o600))?;
    }
    file.write_all(serde_json::to_string_pretty(config)?.as_bytes())?;
    file.sync_all()?;
    Ok(())
}
pub fn load(path: &Path) -> Result<Config> {
    Ok(serde_json::from_slice(
        &fs::read(path).context("请先执行 init")?,
    )?)
}
impl Config {
    pub fn validate(&mut self, path: &Path, bind: std::net::IpAddr) -> Result<()> {
        let origin = url::Url::parse(&self.public_origin)?;
        if !matches!(origin.scheme(), "http" | "https")
            || origin.host_str().is_none()
            || !origin.username().is_empty()
            || origin.password().is_some()
            || origin.query().is_some()
            || origin.fragment().is_some()
            || origin.path() != "/"
            || self.public_origin.ends_with('/')
        {
            bail!("public_origin 只能是 scheme://host[:port]，不能带路径或尾斜线");
        }
        if !bind.is_loopback() && origin.scheme() != "https" {
            bail!("非回环监听须配置 HTTPS public_origin，并通过 HTTPS 反向代理访问");
        }
        for n in &self.allowed_networks {
            let net: ipnet::IpNet = n.parse()?;
            anyhow::ensure!(net.addr() == net.network(), "CIDR 必须使用网络地址: {n}");
        }
        anyhow::ensure!(
            !self.users.is_empty() && self.users.keys().all(|u| valid_user(u)),
            "账号配置错误"
        );
        anyhow::ensure!(
            !self.allowed_ports.is_empty() && !self.allowed_ports.contains(&0),
            "端口配置错误"
        );
        for domain in &mut self.allowed_domains {
            let u = url::Url::parse(&format!("https://{domain}"))?;
            anyhow::ensure!(
                u.username().is_empty()
                    && u.password().is_none()
                    && u.port().is_none()
                    && u.path() == "/"
                    && u.query().is_none()
                    && u.fragment().is_none(),
                "域名配置错误"
            );
            *domain = u
                .host_str()
                .context("域名为空")?
                .trim_end_matches('.')
                .to_lowercase();
        }
        let db = Path::new(&self.database);
        if !db.is_absolute() {
            self.database = path
                .parent()
                .unwrap_or(Path::new("."))
                .join(db)
                .to_string_lossy()
                .into();
        }
        Ok(())
    }
}
