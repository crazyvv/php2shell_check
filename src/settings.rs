//! Administrator-managed scan policy. Secrets and deployment paths remain server-side.
use crate::{
    config::Config,
    portal::{self, State, error, json_response},
};
use anyhow::Result;
use axum::{
    body::Body,
    http::{Method, Request},
    response::Response,
};
use rusqlite::{Connection, OptionalExtension, params};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::sync::Arc;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    pub allow_anonymous: bool,
    pub allow_without_whitelist: bool,
    pub allowed_networks: Vec<String>,
    pub allowed_domains: Vec<String>,
    pub allowed_ports: Vec<u16>,
    /// Permission for a user-selected minimal multipart control, not an automatic POST.
    pub probe_multipart: bool,
    #[serde(default)]
    pub probe_upload_progress: bool,
    pub headers_only: bool,
    #[serde(default)]
    pub collection_defaults: CollectionDefaults,
}
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct CollectionDefaults {
    pub php_command: bool,
    pub package_audit: bool,
    pub middleware: bool,
    pub php_modules: bool,
    pub ports: bool,
    pub web_probe: bool,
}
impl CollectionDefaults {
    pub fn validate(&self) -> Result<()> {
        anyhow::ensure!(
            !(self.php_modules || self.ports || self.web_probe) || self.middleware,
            "模块、端口和 Web 采集需要 middleware"
        );
        anyhow::ensure!(!self.web_probe || self.ports, "Web 采集需要 ports");
        Ok(())
    }
}
impl Policy {
    fn from_config(c: &Config) -> Self {
        Self {
            allow_anonymous: c.allow_anonymous,
            allow_without_whitelist: c.allow_without_whitelist,
            allowed_networks: c.allowed_networks.clone(),
            allowed_domains: c.allowed_domains.clone(),
            allowed_ports: c.allowed_ports.clone(),
            probe_multipart: c.probe_multipart,
            probe_upload_progress: c.probe_upload_progress,
            headers_only: c.headers_only,
            collection_defaults: c.collection_defaults.clone(),
        }
    }
    pub fn apply(&self, c: &mut Config) {
        c.collection_defaults = self.collection_defaults.clone();
        c.allow_anonymous = self.allow_anonymous;
        c.allow_without_whitelist = self.allow_without_whitelist;
        c.allowed_networks = self.allowed_networks.clone();
        c.allowed_domains = self.allowed_domains.clone();
        c.allowed_ports = self.allowed_ports.clone();
        c.probe_multipart = self.probe_multipart;
        c.probe_upload_progress = self.probe_upload_progress;
        c.headers_only = self.headers_only;
    }
    fn validate(&mut self, base: &Config) -> Result<()> {
        anyhow::ensure!(
            self.allowed_networks.len() <= 256
                && self.allowed_domains.len() <= 256
                && self.allowed_ports.len() <= 256,
            "白名单每项最多 256 条"
        );
        anyhow::ensure!(
            self.allowed_networks
                .iter()
                .chain(&self.allowed_domains)
                .all(|s| s.len() <= 253),
            "白名单条目过长"
        );
        self.collection_defaults.validate()?;
        let mut candidate = base.clone();
        self.apply(&mut candidate);
        candidate.validate_online_fields()?;
        self.allowed_domains = candidate.allowed_domains;
        Ok(())
    }
}
pub struct Snapshot {
    pub revision: i64,
    pub policy: Policy,
    pub origin: &'static str,
}
fn query(db: &Connection) -> Result<Option<(i64, String)>> {
    Ok(db
        .query_row(
            "SELECT revision,document FROM runtime_settings WHERE id=1",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()?)
}
impl Snapshot {
    pub fn load(db: &Connection, base: &Config) -> Result<Self> {
        let (revision, mut policy, origin) = if let Some((r, s)) = query(db)? {
            (r, serde_json::from_str::<Policy>(&s)?, "database")
        } else {
            (0, Policy::from_config(base), "file")
        };
        policy.validate(base)?;
        Ok(Self {
            revision,
            policy,
            origin,
        })
    }
    pub fn view(&self) -> Value {
        json!({"revision":self.revision,"origin":self.origin,"document":serde_json::to_string_pretty(&self.policy).unwrap(),"effective":self.policy})
    }
}
pub async fn dispatch(state: Arc<State>, req: Request<Body>, actor: &str) -> Result<Response> {
    let path = req.uri().path().to_owned();
    if req.method() == Method::GET && path == "/api/admin/settings" {
        let mut view = state.settings.read().unwrap().view();
        view["deployment"] = json!({"public_origin":state.config.public_origin,"database":state.config.database,"users":state.config.users.keys().collect::<Vec<_>>(),"admins":state.config.admins.keys().collect::<Vec<_>>(),"note":"部署地址、数据库路径和账号凭据请在服务器配置；不返回密码散列。特征库在专用面板维护。"});
        state.audit(actor, "settings_read", json!({"revision":view["revision"]}))?;
        return Ok(json_response(200, view));
    }
    if req.method() != Method::POST {
        return Ok(error(405, "仅支持读取、校验和保存配置"));
    }
    if !matches!(
        path.as_str(),
        "/api/admin/settings/validate" | "/api/admin/settings/save"
    ) {
        return Ok(error(404, "接口不存在"));
    }
    let body = match portal::read_body(&state.config, req).await {
        Ok(v) => v,
        Err((s, m)) => return Ok(error(s, m)),
    };
    let Some(doc) = body["document"].as_str().filter(|s| s.len() <= 65536) else {
        return Ok(error(400, "配置须为不超过 64 KiB 的 JSON 文本"));
    };
    let mut policy: Policy = match serde_json::from_str(doc) {
        Ok(v) => v,
        Err(e) => return Ok(error(400, &format!("配置格式错误：{e}"))),
    };
    if let Err(e) = policy.validate(&state.config) {
        return Ok(error(400, &format!("配置校验失败：{e}")));
    }
    if path.ends_with("/validate") {
        return Ok(json_response(200, json!({"valid":true,"effective":policy})));
    }
    let Some(expected) = body["revision"].as_i64().filter(|v| *v >= 0) else {
        return Ok(error(400, "保存需要 revision"));
    };
    let mut active = state.settings.write().unwrap();
    if active.revision != expected {
        return Ok(error(
            409,
            "其他管理员已更新配置，草稿保留，请重新加载后合并",
        ));
    }
    let mut db = state.db.lock().unwrap();
    let tx = db.transaction()?;
    if query(&tx)?.map_or(0, |v| v.0) != expected {
        return Ok(error(409, "数据库配置已更新，请重新加载"));
    }
    let revision = expected
        .checked_add(1)
        .ok_or_else(|| anyhow::anyhow!("配置版本溢出"))?;
    tx.execute("INSERT INTO runtime_settings(id,revision,document) VALUES(1,?,?) ON CONFLICT(id) DO UPDATE SET revision=excluded.revision,document=excluded.document",params![revision,serde_json::to_string(&policy)?])?;
    tx.execute(
        "INSERT INTO audit(created,owner,action,detail) VALUES(?,?,?,?)",
        params![
            portal::now(),
            actor,
            "settings_save",
            json!({"revision":revision,"previous_revision":expected,"settings":policy}).to_string()
        ],
    )?;
    tx.commit()?;
    *active = Snapshot {
        revision,
        policy,
        origin: "database",
    };
    Ok(json_response(200, active.view()))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn online_validation_never_opens_deployment_database_or_rule_files() {
        let dir = tempfile::tempdir().unwrap();
        let database = dir.path().join("invalid.sqlite3");
        std::fs::write(&database, b"not a database").unwrap();
        let base:Config=serde_json::from_value(json!({"public_origin":"https://example.com","database":database,"fingerprint_file":dir.path().join("missing.json"),"allow_anonymous":true,"allow_without_whitelist":true})).unwrap();
        let mut policy = Policy::from_config(&base);
        let mut legacy = serde_json::to_value(&policy).unwrap();
        legacy
            .as_object_mut()
            .unwrap()
            .remove("probe_upload_progress");
        let migrated: Policy = serde_json::from_value(legacy).unwrap();
        assert!(!migrated.probe_upload_progress);
        policy.collection_defaults.php_command = true;
        policy.allowed_domains = vec!["EXAMPLE.COM".into()];
        policy.validate(&base).unwrap();
        assert_eq!(policy.allowed_domains, ["example.com"]);
        policy.allowed_networks = vec!["10.0.0.1/8".into()];
        assert!(policy.validate(&base).is_err());
        let partial: CollectionDefaults =
            serde_json::from_value(json!({"php_command":true})).unwrap();
        assert!(partial.php_command);
        assert!(!partial.web_probe);
    }
}
