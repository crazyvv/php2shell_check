//! Administrator rule snapshots: durable updates and optimistic concurrency, no historical rewrite.
use crate::{
    config::Config,
    fingerprints::{self, Library},
    portal::{self, State, error, json_response},
};
use anyhow::Result;
use axum::{
    body::Body,
    http::{Method, Request},
    response::Response,
};
use rusqlite::{Connection, OptionalExtension, params};
use serde_json::{Value, json};
use std::{path::Path, sync::Arc};

pub struct Snapshot {
    pub library: Arc<Library>,
    pub revision: i64,
    pub origin: &'static str,
}
pub fn saved_document(path: &Path) -> Result<Option<(i64, String)>> {
    if !path.is_file() {
        return Ok(None);
    }
    let db = Connection::open_with_flags(path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)?;
    let exists: i64 = db.query_row(
        "SELECT count(*) FROM sqlite_master WHERE type='table' AND name='fingerprint_rules'",
        [],
        |r| r.get(0),
    )?;
    if exists == 0 {
        return Ok(None);
    }
    query(&db)
}
fn query(db: &Connection) -> Result<Option<(i64, String)>> {
    Ok(db
        .query_row(
            "SELECT revision,document FROM fingerprint_rules WHERE id=1",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()?)
}
impl Snapshot {
    pub fn load(db: &Connection, config: &Config) -> Result<Self> {
        if let Some((revision, document)) = query(db)? {
            return Ok(Self {
                library: Library::from_json(&document)?,
                revision,
                origin: "database",
            });
        }
        Ok(Self {
            library: config
                .fingerprint_library
                .clone()
                .unwrap_or_else(fingerprints::builtin),
            revision: 0,
            origin: if config.fingerprint_file.is_some() {
                "file"
            } else {
                "builtin"
            },
        })
    }
    fn view(&self) -> Value {
        json!({"revision":self.revision,"origin":self.origin,"document":self.library.document(),"metadata":self.library.metadata(),"builtin_document":fingerprints::BUILTIN})
    }
}
pub async fn dispatch(state: Arc<State>, req: Request<Body>, actor: &str) -> Result<Response> {
    let path = req.uri().path().to_owned();
    if req.method() == Method::GET && path == "/api/admin/fingerprints" {
        let view = state.rulebook.read().unwrap().view();
        state.audit(
            actor,
            "fingerprints_read",
            json!({"revision":view["revision"]}),
        )?;
        return Ok(json_response(200, view));
    }
    if req.method() != Method::POST {
        return Ok(error(405, "仅支持读取、校验或保存特征库"));
    }
    if !matches!(
        path.as_str(),
        "/api/admin/fingerprints/validate" | "/api/admin/fingerprints/save"
    ) {
        return Ok(error(404, "接口不存在"));
    }
    let body = match portal::read_body_limit(&state.config, req, 2_097_152).await {
        Ok(v) => v,
        Err((code, message)) => return Ok(error(code, message)),
    };
    let Some(document) = body["document"].as_str().filter(|s| s.len() <= 524_288) else {
        return Ok(error(400, "document 必须为不超过 512 KiB 的 JSON 文本"));
    };
    let document = document.to_owned();
    let compiled = tokio::task::spawn_blocking(move || Library::from_json(&document)).await?;
    let library = match compiled {
        Ok(lib) => lib,
        Err(e) => return Ok(error(400, &format!("特征库校验失败：{e:#}"))),
    };
    if path.ends_with("/validate") {
        return Ok(json_response(
            200,
            json!({"valid":true,"metadata":library.metadata()}),
        ));
    }
    let Some(expected) = body["revision"].as_i64().filter(|n| *n >= 0) else {
        return Ok(error(400, "保存须提供读取时的 revision"));
    };
    // Lock order is rules -> database. Readers clone the Arc before taking database locks.
    let mut active = state.rulebook.write().unwrap();
    if active.revision != expected {
        return Ok(error(
            409,
            "其他管理员已更新规则，请备份草稿并重新加载后合并",
        ));
    }
    let mut db = state.db.lock().unwrap();
    let tx = db.transaction()?;
    let actual = query(&tx)?.map_or(0, |v| v.0);
    if actual != expected {
        return Ok(error(409, "规则版本已变化，请重新加载后合并"));
    }
    let revision = expected
        .checked_add(1)
        .ok_or_else(|| anyhow::anyhow!("规则版本超出范围"))?;
    tx.execute("INSERT INTO fingerprint_rules(id,revision,document) VALUES(1,?,?) ON CONFLICT(id) DO UPDATE SET revision=excluded.revision,document=excluded.document",params![revision,library.document()])?;
    tx.execute(
        "INSERT INTO audit(created,owner,action,detail) VALUES(?,?,?,?)",
        params![
            portal::now(),
            actor,
            "fingerprints_save",
            json!({"revision":revision,"previous_revision":expected,"metadata":library.metadata()})
                .to_string()
        ],
    )?;
    tx.commit()?;
    *active = Snapshot {
        library,
        revision,
        origin: "database",
    };
    Ok(json_response(200, active.view()))
}
