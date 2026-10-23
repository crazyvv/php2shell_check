use crate::{
    config::{Config, token, verify},
    scanner,
};
use anyhow::{Context, Result};
use axum::{
    Router,
    body::{Body, to_bytes},
    extract::ConnectInfo,
    http::{HeaderMap, Request, StatusCode, header},
    response::{IntoResponse, Response},
};
use base64::{Engine, engine::general_purpose::STANDARD};
use rusqlite::{Connection, params};
use serde_json::{Value, json};
use std::{
    collections::HashMap,
    net::SocketAddr,
    path::Path,
    sync::{Arc, Mutex},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use tokio::sync::Semaphore;

pub fn now() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs_f64()
}
pub struct State {
    pub config: Config,
    pub(crate) db: Mutex<Connection>,
    rates: Mutex<HashMap<String, Vec<Instant>>>,
    pub(crate) failures: Mutex<HashMap<String, Vec<Instant>>>,
    workers: Arc<Semaphore>,
    connections: Arc<Semaphore>,
}
impl State {
    pub fn new(config: Config) -> Result<Arc<Self>> {
        let path = Path::new(&config.database);
        if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
            let mut builder = std::fs::DirBuilder::new();
            builder.recursive(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::DirBuilderExt;
                builder.mode(0o700);
            }
            builder.create(parent)?;
        }
        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create(true).truncate(false);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let file = opts.open(path)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
        }
        let db = Connection::open(path)?;
        db.busy_timeout(Duration::from_secs(10))?;
        db.execute_batch("PRAGMA journal_mode=WAL;
            CREATE TABLE IF NOT EXISTS jobs(id TEXT PRIMARY KEY,owner TEXT,created REAL,state TEXT,results TEXT);
            CREATE TABLE IF NOT EXISTS reports(id TEXT PRIMARY KEY,owner TEXT,created REAL,target TEXT,payload TEXT);
            CREATE TABLE IF NOT EXISTS audit(id INTEGER PRIMARY KEY,created REAL,owner TEXT,action TEXT,detail TEXT);
            CREATE TABLE IF NOT EXISTS sessions(token_hash TEXT PRIMARY KEY,owner TEXT,kind TEXT,expires REAL,credential TEXT);
            CREATE INDEX IF NOT EXISTS sessions_expiry ON sessions(expires);
            CREATE INDEX IF NOT EXISTS jobs_owner_created ON jobs(owner,created);
            CREATE INDEX IF NOT EXISTS reports_owner_target ON reports(owner,target);
            UPDATE jobs SET state='interrupted' WHERE state IN ('queued','running');")?;
        Ok(Arc::new(Self {
            config,
            db: Mutex::new(db),
            rates: Mutex::new(HashMap::new()),
            failures: Mutex::new(HashMap::new()),
            workers: Arc::new(Semaphore::new(4)),
            connections: Arc::new(Semaphore::new(32)),
        }))
    }
    pub(crate) fn audit(&self, user: &str, action: &str, detail: Value) -> Result<()> {
        self.db.lock().unwrap().execute(
            "INSERT INTO audit(created,owner,action,detail) VALUES(?,?,?,?)",
            params![now(), user, action, detail.to_string()],
        )?;
        Ok(())
    }
}
pub(crate) fn response(status: u16, body: impl Into<Body>, mime: &str) -> Response {
    let mut r = (StatusCode::from_u16(status).unwrap(), body.into()).into_response();
    let h = r.headers_mut();
    h.insert(header::CONTENT_TYPE, mime.parse().unwrap());
    h.insert(header::CACHE_CONTROL, "no-store".parse().unwrap());
    h.insert("x-content-type-options", "nosniff".parse().unwrap());
    h.insert("referrer-policy", "no-referrer".parse().unwrap());
    h.insert("content-security-policy","default-src 'self'; script-src 'self'; style-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'".parse().unwrap());
    r
}
pub(crate) fn json_response(status: u16, v: Value) -> Response {
    response(status, v.to_string(), "application/json; charset=utf-8")
}
pub(crate) fn error(status: u16, msg: &str) -> Response {
    json_response(status, json!({"error":msg}))
}
pub(crate) fn text<'a>(headers: &'a HeaderMap, name: &str) -> &'a str {
    headers
        .get(name)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
}
pub(crate) fn window<'a>(
    map: &'a mut HashMap<String, Vec<Instant>>,
    key: &str,
) -> &'a mut Vec<Instant> {
    map.retain(|_, hits| {
        hits.retain(|x| x.elapsed() < Duration::from_secs(60));
        !hits.is_empty()
    });
    map.entry(key.into()).or_default()
}
pub(crate) fn job(row: &rusqlite::Row<'_>) -> rusqlite::Result<Value> {
    let results: String = row.get(4)?;
    Ok(
        json!({"id":row.get::<_,String>(0)?,"owner":row.get::<_,String>(1)?,"created":row.get::<_,f64>(2)?,"state":row.get::<_,String>(3)?,"results":serde_json::from_str::<Value>(&results).unwrap_or(json!([]))}),
    )
}
pub fn csv_safe(s: &str) -> String {
    if s.starts_with(['\t', '\r']) || s.trim_start().starts_with(['=', '+', '-', '@']) {
        format!("'{s}")
    } else {
        s.into()
    }
}
pub(crate) fn enrich(db: &Connection, user: &str, record: &mut Value) -> Result<()> {
    if let Some(results) = record["results"].as_array_mut() {
        for result in results {
            let target = result["target"].as_str().unwrap_or("");
            let mut query=db.prepare("SELECT id,created,payload FROM reports WHERE owner=? AND target=? ORDER BY created DESC LIMIT 5")?;
            let evidence=query.query_map(params![user,target],|row|{
                let payload:String=row.get(2)?;
                let payload:Value=serde_json::from_str(&payload).unwrap_or(Value::Null);
                Ok(json!({"id":row.get::<_,String>(0)?,"imported_at":row.get::<_,f64>(1)?,"assessment":crate::assessment::host(&payload)}))
            })?.collect::<std::result::Result<Vec<_>,_>>()?;
            result["host_evidence"] = json!(evidence);
        }
    }
    Ok(())
}
pub fn router(state: Arc<State>) -> Router {
    Router::new().fallback(move |req: Request<Body>| {
        let state = state.clone();
        async move {
            let Ok(_slot) = state.connections.clone().try_acquire_owned() else {
                return error(503, "服务繁忙");
            };
            match tokio::time::timeout(Duration::from_secs(15), dispatch(state, req)).await {
                Ok(Ok(r)) => r,
                Ok(Err(_)) => error(500, "服务异常，请联系管理员检查服务状态"),
                Err(_) => error(408, "请求超时"),
            }
        }
    })
}
async fn dispatch(state: Arc<State>, req: Request<Body>) -> Result<Response> {
    let origin = url::Url::parse(&state.config.public_origin)?;
    let expected = &origin[url::Position::BeforeHost..url::Position::AfterPort];
    if !text(req.headers(), "host").eq_ignore_ascii_case(expected) {
        return Ok(error(403, "Host 不在允许范围"));
    }
    if req.method() == axum::http::Method::GET {
        let asset = match req.uri().path() {
            "/shared.js" => Some((
                include_str!("../assets/shared.js"),
                "text/javascript; charset=utf-8",
            )),
            "/ui.js" => Some((
                include_str!("../assets/ui.js"),
                "text/javascript; charset=utf-8",
            )),
            "/style.css" => Some((
                include_str!("../assets/style.css"),
                "text/css; charset=utf-8",
            )),
            _ => None,
        };
        if let Some((body, mime)) = asset {
            return Ok(response(200, body, mime));
        }
    }
    let path = req.uri().path();
    if path == "/admin"
        || path == "/admin/"
        || path == "/admin.js"
        || path == "/admin.css"
        || path == "/admin-shared.js"
    {
        if req.method() != axum::http::Method::GET {
            return Ok(error(405, "仅支持 GET"));
        }
        return Ok(match path {
            "/admin-shared.js" => response(
                200,
                include_str!("../assets/shared.js"),
                "text/javascript; charset=utf-8",
            ),
            "/admin.js" => response(
                200,
                include_str!("../assets/admin.js"),
                "text/javascript; charset=utf-8",
            ),
            "/admin.css" => response(
                200,
                include_str!("../assets/style.css"),
                "text/css; charset=utf-8",
            ),
            _ => response(
                200,
                include_str!("../assets/admin.html"),
                "text/html; charset=utf-8",
            ),
        });
    }
    if path.starts_with("/api/admin/") {
        return crate::admin::dispatch(state, req).await;
    }
    let peer = req
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|p| p.0.ip().to_string())
        .unwrap_or_else(|| "unknown".into());
    if !state.config.allow_anonymous
        && window(&mut state.failures.lock().unwrap(), &peer).len() >= 12
    {
        return Ok(error(429, "认证失败次数过多，请稍后再试"));
    }
    let auth = text(req.headers(), "authorization").to_owned();
    let credentials = auth
        .split_once(' ')
        .filter(|(scheme, t)| scheme.eq_ignore_ascii_case("basic") && t.len() <= 4096)
        .and_then(|(_, t)| STANDARD.decode(t).ok())
        .and_then(|b| String::from_utf8(b).ok())
        .and_then(|s| s.split_once(':').map(|(u, p)| (u.to_owned(), p.to_owned())));
    let mut new_cookie = None;
    let user = if state.config.allow_anonymous {
        let db = state.db.lock().unwrap();
        if let Some(owner) = crate::session::lookup(&db, &state.config, req.headers(), "visitor")? {
            Some(owner)
        } else {
            let (owner, cookie) = crate::session::create(&db, &state.config, "visitor", None)?;
            new_cookie = Some(cookie);
            Some(owner)
        }
    } else if let Some((user, password)) = credentials {
        if let Some(stored) = state.config.users.get(&user).cloned() {
            if tokio::task::spawn_blocking(move || verify(&password, &stored)).await? {
                Some(user)
            } else {
                None
            }
        } else {
            None
        }
    } else {
        None
    };
    let Some(user) = user else {
        if !auth.is_empty() {
            window(&mut state.failures.lock().unwrap(), &peer).push(Instant::now());
            state.audit("unknown", "auth_failed", json!({"peer":peer}))?;
        }
        let mut r = error(401, "请输入管理员分配的个人账号和密码");
        r.headers_mut().insert(
            header::WWW_AUTHENTICATE,
            "Basic realm=\"PHP SelfCheck\", charset=\"UTF-8\"".parse()?,
        );
        return Ok(r);
    };
    let mut response = dispatch_user(state, req, &user).await?;
    if let Some(cookie) = new_cookie {
        response
            .headers_mut()
            .insert(header::SET_COOKIE, cookie.parse()?);
    }
    Ok(response)
}
async fn dispatch_user(state: Arc<State>, req: Request<Body>, user: &str) -> Result<Response> {
    {
        let mut rates = state.rates.lock().unwrap();
        let hits = window(&mut rates, user);
        if hits.len() >= 120 {
            return Ok(error(429, "请求过于频繁"));
        }
        hits.push(Instant::now());
    }
    let path = req.uri().path().to_owned();
    let query = req.uri().query().unwrap_or("").to_owned();
    if req.method() == axum::http::Method::GET {
        return get(&state, user, &path, &query);
    }
    if req.method() != axum::http::Method::POST {
        return Ok(error(405, "仅支持 GET/POST"));
    }
    let body = match read_body(&state.config, req).await {
        Ok(body) => body,
        Err((status, message)) => return Ok(error(status, message)),
    };
    post(state, user, &path, body)
}
pub(crate) async fn read_body(
    config: &Config,
    req: Request<Body>,
) -> std::result::Result<Value, (u16, &'static str)> {
    if text(req.headers(), "origin") != config.public_origin
        || text(req.headers(), "x-requested-with") != "PHP-SelfCheck"
        || !text(req.headers(), "content-type")
            .split(';')
            .next()
            .unwrap_or("")
            .trim()
            .eq_ignore_ascii_case("application/json")
    {
        return Err((403, "请求来源或格式不合法"));
    }
    if req.headers().contains_key("transfer-encoding") {
        return Err((400, "不支持分块请求"));
    }
    let size = text(req.headers(), "content-length")
        .parse::<usize>()
        .unwrap_or(0);
    if !(1..=262144).contains(&size) {
        return Err((400, "请求体应为 1–262144 字节"));
    }
    let bytes = match to_bytes(req.into_body(), 262144).await {
        Ok(b) => b,
        Err(_) => return Err((400, "请求体无效或过大")),
    };
    let body: Value = match serde_json::from_slice(&bytes) {
        Ok(Value::Object(v)) => Value::Object(v),
        _ => return Err((400, "请求体必须是 JSON 对象")),
    };
    Ok(body)
}
fn get(state: &State, user: &str, path: &str, query: &str) -> Result<Response> {
    match path {
        "/" => {
            return Ok(response(
                200,
                include_str!("../assets/index.html"),
                "text/html; charset=utf-8",
            ));
        }
        "/shared.js" => {
            return Ok(response(
                200,
                include_str!("../assets/shared.js"),
                "text/javascript; charset=utf-8",
            ));
        }
        "/ui.js" => {
            return Ok(response(
                200,
                include_str!("../assets/ui.js"),
                "text/javascript; charset=utf-8",
            ));
        }
        "/style.css" => {
            return Ok(response(
                200,
                include_str!("../assets/style.css"),
                "text/css; charset=utf-8",
            ));
        }
        "/api/me" => {
            return Ok(json_response(
                200,
                json!({"headers_only":state.config.headers_only,"user":user,"rule_date":scanner::RULE_DATE,"allowed_ports":state.config.allowed_ports,"scope_configured":state.config.allow_without_whitelist || !state.config.allowed_networks.is_empty(),"allow_anonymous":state.config.allow_anonymous,"allow_without_whitelist":state.config.allow_without_whitelist}),
            ));
        }
        _ => {}
    }
    if path == "/api/jobs" {
        let db = state.db.lock().unwrap();
        let mut q=db.prepare("SELECT id,owner,created,state,results FROM jobs WHERE owner=? ORDER BY created DESC LIMIT 1")?;
        let mut records = q
            .query_map([user], job)?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        for record in &mut records {
            enrich(&db, user, record)?;
        }
        return Ok(json_response(200, json!(records)));
    }
    if path == "/api/reports" {
        let db = state.db.lock().unwrap();
        let mut q=db.prepare("SELECT id,created,target,payload FROM reports WHERE owner=? ORDER BY created DESC LIMIT 40")?;
        let records=q.query_map([user],|r|{let p:String=r.get(3)?;Ok(json!({"id":r.get::<_,String>(0)?,"created":r.get::<_,f64>(1)?,"target":r.get::<_,String>(2)?,"assessment":crate::assessment::host(&serde_json::from_str::<Value>(&p).unwrap_or(Value::Null)),"payload":serde_json::from_str::<Value>(&p).unwrap_or(Value::Null)}))})?.collect::<std::result::Result<Vec<_>,_>>()?;
        return Ok(json_response(200, json!(records)));
    }
    if let Some(id) = path.strip_prefix("/api/jobs/") {
        let record = {
            use rusqlite::OptionalExtension;
            state
                .db
                .lock()
                .unwrap()
                .query_row(
                    "SELECT id,owner,created,state,results FROM jobs WHERE id=? AND owner=?",
                    params![id, user],
                    job,
                )
                .optional()?
        };
        let Some(mut record) = record else {
            return Ok(error(404, "记录不存在"));
        };
        enrich(&state.db.lock().unwrap(), user, &mut record)?;
        return job_response(state, user, record, query);
    }
    Ok(error(404, "不存在"))
}
pub(crate) fn job_response(
    state: &State,
    user: &str,
    record: Value,
    query: &str,
) -> Result<Response> {
    let id = record["id"].as_str().unwrap_or("").to_owned();
    let csv =
        url::form_urlencoded::parse(query.as_bytes()).any(|(k, v)| k == "format" && v == "csv");
    let mut r = if csv {
        let mut writer = csv::Writer::from_writer(vec![]);
        let keys = [
            "target",
            "verdict",
            "reason",
            "versions",
            "http_status",
            "connected_ip",
            "checked_at",
            "assessment",
            "host_evidence",
        ];
        writer.write_record(keys)?;
        for result in record["results"].as_array().context("记录损坏")? {
            writer.write_record(keys.map(|k| {
                let v = &result[k];
                csv_safe(&if v.is_null() {
                    String::new()
                } else if let Some(s) = v.as_str() {
                    s.into()
                } else {
                    v.to_string()
                })
            }))?;
        }
        let mut body = vec![0xef, 0xbb, 0xbf];
        body.extend(writer.into_inner()?);
        response(200, body, "text/csv; charset=utf-8")
    } else {
        json_response(200, record)
    };
    r.headers_mut().insert(
        header::CONTENT_DISPOSITION,
        if csv {
            "attachment; filename=\"php-selfcheck.csv\""
        } else {
            "attachment; filename=\"php-selfcheck.json\""
        }
        .parse()?,
    );
    state.audit(
        user,
        "export",
        json!({"job":id,"format":if csv{"csv"}else{"json"}}),
    )?;
    Ok(r)
}
fn post(state: Arc<State>, user: &str, path: &str, body: Value) -> Result<Response> {
    match path {
        "/api/scan" => {
            let Some(raw) = body["targets"]
                .as_array()
                .filter(|a| (1..=50).contains(&a.len()))
            else {
                return Ok(error(400, "每次提交 1–50 个目标"));
            };
            if body.get("headers_only").is_some_and(|v| !v.is_boolean()) {
                return Ok(error(400, "headers_only 必须为布尔值"));
            }
            let mut scan_config = state.config.clone();
            scan_config.headers_only |= body["headers_only"].as_bool().unwrap_or(false);
            let mut targets = vec![];
            for t in raw {
                let Some(t) = t.as_str() else {
                    return Ok(error(400, "目标必须是字符串"));
                };
                let u = match scanner::normalize(t) {
                    Ok(u) => u.to_string(),
                    Err(e) => return Ok(error(400, &e.to_string())),
                };
                if !targets.contains(&u) {
                    targets.push(u)
                }
            }
            let id = token(16);
            {
                let db = state.db.lock().unwrap();
                let active: i64 = db.query_row(
                    "SELECT count(*) FROM jobs WHERE state IN ('queued','running')",
                    [],
                    |r| r.get(0),
                )?;
                let own: i64 = db.query_row(
                    "SELECT count(*) FROM jobs WHERE owner=? AND state IN ('queued','running')",
                    [user],
                    |r| r.get(0),
                )?;
                if active >= 8 || own >= 2 {
                    return Ok(error(429, "检测任务已达并发限制，请等待现有任务完成"));
                }
                db.execute(
                    "INSERT INTO jobs VALUES(?,?,?,?,?)",
                    params![id, user, now(), "queued", "[]"],
                )?;
            }
            state.audit(
                user,
                "scan_submit",
                json!({"job":id,"targets":targets,"headers_only":scan_config.headers_only}),
            )?;
            let job_id = id.clone();
            tokio::spawn(async move {
                let done: Result<()> = async {
                    let _permit = state.workers.clone().acquire_owned().await?;
                    state
                        .db
                        .lock()
                        .unwrap()
                        .execute("UPDATE jobs SET state='running' WHERE id=?", [&job_id])?;
                    let mut results = vec![];
                    for target in targets {
                        results.push(scanner::scan(&target, &scan_config).await);
                        state.db.lock().unwrap().execute(
                            "UPDATE jobs SET results=? WHERE id=?",
                            params![serde_json::to_string(&results)?, job_id],
                        )?;
                        tokio::time::sleep(Duration::from_millis(500)).await;
                    }
                    Ok(())
                }
                .await;
                let _ = state.db.lock().unwrap().execute(
                    "UPDATE jobs SET state=? WHERE id=?",
                    params![if done.is_ok() { "done" } else { "failed" }, job_id],
                );
            });
            Ok(json_response(202, json!({"id":id})))
        }
        "/api/reports" => {
            let Some(target) = body["target"].as_str() else {
                return Ok(error(400, "缺少关联目标"));
            };
            let target = match scanner::normalize(target) {
                Ok(u) => u.to_string(),
                Err(e) => return Ok(error(400, &e.to_string())),
            };
            let report = &body["report"];
            if !report.is_object() || report["schema"] != "php-selfcheck-host/v1" {
                return Ok(error(400, "报告格式不匹配，请使用 php-selfcheck collect"));
            }
            let review = match crate::assessment::review(&body["review"]) {
                Ok(v) => v,
                Err(e) => return Ok(error(400, &e.to_string())),
            };
            let payload = json!({"review":review,"trust":"开发者提交，未经独立核验","report":report,"association":"用户指定关联目标，未验证此主机是否实际承载该 URL"});
            let id = token(16);
            state.db.lock().unwrap().execute(
                "INSERT INTO reports VALUES(?,?,?,?,?)",
                params![id, user, now(), target, payload.to_string()],
            )?;
            state.audit(user, "host_report_import", json!({"id":id,"target":target}))?;
            Ok(json_response(201, json!({"id":id})))
        }
        _ => Ok(error(404, "不存在")),
    }
}
pub async fn serve(config: Config, bind: SocketAddr) -> Result<()> {
    let state = State::new(config)?;
    let listener = tokio::net::TcpListener::bind(bind).await?;
    println!(
        "PHP 自查服务已启动: {} (Ctrl+C 停止)",
        state.config.public_origin
    );
    axum::serve(
        listener,
        router(state).into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(async {
        let _ = tokio::signal::ctrl_c().await;
    })
    .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn fixture() -> (tempfile::TempDir, Arc<State>) {
        let dir = tempfile::tempdir().unwrap();
        let cfg = Config {
            public_origin: "http://127.0.0.1:8080".into(),
            admins: Default::default(),
            allow_anonymous: false,
            probe_multipart: false,
            headers_only: false,
            allow_without_whitelist: false,
            allowed_networks: vec![],
            allowed_domains: vec![],
            allowed_ports: vec![80, 443],
            database: dir
                .path()
                .join("test.sqlite3")
                .to_string_lossy()
                .into_owned(),
            users: std::collections::BTreeMap::from([(
                "alice".into(),
                crate::config::password_hash("a", None).unwrap(),
            )]),
        };
        (dir, State::new(cfg).unwrap())
    }
    #[tokio::test]
    async fn per_user_and_global_job_limits() {
        let (_dir, state) = fixture();
        {
            let db = state.db.lock().unwrap();
            for i in 0..2 {
                db.execute(
                    "INSERT INTO jobs VALUES(?, 'alice', 0, 'queued', '[]')",
                    [format!("a{i}")],
                )
                .unwrap();
            }
        }
        assert_eq!(
            post(
                state.clone(),
                "alice",
                "/api/scan",
                json!({"targets":["example.com"]})
            )
            .unwrap()
            .status(),
            429
        );
        {
            let db = state.db.lock().unwrap();
            db.execute("DELETE FROM jobs", []).unwrap();
            for i in 0..8 {
                db.execute(
                    "INSERT INTO jobs VALUES(?, 'bob', 0, 'running', '[]')",
                    [format!("b{i}")],
                )
                .unwrap();
            }
        }
        assert_eq!(
            post(
                state,
                "alice",
                "/api/scan",
                json!({"targets":["example.com"]})
            )
            .unwrap()
            .status(),
            429
        );
    }
    #[tokio::test]
    async fn authentication_failure_and_account_rate_windows() {
        let (_dir, state) = fixture();
        state
            .failures
            .lock()
            .unwrap()
            .insert("unknown".into(), vec![Instant::now(); 12]);
        let req = Request::builder()
            .uri("/api/me")
            .header("host", "127.0.0.1:8080")
            .body(Body::empty())
            .unwrap();
        assert_eq!(dispatch(state.clone(), req).await.unwrap().status(), 429);
        state.failures.lock().unwrap().clear();
        state
            .rates
            .lock()
            .unwrap()
            .insert("alice".into(), vec![Instant::now(); 120]);
        let req = Request::builder()
            .uri("/api/me")
            .header("host", "127.0.0.1:8080")
            .header(
                "authorization",
                format!("Basic {}", STANDARD.encode("alice:a")),
            )
            .body(Body::empty())
            .unwrap();
        assert_eq!(dispatch(state, req).await.unwrap().status(), 429);
    }
}
