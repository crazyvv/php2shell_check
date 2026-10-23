use crate::{
    config::verify,
    portal::{self, State, error, json_response, window},
    session,
};
use anyhow::Result;
use axum::{
    body::Body,
    extract::ConnectInfo,
    http::{Request, header},
    response::Response,
};
use rusqlite::{OptionalExtension, params};
use serde_json::json;
use std::{net::SocketAddr, sync::Arc, time::Instant};
pub async fn dispatch(state: Arc<State>, req: Request<Body>) -> Result<Response> {
    let path = req.uri().path().to_owned();
    let query = req.uri().query().unwrap_or("").to_owned();
    let method = req.method().clone();
    if path == "/api/admin/login" {
        if method != axum::http::Method::POST {
            return Ok(error(405, "请使用 POST 登录"));
        }
        let peer = req
            .extensions()
            .get::<ConnectInfo<SocketAddr>>()
            .map(|p| p.0.ip().to_string())
            .unwrap_or_else(|| "unknown".into());
        let rate_key = format!("admin:{peer}");
        if window(&mut state.failures.lock().unwrap(), &rate_key).len() >= 12 {
            return Ok(error(429, "管理员登录失败过多，请稍后再试"));
        }
        let login_headers = req.headers().clone();
        let body = match portal::read_body(&state.config, req).await {
            Ok(v) => v,
            Err((status, message)) => return Ok(error(status, message)),
        };
        let name = body["user"].as_str().unwrap_or("").to_owned();
        let password = body["password"].as_str().unwrap_or("").to_owned();
        if name.len() > 64 || password.len() > 4096 {
            return Ok(error(400, "登录信息过长"));
        }
        let hash = state.config.admins.get(&name).cloned();
        let valid = if let Some(hash) = hash {
            tokio::task::spawn_blocking(move || verify(&password, &hash)).await?
        } else {
            false
        };
        if !valid {
            window(&mut state.failures.lock().unwrap(), &rate_key).push(Instant::now());
            state.audit("unknown", "admin_login_failed", json!({"peer":peer}))?;
            return Ok(error(
                401,
                "管理员账号或密码不正确；未配置时请在服务器执行 add-admin",
            ));
        }
        // A new token on every login prevents fixation. Revoke an existing session for this browser.
        let cookie = {
            let db = state.db.lock().unwrap();
            session::revoke(&db, &login_headers, "admin")?;
            session::create(&db, &state.config, "admin", Some(&name))?.1
        };
        state.audit(
            &format!("admin:{name}"),
            "admin_login",
            json!({"peer":peer}),
        )?;
        let mut response = json_response(200, json!({"user":name}));
        response
            .headers_mut()
            .insert(header::SET_COOKIE, cookie.parse()?);
        return Ok(response);
    }
    let user = {
        let db = state.db.lock().unwrap();
        session::lookup(&db, &state.config, req.headers(), "admin")?
    };
    let Some(user) = user else {
        return Ok(error(401, "请先登录管理员页面"));
    };
    let actor = format!("admin:{user}");
    if method == axum::http::Method::POST && path == "/api/admin/logout" {
        let headers = req.headers().clone();
        if let Err((status, message)) = portal::read_body(&state.config, req).await {
            return Ok(error(status, message));
        }
        session::revoke(&state.db.lock().unwrap(), &headers, "admin")?;
        state.audit(&actor, "admin_logout", json!({}))?;
        let mut response = json_response(200, json!({"ok":true}));
        response.headers_mut().insert(
            header::SET_COOKIE,
            session::cookie(&state.config, "admin", "", true).parse()?,
        );
        return Ok(response);
    }
    if method != axum::http::Method::GET {
        return Ok(error(405, "仅支持 GET"));
    }
    if path == "/api/admin/me" {
        return Ok(json_response(200, json!({"user":user})));
    }
    if path == "/api/admin/jobs" {
        let fields: Vec<_> = url::form_urlencoded::parse(query.as_bytes()).collect();
        let value = |name: &str| {
            fields
                .iter()
                .find(|(k, _)| k == name)
                .map(|(_, v)| v.as_ref())
        };
        let offset = value("offset")
            .and_then(|s| s.parse::<u32>().ok())
            .unwrap_or(0)
            .min(1_000_000);
        let limit = value("limit")
            .and_then(|s| s.parse::<u32>().ok())
            .unwrap_or(25)
            .clamp(1, 100);
        let search = value("search").unwrap_or("");
        if search.len() > 200 {
            return Ok(error(400, "搜索内容过长"));
        }
        let pattern = format!(
            "%{}%",
            search
                .replace('\\', "\\\\")
                .replace('%', "\\%")
                .replace('_', "\\_")
        );
        let records;
        let total;
        let summary;
        {
            let db = state.db.lock().unwrap();
            let filter = "(?='' OR owner LIKE ? ESCAPE '\\' OR id LIKE ? ESCAPE '\\' OR EXISTS(SELECT 1 FROM json_each(jobs.results) WHERE json_extract(value,'$.target') LIKE ? ESCAPE '\\'))";
            total = db.query_row(
                &format!("SELECT count(*) FROM jobs WHERE {filter}"),
                params![search, pattern, pattern, pattern],
                |r| r.get::<_, i64>(0),
            )?;
            let mut q=db.prepare(&format!("SELECT id,owner,created,state,results FROM jobs WHERE {filter} ORDER BY created DESC,id DESC LIMIT ? OFFSET ?"))?;
            let mut rows = q
                .query_map(
                    params![search, pattern, pattern, pattern, limit, offset],
                    portal::job,
                )?
                .collect::<std::result::Result<Vec<_>, _>>()?;
            for record in &mut rows {
                let owner = record["owner"].as_str().unwrap_or("").to_owned();
                portal::enrich(&db, &owner, record)?;
            }
            records = rows;
            let mut states = serde_json::Map::new();
            let mut q = db.prepare("SELECT state,count(*) FROM jobs GROUP BY state")?;
            for row in q.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?)))? {
                let (k, v) = row?;
                states.insert(k, json!(v));
            }
            let mut verdicts = serde_json::Map::new();
            let mut q=db.prepare("SELECT coalesce(json_extract(value,'$.verdict'),'未知'),count(*) FROM jobs,json_each(jobs.results) GROUP BY 1")?;
            for row in q.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?)))? {
                let (k, v) = row?;
                verdicts.insert(k, json!(v));
            }
            summary = json!({"jobs":db.query_row("SELECT count(*) FROM jobs",[],|r|r.get::<_,i64>(0))?,"reports":db.query_row("SELECT count(*) FROM reports",[],|r|r.get::<_,i64>(0))?,"states":states,"verdicts":verdicts});
        }
        state.audit(
            &actor,
            "admin_history_view",
            json!({"offset":offset,"limit":limit}),
        )?;
        return Ok(json_response(
            200,
            json!({"jobs":records,"total":total,"offset":offset,"limit":limit,"summary":summary}),
        ));
    }
    if let Some(id) = path.strip_prefix("/api/admin/jobs/") {
        let record = state
            .db
            .lock()
            .unwrap()
            .query_row(
                "SELECT id,owner,created,state,results FROM jobs WHERE id=?",
                [id],
                portal::job,
            )
            .optional()?;
        let Some(mut record) = record else {
            return Ok(error(404, "记录不存在"));
        };
        let owner = record["owner"].as_str().unwrap_or("").to_owned();
        portal::enrich(&state.db.lock().unwrap(), &owner, &mut record)?;
        return portal::job_response(&state, &actor, record, &query);
    }
    Ok(error(404, "不存在"))
}
