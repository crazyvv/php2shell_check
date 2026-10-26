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
    if path == "/api/admin/fingerprints" || path.starts_with("/api/admin/fingerprints/") {
        return crate::rulebook::dispatch(state, req, &actor).await;
    }
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
    if method == axum::http::Method::POST
        && let Some(id) = path
            .strip_prefix("/api/admin/jobs/")
            .and_then(|p| p.strip_suffix("/delete"))
    {
        let body = match portal::read_body(&state.config, req).await {
            Ok(v) => v,
            Err((status, message)) => return Ok(error(status, message)),
        };
        if body["confirm"] != true {
            return Ok(error(400, "删除需要明确确认"));
        }
        let mut db = state.db.lock().unwrap();
        let tx = db.transaction()?;
        let record = tx
            .query_row(
                "SELECT id,owner,created,state,results FROM jobs WHERE id=?",
                [id],
                portal::job,
            )
            .optional()?;
        let Some(record) = record else {
            return Ok(error(404, "记录不存在"));
        };
        if matches!(record["state"].as_str(), Some("queued" | "running")) {
            return Ok(error(409, "排队或执行中的扫描不能删除，请等待完成"));
        }
        tx.execute("DELETE FROM jobs WHERE id=?", [id])?;
        tx.execute("INSERT INTO audit(created,owner,action,detail) VALUES(?,?,?,?)",params![portal::now(),actor,"admin_scan_delete",json!({"job":id,"owner":record["owner"],"results_count":record["results"].as_array().map(Vec::len).unwrap_or(0)}).to_string()])?;
        tx.commit()?;
        return Ok(json_response(200, json!({"ok":true,"id":id})));
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
        let verdict = value("verdict").unwrap_or("");
        if verdict.len() > 100 {
            return Ok(error(400, "结果筛选内容过长"));
        }
        let sort = value("sort").unwrap_or("newest");
        let order = match sort {
            "newest" => "created DESC,id DESC".to_owned(),
            "oldest" => "created ASC,id ASC".to_owned(),
            "risk_desc" | "risk_asc" => format!(
                "CASE WHEN json_array_length(results)=0 THEN 1 ELSE 0 END, (SELECT max(CASE json_extract(value,'$.verdict') WHEN '疑似受影响' THEN 6 WHEN '无法完成检测' THEN 5 WHEN '无法判断' THEN 4 WHEN '已识别 PHP 特征，版本未知' THEN 3 WHEN '疑似使用 PHP' THEN 2 WHEN '版本达到修复基线（待核验）' THEN 1 WHEN '未发现 PHP 特征' THEN 0 ELSE 4 END) FROM json_each(jobs.results)) {}, created DESC,id DESC",
                if sort == "risk_desc" { "DESC" } else { "ASC" }
            ),
            _ => return Ok(error(400, "不支持的排序方式")),
        };
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
            let filter = "(?='' OR owner LIKE ? ESCAPE '\\' OR id LIKE ? ESCAPE '\\' OR EXISTS(SELECT 1 FROM json_each(jobs.results) WHERE json_extract(value,'$.target') LIKE ? ESCAPE '\\' AND (?='' OR coalesce(json_extract(value,'$.verdict'),'未知')=?)))";
            let filter = format!(
                "{filter} AND (?='' OR EXISTS(SELECT 1 FROM json_each(jobs.results) WHERE coalesce(json_extract(value,'$.verdict'),'未知')=?))"
            );
            total = db.query_row(
                &format!("SELECT count(*) FROM jobs WHERE {filter}"),
                params![
                    search, pattern, pattern, pattern, verdict, verdict, verdict, verdict
                ],
                |r| r.get::<_, i64>(0),
            )?;
            let mut q=db.prepare(&format!("SELECT id,owner,created,state,results FROM jobs WHERE {filter} ORDER BY {order} LIMIT ? OFFSET ?"))?;
            let mut rows = q
                .query_map(
                    params![
                        search, pattern, pattern, pattern, verdict, verdict, verdict, verdict,
                        limit, offset
                    ],
                    portal::job,
                )?
                .collect::<std::result::Result<Vec<_>, _>>()?;
            for record in &mut rows {
                let owner = record["owner"].as_str().unwrap_or("").to_owned();
                portal::enrich(&db, &owner, record)?;
                filter_results(record, verdict);
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
            json!({"offset":offset,"limit":limit,"verdict":verdict,"sort":sort}),
        )?;
        return Ok(json_response(
            200,
            json!({"jobs":records,"total":total,"offset":offset,"limit":limit,"summary":summary,"verdict":verdict,"sort":sort}),
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
        let fields: Vec<_> = url::form_urlencoded::parse(query.as_bytes()).collect();
        let verdict = fields
            .iter()
            .find(|(k, _)| k == "verdict")
            .map(|(_, v)| v.as_ref())
            .unwrap_or("");
        if verdict.len() > 100 {
            return Ok(error(400, "结果筛选内容过长"));
        }
        filter_results(&mut record, verdict);
        return portal::job_response(&state, &actor, record, &query);
    }
    Ok(error(404, "不存在"))
}

fn filter_results(record: &mut serde_json::Value, verdict: &str) {
    if let Some(results) = record["results"].as_array_mut() {
        let total = results.len();
        if !verdict.is_empty() {
            results.retain(|r| r["verdict"].as_str().unwrap_or("未知") == verdict);
        }
        record["total_results"] = json!(total);
    }
}
