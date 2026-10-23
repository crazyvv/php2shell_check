//! Opaque, database-backed sessions. Only token hashes are stored.
use crate::config::{Config, token};
use anyhow::Result;
use axum::http::HeaderMap;
use rusqlite::{Connection, OptionalExtension, params};
use sha2::{Digest, Sha256};
pub const VISITOR_COOKIE: &str = "php_selfcheck_visitor";
pub const ADMIN_COOKIE: &str = "php_selfcheck_admin";
fn digest(s: &str) -> String {
    hex::encode(Sha256::digest(s.as_bytes()))
}
fn cookie_value(headers: &HeaderMap, name: &str) -> Option<String> {
    let values: Vec<_> = headers
        .get_all("cookie")
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|s| s.split(';'))
        .filter_map(|s| s.trim().split_once('='))
        .filter(|(k, _)| *k == name)
        .map(|(_, v)| v)
        .collect();
    if values.len() != 1 {
        return None;
    }
    let v = values[0];
    (v.len() == 64 && v.bytes().all(|b| b.is_ascii_hexdigit())).then(|| v.to_owned())
}
pub fn cookie(config: &Config, kind: &str, value: &str, clear: bool) -> String {
    let (name, path) = if kind == "admin" {
        (ADMIN_COOKIE, "/api/admin")
    } else {
        (VISITOR_COOKIE, "/")
    };
    let age = if clear {
        "; Max-Age=0"
    } else if kind == "admin" {
        "; Max-Age=28800"
    } else {
        ""
    };
    format!(
        "{name}={value}; Path={path}; HttpOnly; SameSite=Strict{age}{}",
        if config.public_origin.starts_with("https://") {
            "; Secure"
        } else {
            ""
        }
    )
}
pub fn create(
    db: &Connection,
    config: &Config,
    kind: &str,
    owner: Option<&str>,
) -> Result<(String, String)> {
    let raw = token(32);
    let owner = owner
        .map(str::to_owned)
        .unwrap_or_else(|| format!("visitor:{}", token(16)));
    let credential = if kind == "admin" {
        digest(config.admins.get(&owner).map(String::as_str).unwrap_or(""))
    } else {
        String::new()
    };
    let ttl = if kind == "admin" { 28800.0 } else { 604800.0 };
    db.execute(
        "DELETE FROM sessions WHERE expires<=?",
        [crate::portal::now()],
    )?;
    db.execute(
        "INSERT INTO sessions(token_hash,owner,kind,expires,credential) VALUES(?,?,?,?,?)",
        params![
            digest(&raw),
            owner,
            kind,
            crate::portal::now() + ttl,
            credential
        ],
    )?;
    Ok((owner, cookie(config, kind, &raw, false)))
}
pub fn lookup(
    db: &Connection,
    config: &Config,
    headers: &HeaderMap,
    kind: &str,
) -> Result<Option<String>> {
    let name = if kind == "admin" {
        ADMIN_COOKIE
    } else {
        VISITOR_COOKIE
    };
    let Some(raw) = cookie_value(headers, name) else {
        return Ok(None);
    };
    let row: Option<(String, String)> = db
        .query_row(
            "SELECT owner,credential FROM sessions WHERE token_hash=? AND kind=? AND expires>?",
            params![digest(&raw), kind, crate::portal::now()],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()?;
    Ok(row.and_then(|(owner, credential)| {
        if kind == "admin"
            && config
                .admins
                .get(&owner)
                .is_none_or(|hash| digest(hash) != credential)
        {
            None
        } else {
            Some(owner)
        }
    }))
}
pub fn revoke(db: &Connection, headers: &HeaderMap, kind: &str) -> Result<()> {
    let name = if kind == "admin" {
        ADMIN_COOKIE
    } else {
        VISITOR_COOKIE
    };
    if let Some(raw) = cookie_value(headers, name) {
        db.execute(
            "DELETE FROM sessions WHERE token_hash=? AND kind=?",
            params![digest(&raw), kind],
        )?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn config() -> Config {
        serde_json::from_value(serde_json::json!({"public_origin":"https://scan.example","allow_anonymous":true,"database":"unused","admins":{"admin":"hash1"}})).unwrap()
    }
    #[test]
    fn token_hash_roles_expiry_and_revocation() {
        let db = Connection::open_in_memory().unwrap();
        db.execute_batch("CREATE TABLE sessions(token_hash TEXT PRIMARY KEY,owner TEXT,kind TEXT,expires REAL,credential TEXT)").unwrap();
        let c = config();
        let (owner, cookie) = create(&db, &c, "visitor", None).unwrap();
        assert!(owner.starts_with("visitor:"));
        assert!(
            cookie.contains("HttpOnly")
                && cookie.contains("SameSite=Strict")
                && cookie.contains("Secure")
                && cookie.contains("Path=/;")
        );
        let raw = cookie.split(';').next().unwrap().split_once('=').unwrap().1;
        let stored: String = db
            .query_row("SELECT token_hash FROM sessions", [], |r| r.get(0))
            .unwrap();
        assert_ne!(stored, raw);
        let mut headers = HeaderMap::new();
        headers.insert("cookie", cookie.split(';').next().unwrap().parse().unwrap());
        assert_eq!(lookup(&db, &c, &headers, "visitor").unwrap(), Some(owner));
        assert!(lookup(&db, &c, &headers, "admin").unwrap().is_none());
        db.execute("UPDATE sessions SET expires=0", []).unwrap();
        assert!(lookup(&db, &c, &headers, "visitor").unwrap().is_none());
        let (_, cookie) = create(&db, &c, "admin", Some("admin")).unwrap();
        headers.insert("cookie", cookie.split(';').next().unwrap().parse().unwrap());
        assert_eq!(
            lookup(&db, &c, &headers, "admin").unwrap(),
            Some("admin".into())
        );
        let mut changed = c.clone();
        changed.admins.insert("admin".into(), "hash2".into());
        assert!(lookup(&db, &changed, &headers, "admin").unwrap().is_none());
        revoke(&db, &headers, "admin").unwrap();
        assert!(lookup(&db, &c, &headers, "admin").unwrap().is_none());
    }
}
