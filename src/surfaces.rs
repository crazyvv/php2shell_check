//! Bounded passive observations. Never follows forms or sends payloads.
use regex::Regex;
use serde_json::{Value, json};
use std::{collections::BTreeMap, sync::LazyLock};
use url::Url;

static TAG: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?is)<[^>]{1,4096}>").unwrap());
static ATTR: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?is)\b([a-z][a-z0-9_-]*)\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))"#).unwrap()
});
static HIDDEN: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?is)<!--.*?(?:-->|$)|<script\b[^>]*>.*?(?:</script\s*>|$)|<style\b[^>]*>.*?(?:</style\s*>|$)").unwrap()
});
static ERRORS: LazyLock<Vec<(&str, &str, Regex)>> = LazyLock::new(|| {
    [
        ("memory_limit", "响应出现 PHP 内存耗尽文本；不能证明触发路径或漏洞", r"(?i)allowed memory size of [0-9]+ bytes exhausted"),
        ("session_decode", "响应出现会话解码失败文本；不能确认序列化处理器切换或特定 CVE", r"(?i)(?:failed to decode session object|session_start\(\)[^\r\n<]{0,100}(?:decod|serializ))"),
        ("session_handler", "响应出现会话序列化处理器错误文本；需核对实际配置与日志", r"(?i)(?:session\.serialize_handler|cannot find serialization handler|serialization handler[^\r\n<]{0,80}(?:failed|cannot|unknown))"),
        ("file_include", "响应出现文件包含错误文本；不是 LFI 或任意文件读取的证据", r"(?i)(?:include|require)(?:_once)?\([^\r\n<]{0,160}\)[^\r\n<]{0,160}(?:failed to open stream|failed opening)"),
    ].into_iter().map(|(id, detail, p)| (id, detail, Regex::new(p).unwrap())).collect()
});
fn attributes(tag: &str) -> BTreeMap<String, String> {
    let mut attrs = BTreeMap::new();
    for c in ATTR.captures_iter(tag).take(32) {
        attrs.entry(c[1].to_ascii_lowercase()).or_insert_with(|| {
            c.get(2)
                .or_else(|| c.get(3))
                .or_else(|| c.get(4))
                .unwrap()
                .as_str()
                .chars()
                .take(512)
                .collect()
        });
    }
    attrs
}
fn endpoint(base: Option<&Url>, raw: &str) -> Value {
    // Queries, fragments and credentials are never retained. No discovered URL is fetched.
    let Some(u) = base.and_then(|b| b.join(raw).ok()) else {
        return json!({"relation":"unknown"});
    };
    if !matches!(u.scheme(), "http" | "https") || !u.username().is_empty() || u.password().is_some()
    {
        return json!({"relation":"unsupported"});
    }
    json!({"origin":u.origin().ascii_serialization(),"path":u.path(),"relation":if base.is_some_and(|b|b.origin()==u.origin()) {"same_origin"} else {"external_reference"}})
}
/// Reads at most the existing 128KiB response budget and 512 HTML tags.
pub fn inspect(base: Option<&Url>, body: &[u8]) -> Value {
    let text = String::from_utf8_lossy(&body[..body.len().min(128 * 1024)]);
    let clean = HIDDEN.replace_all(&text, "");
    let mut forms = Vec::new();
    let mut current: Option<Value> = None;
    let mut tags = 0;
    for tag in TAG.find_iter(&clean).take(512) {
        tags += 1;
        let raw = tag.as_str();
        let name = raw
            .trim_start_matches('<')
            .split(|c: char| c.is_whitespace() || c == '>')
            .next()
            .unwrap_or("")
            .to_ascii_lowercase();
        if name == "form" {
            if let Some(form) = current.take() {
                forms.push(form);
            }
            if forms.len() >= 16 {
                break;
            }
            let a = attributes(raw);
            current = Some(
                json!({"endpoint":endpoint(base,a.get("action").map(String::as_str).unwrap_or("")),"method":if a.get("method").is_some_and(|v|v.eq_ignore_ascii_case("post")){"POST"}else{"GET_OR_OTHER"},"multipart":a.get("enctype").is_some_and(|v|v.eq_ignore_ascii_case("multipart/form-data")),"file_fields":[],"progress_field":false}),
            );
        } else if name == "/form" {
            if let Some(form) = current.take() {
                forms.push(form);
            }
        } else if name == "input"
            && let Some(form) = current.as_mut()
        {
            let a = attributes(raw);
            if a.get("name")
                .is_some_and(|v| v.eq_ignore_ascii_case("PHP_SESSION_UPLOAD_PROGRESS"))
            {
                form["progress_field"] = json!(true);
            }
            if a.get("type")
                .is_some_and(|v| v.eq_ignore_ascii_case("file"))
                && let Some(name) = a.get("name")
            {
                let fields = form["file_fields"].as_array_mut().unwrap();
                if fields.len() < 16 {
                    fields.push(json!(name.chars().take(100).collect::<String>()));
                }
            }
        }
    }
    if forms.len() < 16
        && let Some(form) = current
    {
        forms.push(form);
    }
    let form_limit = forms.len() >= 16;
    forms.retain(|f| {
        f["multipart"] == true
            || f["progress_field"] == true
            || f["file_fields"].as_array().is_some_and(|v| !v.is_empty())
    });
    let errors: Vec<_> = ERRORS.iter().filter(|(_,_,r)|r.is_match(&clean)).map(|(id,detail,_)| json!({"kind":id,"detail":detail,"source":"response_text","confidence":"low"})).collect();
    json!({"mode":"passive","forms":forms,"errors":errors,"limits_reached":body.len()>128*1024 || tags>=512 || form_limit,"limitations":["只分析已取得的响应；不爬取、猜测路径、提交表单或上传文件","HTML 解析为有界线索提取，脚本生成、畸形 HTML、外部关联表单可能遗漏","错误文本可以是示例或伪造，不证明特定漏洞；未发现错误也不代表安全","入口仅保留来源与路径，省略查询参数、片段、表单值及错误原文"]})
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn extracts_forms_without_secrets_or_following_external_actions() {
        let u = Url::parse("https://example.com/account/page").unwrap();
        let r=inspect(Some(&u),br#"<!-- <form enctype="multipart/form-data"> --><script>let x='<input type="file" name="fake">'</script><form action="../upload.php?token=SECRET#frag" method="post" enctype="multipart/form-data"><input type="hidden" name="csrf" value="SECRET"><input type="file" name="document"><input name="PHP_SESSION_UPLOAD_PROGRESS" value="SECRET"></form><form action="https://other.example/upload" enctype="multipart/form-data"></form>"#);
        assert_eq!(r["forms"].as_array().unwrap().len(), 2);
        assert_eq!(r["forms"][0]["endpoint"]["path"], "/upload.php");
        assert_eq!(r["forms"][0]["file_fields"][0], "document");
        assert_eq!(r["forms"][0]["progress_field"], true);
        assert_eq!(r["forms"][1]["endpoint"]["relation"], "external_reference");
        assert!(!r.to_string().contains("SECRET"));
        assert!(!r.to_string().contains("fake"));
    }
    #[test]
    fn budgets_and_unsupported_actions_are_explicit() {
        let base = Url::parse("https://example.com/").unwrap();
        for action in ["javascript:alert(1)", "https://user:secret@other.example/x"] {
            let html = format!("<form enctype='multipart/form-data' action='{action}'></form>");
            let r = inspect(Some(&base), html.as_bytes());
            assert_eq!(r["forms"][0]["endpoint"]["relation"], "unsupported");
            assert!(!r.to_string().contains("secret"));
        }
        let html = "<form enctype='multipart/form-data'></form>".repeat(100);
        let r = inspect(Some(&base), html.as_bytes());
        assert_eq!(r["forms"].as_array().unwrap().len(), 16);
        assert_eq!(r["limits_reached"], true);
    }
    #[test]
    fn error_categories_are_not_cve_or_execution_verification() {
        let r=inspect(None,b"Allowed memory size of 999 bytes exhausted; Failed to decode session object; session.serialize_handler; include(foo): failed to open stream");
        assert_eq!(r["errors"].as_array().unwrap().len(), 4);
        assert!(!r.to_string().contains("foo"));
        assert!(inspect(None, b"")["errors"].as_array().unwrap().is_empty());
        assert!(inspect(None, &vec![b'x'; 200000])["limits_reached"] == true);
    }
}
