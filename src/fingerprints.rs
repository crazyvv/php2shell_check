//! Passive, bounded technology hints. Rules never issue requests or determine patch status.
use anyhow::{Context, Result, ensure};
use regex::{Regex, RegexBuilder};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    io::Read,
    path::Path,
    sync::{Arc, LazyLock},
};
use url::Url;

pub const SCHEMA: &str = "php-selfcheck-fingerprints/v1";
pub const BUILTIN: &str = include_str!("../rules/fingerprints.json");
const MAX_RULES: usize = 256;
const MAX_MATCHES: usize = 64;
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum Mode {
    #[default]
    Extend,
    Replace,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RuleFile {
    schema: String,
    version: String,
    #[serde(default)]
    mode: Mode,
    #[serde(default)]
    disabled_rules: Vec<String>,
    rules: Vec<Rule>,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
enum Category {
    Cms,
    Framework,
    Runtime,
    StaticGenerator,
    HostedPlatform,
    Hosting,
    WebServer,
    Cdn,
    Waf,
    Challenge,
}
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
enum Runtime {
    Php,
    Nodejs,
    Static,
    #[default]
    Unknown,
}
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Confidence {
    #[default]
    Low,
    Medium,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Rule {
    id: String,
    name: String,
    category: Category,
    #[serde(default)]
    runtime: Runtime,
    #[serde(default)]
    confidence: Confidence,
    #[serde(default)]
    all: Vec<Matcher>,
    #[serde(default)]
    any: Vec<Matcher>,
    #[serde(default)]
    advice: String,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
enum Source {
    Header,
    CookieName,
    MetaGenerator,
    Title,
    ResourcePath,
    Body,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Matcher {
    source: Source,
    #[serde(default)]
    header: Option<String>,
    pattern: String,
    #[serde(default = "yes")]
    same_origin: bool,
}
fn yes() -> bool {
    true
}
#[derive(Debug)]
struct CompiledRule {
    rule: Rule,
    all: Vec<Regex>,
    any: Vec<Regex>,
}
#[derive(Debug)]
pub struct Library {
    rules: Vec<CompiledRule>,
    metadata: Value,
}
static DEFAULT: LazyLock<Arc<Library>> =
    LazyLock::new(|| Arc::new(Library::compile(None).expect("bundled fingerprint rules")));
pub fn builtin() -> Arc<Library> {
    DEFAULT.clone()
}

impl Library {
    pub fn load(path: &Path) -> Result<Arc<Self>> {
        let mut data = String::new();
        std::fs::File::open(path)
            .context("无法读取特征库")?
            .take(524_289)
            .read_to_string(&mut data)?;
        ensure!(data.len() <= 524_288, "特征库文件不能超过 512 KiB");
        Ok(Arc::new(Self::compile(Some(&data))?))
    }
    pub fn from_json(data: &str) -> Result<Arc<Self>> {
        ensure!(data.len() <= 524_288, "特征库文件不能超过 512 KiB");
        Ok(Arc::new(Self::compile(Some(data))?))
    }
    fn compile(custom: Option<&str>) -> Result<Self> {
        let base: RuleFile = serde_json::from_str(BUILTIN)?;
        let builtin_version = base.version.clone();
        let mut effective = base.rules;
        let mut version = builtin_version.clone();
        let mut mode = Mode::Replace;
        if let Some(data) = custom {
            let file: RuleFile = serde_json::from_str(data).context("特征库 JSON 格式错误")?;
            ensure!(file.schema == SCHEMA, "特征库 schema 不支持");
            ensure!(
                !file.version.trim().is_empty() && file.version.len() <= 100,
                "特征库 version 不能为空或超过 100 字节"
            );
            ensure!(
                file.rules.len() <= MAX_RULES && file.disabled_rules.len() <= MAX_RULES,
                "特征规则过多"
            );
            let mut seen = BTreeSet::new();
            for rule in &file.rules {
                ensure!(
                    seen.insert(rule.id.clone()),
                    "特征库包含重复规则 ID: {}",
                    rule.id
                );
            }
            version = file.version;
            mode = file.mode;
            if mode == Mode::Replace {
                ensure!(
                    file.disabled_rules.is_empty(),
                    "replace 模式不接受 disabled_rules"
                );
                effective = file.rules;
            } else {
                let ids: BTreeSet<_> = effective
                    .iter()
                    .map(|r| r.id.clone())
                    .chain(file.rules.iter().map(|r| r.id.clone()))
                    .collect();
                let mut disabled = BTreeSet::new();
                for id in &file.disabled_rules {
                    ensure!(
                        ids.contains(id) && disabled.insert(id),
                        "禁用的规则 ID 不存在或重复: {id}"
                    );
                }
                for rule in file.rules {
                    if let Some(at) = effective.iter().position(|r| r.id == rule.id) {
                        effective[at] = rule;
                    } else {
                        effective.push(rule);
                    }
                }
                effective.retain(|r| !disabled.contains(&r.id));
            }
        }
        ensure!(effective.len() <= MAX_RULES, "有效特征规则不能超过 256 条");
        let digest = hex::encode(Sha256::digest(serde_json::to_vec(&effective)?));
        let mut rules = vec![];
        for rule in effective {
            ensure!(
                !rule.id.is_empty()
                    && rule.id.len() <= 80
                    && rule
                        .id
                        .bytes()
                        .all(|c| c.is_ascii_alphanumeric() || b"._-".contains(&c)),
                "规则 ID 格式不合法"
            );
            ensure!(
                !rule.name.trim().is_empty() && rule.name.len() <= 160 && rule.advice.len() <= 2000,
                "规则名称/建议长度不合法: {}",
                rule.id
            );
            ensure!(
                (1..=16).contains(&(rule.all.len() + rule.any.len())),
                "每条规则须有 1–16 个匹配条件: {}",
                rule.id
            );
            let compile = |matcher: &Matcher| -> Result<Regex> {
                ensure!(
                    !matcher.pattern.is_empty() && matcher.pattern.len() <= 4096,
                    "匹配表达式为空或过长: {}",
                    rule.id
                );
                if matcher.source == Source::Header {
                    let h = matcher.header.as_deref().unwrap_or("");
                    ensure!(
                        !h.is_empty()
                            && h.len() <= 100
                            && h.bytes()
                                .all(|c| c.is_ascii_alphanumeric()
                                    || b"!#$%&'*+-.^_`|~".contains(&c)),
                        "header 条件须提供合法 header 名称: {}",
                        rule.id
                    );
                    ensure!(
                        ![
                            "set-cookie",
                            "cookie",
                            "authorization",
                            "proxy-authorization",
                            "www-authenticate",
                            "proxy-authenticate"
                        ]
                        .contains(&h.to_ascii_lowercase().as_str()),
                        "敏感头不能用于 header 匹配，请用 cookie_name: {}",
                        rule.id
                    );
                } else {
                    ensure!(
                        matcher.header.is_none(),
                        "仅 header 条件可指定 header 字段: {}",
                        rule.id
                    );
                }
                ensure!(
                    matcher.same_origin || matcher.source == Source::ResourcePath,
                    "same_origin 仅用于 resource_path: {}",
                    rule.id
                );
                let re = RegexBuilder::new(&matcher.pattern)
                    .size_limit(1_048_576)
                    .dfa_size_limit(1_048_576)
                    .build()
                    .with_context(|| format!("规则 {} 的正则无效", rule.id))?;
                ensure!(
                    !re.capture_names().flatten().any(|n| n == "version")
                        || matches!(matcher.source, Source::Header | Source::MetaGenerator),
                    "版本声明仅能从 header/meta_generator 提取: {}",
                    rule.id
                );
                Ok(re)
            };
            let all = rule.all.iter().map(compile).collect::<Result<Vec<_>>>()?;
            let any = rule.any.iter().map(compile).collect::<Result<Vec<_>>>()?;
            rules.push(CompiledRule { rule, all, any });
        }
        let metadata = json!({"schema":SCHEMA,"version":version,"builtin_version":builtin_version,"source":if custom.is_none(){"builtin"}else if mode==Mode::Extend{"custom_extend"}else{"custom_replace"},"sha256":digest,"rule_count":rules.len()});
        Ok(Self { rules, metadata })
    }
    pub fn metadata(&self) -> &Value {
        &self.metadata
    }
    pub fn detect(&self, url: Option<&Url>, headers: &[(String, String)], body: &[u8]) -> Value {
        let observations = observations(url, headers, body);
        let mut matches = vec![];
        let mut truncated = false;
        for compiled in &self.rules {
            let mut evidence = vec![];
            let mut versions = BTreeSet::new();
            let mut response_hint = false;
            let mut match_one = |matcher: &Matcher, re: &Regex| -> bool {
                let found = observations
                    .iter()
                    .filter(|o| {
                        o.source == matcher.source
                            && (matcher.source != Source::Header
                                || matcher.header.as_ref().is_some_and(|h| {
                                    h.eq_ignore_ascii_case(o.header.as_deref().unwrap_or(""))
                                }))
                            && (matcher.source != Source::ResourcePath
                                || !matcher.same_origin
                                || o.relation == "same_origin")
                    })
                    .flat_map(|o| {
                        re.captures_iter(&o.text)
                            .take(3)
                            .map(move |captures| (o, captures))
                    })
                    .take(3)
                    .collect::<Vec<_>>();
                let hit = !found.is_empty();
                for (o, captures) in found {
                    if let Some(v) = captures.name("version") {
                        let v = v.as_str();
                        if v.len() <= 80
                            && v.starts_with(|c: char| c.is_ascii_digit())
                            && v.bytes()
                                .all(|c| c.is_ascii_alphanumeric() || b".+~_:-".contains(&c))
                        {
                            versions.insert(v.to_owned());
                        }
                    }
                    if o.relation != "external_resource" && o.relation != "unresolved_resource" {
                        response_hint = true;
                    }
                    if evidence.len() < 8 {
                        evidence.push(json!({"source":matcher.source,"header":o.header,"pattern":matcher.pattern.chars().take(256).collect::<String>(),"pattern_truncated":matcher.pattern.chars().count()>256,"resource_origin":o.resource_origin,"relation":o.relation,"url":url.map(Url::as_str),"detail":match matcher.source {Source::CookieName=>format!("Cookie 名称 {} 命中（不读取/保存值）",o.text.chars().take(100).collect::<String>()),Source::ResourcePath=>format!("资源路径 {} 命中（查询参数已省略）",o.text.chars().take(160).collect::<String>()),_=>"已获取响应中的该位置命中规则（不保存原始内容）".into()}}));
                    }
                }
                hit
            };
            let all = compiled
                .rule
                .all
                .iter()
                .zip(&compiled.all)
                .map(|(m, r)| match_one(m, r))
                .collect::<Vec<_>>()
                .into_iter()
                .all(|v| v);
            let any = compiled
                .rule
                .any
                .iter()
                .zip(&compiled.any)
                .map(|(m, r)| match_one(m, r))
                .collect::<Vec<_>>();
            if !all || (!any.is_empty() && !any.iter().any(|v| *v)) {
                continue;
            }
            if matches.len() >= MAX_MATCHES {
                truncated = true;
                break;
            }
            matches.push(json!({"id":compiled.rule.id,"name":compiled.rule.name,"category":compiled.rule.category,"runtime_hint":compiled.rule.runtime,"confidence":compiled.rule.confidence,"relation":if response_hint{"response"}else{"external_reference"},"versions":versions,"version_conflict":versions.len()>1,"evidence":evidence,"advice":compiled.rule.advice,"php_hint":compiled.rule.runtime==Runtime::Php && response_hint,"blocked_hint":compiled.rule.category==Category::Challenge && response_hint,"patch_verified":false}));
        }
        json!({"library":self.metadata,"matches":matches,"matches_truncated":truncated,"php_hint":matches.iter().any(|m|m["php_hint"]==true),"blocked_hint":matches.iter().any(|m|m["blocked_hint"]==true),"limitations":"被动特征仅为线索；资源可能来自外部服务或静态导出，不确认实际运行版本、实例归属或修复状态"})
    }
}
#[derive(Debug)]
struct Observation {
    source: Source,
    header: Option<String>,
    text: String,
    relation: &'static str,
    resource_origin: Option<String>,
}
static TAG: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?is)<(?:meta|script|link|img|form|a|source|iframe|input|video|audio)\b[^>]*>")
        .unwrap()
});
static ATTR: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)([a-z][a-z0-9_-]*)\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'<>`=]+))"#).unwrap()
});
static COMMENTS: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?s)<!--.*?(?:-->|$)").unwrap());
static SCRIPTS: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?is)(<script\b[^>]*>).*?</script\s*>").unwrap());
static TITLE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?is)<title\b[^>]*>([^<]*)</title\s*>").unwrap());
fn observations(url: Option<&Url>, headers: &[(String, String)], body: &[u8]) -> Vec<Observation> {
    let mut out = vec![];
    for (name, value) in headers.iter().take(128) {
        if name.eq_ignore_ascii_case("set-cookie") {
            if let Some((cookie, _)) = value.split_once('=') {
                let cookie = cookie.trim();
                if !cookie.is_empty() && cookie.len() <= 128 {
                    out.push(Observation {
                        source: Source::CookieName,
                        header: None,
                        text: cookie.into(),
                        relation: "response",
                        resource_origin: None,
                    });
                }
            }
        } else if ![
            "cookie",
            "authorization",
            "proxy-authorization",
            "www-authenticate",
            "proxy-authenticate",
        ]
        .contains(&name.to_ascii_lowercase().as_str())
        {
            out.push(Observation {
                source: Source::Header,
                header: Some(name.to_ascii_lowercase()),
                text: value.chars().take(4096).collect(),
                relation: "response",
                resource_origin: None,
            });
        }
    }
    if body.is_empty() {
        return out;
    }
    let page = String::from_utf8_lossy(&body[..body.len().min(131072)]);
    let page = COMMENTS.replace_all(&page, "");
    if !body.is_empty() {
        out.push(Observation {
            source: Source::Body,
            header: None,
            text: page.to_string(),
            relation: "response",
            resource_origin: None,
        });
    }
    if let Some(c) = TITLE.captures(&page) {
        out.push(Observation {
            source: Source::Title,
            header: None,
            text: c[1].chars().take(1024).collect(),
            relation: "response",
            resource_origin: None,
        });
    }
    let html = SCRIPTS.replace_all(&page, "$1</script>");
    for tag in TAG.find_iter(&html).filter(|t| t.len() <= 4096).take(256) {
        let tag = tag.as_str();
        let attrs: BTreeMap<_, _> = ATTR
            .captures_iter(tag)
            .filter_map(|c| {
                Some((
                    c[1].to_ascii_lowercase(),
                    c.get(2).or(c.get(3)).or(c.get(4))?.as_str().to_string(),
                ))
            })
            .collect();
        if tag
            .get(..5)
            .is_some_and(|s| s.eq_ignore_ascii_case("<meta"))
            && attrs
                .get("name")
                .is_some_and(|s| s.eq_ignore_ascii_case("generator"))
            && let Some(content) = attrs.get("content")
        {
            out.push(Observation {
                source: Source::MetaGenerator,
                header: None,
                text: content.chars().take(1024).collect(),
                relation: "response",
                resource_origin: None,
            });
        }
        if tag
            .get(..5)
            .is_some_and(|s| s.eq_ignore_ascii_case("<meta"))
        {
            continue;
        }
        for key in ["src", "href", "action", "data-src"] {
            let Some(value) = attrs.get(key) else {
                continue;
            };
            let joined = url
                .and_then(|base| base.join(value).ok())
                .or_else(|| Url::parse(value).ok());
            if let Some(resource) = joined.filter(|u| {
                matches!(u.scheme(), "http" | "https")
                    && u.username().is_empty()
                    && u.password().is_none()
            }) {
                let relation = if url.is_some_and(|base| base.origin() == resource.origin()) {
                    "same_origin"
                } else {
                    "external_resource"
                };
                out.push(Observation {
                    source: Source::ResourcePath,
                    header: None,
                    text: resource.path().chars().take(2048).collect(),
                    relation,
                    resource_origin: Some(resource.origin().ascii_serialization()),
                });
            } else if url.is_none() && value.starts_with('/') && !value.starts_with("//") {
                out.push(Observation {
                    source: Source::ResourcePath,
                    header: None,
                    text: value
                        .split(['?', '#'])
                        .next()
                        .unwrap_or("")
                        .chars()
                        .take(2048)
                        .collect(),
                    relation: "unresolved_resource",
                    resource_origin: None,
                });
            }
        }
    }
    out
}
