//! Central collector (server mode) and agent-side forwarding. No extra dependencies; HMAC-SHA256 signed requests.
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashSet};
use std::fs;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream, ToSocketAddrs};
use std::os::unix::fs::OpenOptionsExt;
use std::sync::{Arc, Mutex};
use std::time::Duration;

pub const CONF: &str = "/var/lib/fimeyfim/central.conf";
pub const SPOOL: &str = "/var/log/fimeyfim/spool.tsv";
static LOCK: Mutex<()> = Mutex::new(());

fn hex(b: &[u8]) -> String { b.iter().map(|x| format!("{x:02x}")).collect() }
pub fn now() -> u64 { std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0) }
fn hmac(key: &[u8], msg: &[u8]) -> String {
    let mut k = [0u8; 64];
    if key.len() > 64 { k[..32].copy_from_slice(&Sha256::digest(key)); } else { k[..key.len()].copy_from_slice(key); }
    let ip: Vec<u8> = k.iter().map(|b| b ^ 0x36).collect();
    let op: Vec<u8> = k.iter().map(|b| b ^ 0x5c).collect();
    let mut h = Sha256::new(); h.update(&ip); h.update(msg); let inner = h.finalize();
    let mut h = Sha256::new(); h.update(&op); h.update(inner); hex(&h.finalize())
}
fn ct_eq(a: &str, b: &str) -> bool { a.len() == b.len() && a.bytes().zip(b.bytes()).fold(0u8, |r, (x, y)| r | (x ^ y)) == 0 }
fn kv(path: &str) -> BTreeMap<String, String> {
    fs::read_to_string(path).unwrap_or_default().lines().filter_map(|l| l.split_once('=')).map(|(k, v)| (k.trim().to_string(), v.trim().to_string())).collect()
}
fn put(path: &str, s: &str, append: bool) {
    if let Ok(mut f) = fs::OpenOptions::new().create(true).write(true).append(append).truncate(!append).mode(0o600).open(path) { let _ = f.write_all(s.as_bytes()); }
}
fn rnd(n: usize) -> String { let mut b = vec![0u8; n]; let _ = fs::File::open("/dev/urandom").and_then(|mut f| f.read_exact(&mut b)); hex(&b) }
fn safe(s: &str) -> bool { !s.is_empty() && s.len() <= 64 && s.chars().all(|c| c.is_ascii_alphanumeric() || "-_.".contains(c)) }

// ---------------- agent side ----------------
pub struct Agent { pub host: String, pub secret: String, pub name: String }
pub fn agent() -> Option<Agent> {
    let c = kv(CONF);
    let mut host = c.get("url")?.strip_prefix("http://")?.trim_end_matches('/').to_string();
    if !host.contains(':') { host += ":80"; }
    let h = fs::read_to_string("/etc/hostname").unwrap_or_default().trim().to_string();
    let name = c.get("name").cloned().filter(|n| safe(n)).unwrap_or_else(|| if safe(&h) { h } else { "agent".into() });
    Some(Agent { host, secret: c.get("secret")?.clone(), name })
}
pub fn save_conf(url: &str, secret: &str, name: &str) -> std::io::Result<()> {
    put(CONF, &format!("url={url}\nsecret={secret}\nname={name}\n"), false);
    if fs::metadata(CONF).is_ok() { Ok(()) } else { Err(std::io::Error::new(std::io::ErrorKind::Other, "cannot write central.conf")) }
}
fn http(host: &str, method: &str, path: &str, hdrs: &[(&str, String)], body: &[u8]) -> Option<(u16, String)> {
    let addr = host.to_socket_addrs().ok()?.next()?;
    let mut s = TcpStream::connect_timeout(&addr, Duration::from_secs(3)).ok()?;
    let _ = s.set_read_timeout(Some(Duration::from_secs(5)));
    let _ = s.set_write_timeout(Some(Duration::from_secs(5)));
    let mut req = format!("{method} {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\nContent-Length: {}\r\n", body.len());
    for (k, v) in hdrs { req += &format!("{k}: {v}\r\n"); }
    req += "\r\n";
    s.write_all(req.as_bytes()).ok()?; s.write_all(body).ok()?;
    let mut r = Vec::new(); s.read_to_end(&mut r).ok()?;
    let t = String::from_utf8_lossy(&r).to_string();
    Some((t.get(9..12)?.parse().ok()?, t.split("\r\n\r\n").nth(1).unwrap_or("").to_string()))
}
fn signed(a: &Agent, method: &str, path: &str, body: &str) -> Option<(u16, String)> {
    let ts = now().to_string();
    let sig = hmac(a.secret.as_bytes(), format!("{method} {path}\n{}\n{ts}\n{body}", a.name).as_bytes());
    http(&a.host, method, path, &[("X-Agent", a.name.clone()), ("X-Ts", ts), ("X-Sig", sig)], body.as_bytes())
}
fn sent(a: &Agent, line: &str) -> bool { matches!(signed(a, "POST", "/api/alert", line), Some((200, _))) }
pub fn forward(line: &str) {
    let line = line.trim_end().to_string();
    std::thread::spawn(move || {
        let Some(a) = agent() else { return };
        if !sent(&a, &line) { let _g = LOCK.lock(); put(SPOOL, &format!("{line}\n"), true); }
    });
}
pub fn pending() -> usize { fs::read_to_string(SPOOL).map(|s| s.lines().count()).unwrap_or(0) }
pub fn flush() {
    let Some(a) = agent() else { return };
    let _g = LOCK.lock();
    let Ok(s) = fs::read_to_string(SPOOL) else { return };
    let keep: String = s.lines().filter(|l| !sent(&a, l)).map(|l| format!("{l}\n")).collect();
    put(SPOOL, &keep, false);
}
pub fn ping(files: usize) -> Option<u16> { let a = agent()?; signed(&a, "POST", "/api/heartbeat", &format!("{files}\t{}", super::VER)).map(|(c, _)| c) }
pub fn heartbeat(files: usize) { std::thread::spawn(move || { if ping(files).is_some() { flush(); } }); }
pub fn policy() -> Option<Vec<(String, String)>> {
    let a = agent()?;
    match signed(&a, "GET", "/api/policy", "")? { (200, b) => Some(b.lines().filter_map(|l| l.split_once('\t')).map(|(k, v)| (k.to_string(), v.to_string())).collect()), _ => None }
}

// ---------------- server side ----------------
struct St { seen: HashSet<String>, agents: BTreeMap<String, (u64, String)> }
fn srv_conf() -> String { std::env::var("FIM_CENTRAL_CONF").unwrap_or_else(|_| "/etc/fimeyfim-central.conf".into()) }
pub fn server_init() {
    let p = srv_conf();
    if std::path::Path::new(&p).exists() { return println!("{p} already exists (delete it to generate new keys)."); }
    let (secret, token) = (rnd(32), rnd(16));
    put(&p, &format!("secret={secret}\ntoken={token}\nport=8443\nbind=0.0.0.0\ndata=/var/lib/fimeyfim-central\n"), false);
    println!("Created {p}\n\nAgent secret : {secret}\nAdmin token  : {token}\n\nOn every agent:  fim central set http://<this-server>:8443 {secret}\nDashboard    :  http://<this-server>:8443/?token={token}\nPolicy file  :  /var/lib/fimeyfim-central/policy.txt   (lines: <agent|all> <file|dir|tfc> <path>)\nStart server :  fimeyfim --server   (or the systemd unit in contrib/)");
}
pub fn server() {
    let c = kv(&srv_conf());
    let (Some(secret), Some(token)) = (c.get("secret").cloned(), c.get("token").cloned()) else { return eprintln!("Not configured. Run: fimeyfim --server-init") };
    let data = c.get("data").cloned().unwrap_or_else(|| "/var/lib/fimeyfim-central".into());
    let addr = format!("{}:{}", c.get("bind").map(|s| s.as_str()).unwrap_or("0.0.0.0"), c.get("port").map(|s| s.as_str()).unwrap_or("8443"));
    let _ = fs::create_dir_all(&data);
    let mut st = St { seen: HashSet::new(), agents: BTreeMap::new() };
    for l in fs::read_to_string(format!("{data}/alerts.tsv")).unwrap_or_default().lines() {
        let f: Vec<&str> = l.splitn(5, '\t').collect();
        if f.len() > 4 { st.seen.insert(format!("{}|{}|{}", f[1], f[2], f[3])); }
    }
    for l in fs::read_to_string(format!("{data}/agents.tsv")).unwrap_or_default().lines() {
        let f: Vec<&str> = l.splitn(3, '\t').collect();
        if f.len() == 3 { st.agents.insert(f[0].into(), (f[1].parse().unwrap_or(0), f[2].into())); }
    }
    let l = match TcpListener::bind(&addr) { Ok(l) => l, Err(e) => return eprintln!("cannot bind {addr}: {e}") };
    println!("FIMEY-FIM central listening on http://{addr} (data: {data})");
    let st = Arc::new(Mutex::new(st));
    for s in l.incoming().flatten() {
        let (st, secret, token, data) = (st.clone(), secret.clone(), token.clone(), data.clone());
        std::thread::spawn(move || handle(s, &secret, &token, &data, &st));
    }
}
fn reply(s: &mut TcpStream, code: u16, ctype: &str, body: &str) {
    let r = match code { 200 => "OK", 400 => "Bad Request", 401 => "Unauthorized", 404 => "Not Found", 413 => "Payload Too Large", _ => "Error" };
    let _ = write!(s, "HTTP/1.1 {code} {r}\r\nContent-Type: {ctype}\r\nContent-Length: {}\r\nConnection: close\r\nX-Content-Type-Options: nosniff\r\n\r\n{body}", body.len());
}
fn handle(mut s: TcpStream, secret: &str, token: &str, data: &str, st: &Mutex<St>) {
    let _ = s.set_read_timeout(Some(Duration::from_secs(5)));
    let (mut buf, mut tmp) = (Vec::new(), [0u8; 4096]);
    let hend = loop {
        if let Some(i) = buf.windows(4).position(|w| w == b"\r\n\r\n") { break i; }
        if buf.len() > 16384 { return; }
        match s.read(&mut tmp) { Ok(0) | Err(_) => return, Ok(n) => buf.extend_from_slice(&tmp[..n]) }
    };
    let head = String::from_utf8_lossy(&buf[..hend]).to_string();
    let mut rl = head.lines().next().unwrap_or("").split_whitespace();
    let (method, full) = (rl.next().unwrap_or("").to_string(), rl.next().unwrap_or("").to_string());
    let hdr = |n: &str| head.lines().skip(1).find_map(|l| l.split_once(':').filter(|(k, _)| k.trim().eq_ignore_ascii_case(n)).map(|(_, v)| v.trim().to_string())).unwrap_or_default();
    let clen: usize = hdr("content-length").parse().unwrap_or(0);
    if clen > 65536 { return reply(&mut s, 413, "text/plain", "too large"); }
    let mut body = buf[hend + 4..].to_vec();
    while body.len() < clen { match s.read(&mut tmp) { Ok(0) | Err(_) => break, Ok(n) => body.extend_from_slice(&tmp[..n]) } }
    let body = String::from_utf8_lossy(&body).to_string();
    let (path, query) = full.split_once('?').unwrap_or((&full, ""));
    if path.starts_with("/api/") {
        let (agent, ts, sig) = (hdr("x-agent"), hdr("x-ts"), hdr("x-sig"));
        let want = hmac(secret.as_bytes(), format!("{method} {path}\n{agent}\n{ts}\n{body}").as_bytes());
        if !safe(&agent) || now().abs_diff(ts.parse().unwrap_or(0)) > 600 || !ct_eq(&want, &sig) { return reply(&mut s, 401, "text/plain", "unauthorized"); }
        match (method.as_str(), path) {
            ("POST", "/api/alert") => {
                let line = body.trim_end();
                let f: Vec<&str> = line.split('\t').collect();
                if f.len() != 12 { return reply(&mut s, 400, "text/plain", "bad record"); }
                let mut g = st.lock().unwrap();
                if g.seen.insert(format!("{agent}|{}|{}", f[0], f[1])) { put(&format!("{data}/alerts.tsv"), &format!("{}\t{agent}\t{line}\n", now()), true); }
                reply(&mut s, 200, "text/plain", "ok")
            }
            ("POST", "/api/heartbeat") => {
                let mut g = st.lock().unwrap();
                g.agents.insert(agent, (now(), body.replace('\n', " ")));
                put(&format!("{data}/agents.tsv"), &g.agents.iter().map(|(a, (t, i))| format!("{a}\t{t}\t{i}\n")).collect::<String>(), false);
                reply(&mut s, 200, "text/plain", "ok")
            }
            ("GET", "/api/policy") => {
                let out: String = fs::read_to_string(format!("{data}/policy.txt")).unwrap_or_default().lines().filter_map(|l| {
                    let mut p = l.trim().splitn(3, ' ');
                    let (a, k, v) = (p.next()?, p.next()?, p.next()?);
                    if (a == "all" || a == agent) && ["file", "dir", "tfc"].contains(&k) { Some(format!("{k}\t{v}\n")) } else { None }
                }).collect();
                reply(&mut s, 200, "text/plain", &out)
            }
            _ => reply(&mut s, 404, "text/plain", "not found"),
        }
    } else if path == "/" || path == "/export.tsv" {
        let q = query.split('&').find_map(|p| p.strip_prefix("token=")).unwrap_or("").to_string();
        if !ct_eq(&q, token) && !ct_eq(hdr("authorization").trim_start_matches("Bearer "), token) { return reply(&mut s, 401, "text/plain", "admin token required: /?token=<token>"); }
        let alerts = fs::read_to_string(format!("{data}/alerts.tsv")).unwrap_or_default();
        if path == "/export.tsv" { return reply(&mut s, 200, "text/tab-separated-values", &alerts); }
        let page = dashboard(&alerts, &st.lock().unwrap().agents);
        reply(&mut s, 200, "text/html; charset=utf-8", &page)
    } else { reply(&mut s, 404, "text/plain", "not found") }
}
fn esc(s: &str) -> String { s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('"', "&quot;") }
fn fmt(t: u64) -> String { chrono::DateTime::from_timestamp(t as i64, 0).map(|d| d.format("%Y-%m-%d %H:%M:%S UTC").to_string()).unwrap_or_default() }
fn dashboard(alerts: &str, agents: &BTreeMap<String, (u64, String)>) -> String {
    let n = now();
    let mut h = String::from("<!doctype html><meta charset=utf-8><meta http-equiv=refresh content=15><title>FIMEY-FIM Central</title><style>body{font:14px system-ui;background:#0d1117;color:#e6edf3;margin:20px}h1{font-size:22px}table{border-collapse:collapse;width:100%;margin-bottom:24px}td,th{border:1px solid #30363d;padding:5px 8px;text-align:left;font-size:12px;word-break:break-all}th{background:#161b22}.bad{color:#ff7b72;font-weight:bold}.ok{color:#3fb950;font-weight:bold}.w{color:#d29922;font-weight:bold}</style><h1>FIMEY-FIM Central</h1><h2>Agents</h2><table><tr><th>Agent</th><th>Last seen</th><th>Status</th><th>Protected files</th><th>Version</th></tr>");
    for (a, (t, info)) in agents {
        let off = n.saturating_sub(*t) > 300;
        let mut i = info.split('\t');
        h += &format!("<tr><td>{}</td><td>{}</td><td class={}>{}</td><td>{}</td><td>{}</td></tr>", esc(a), fmt(*t), if off { "bad" } else { "ok" }, if off { "OFFLINE" } else { "ONLINE" }, esc(i.next().unwrap_or("")), esc(i.next().unwrap_or("")));
    }
    h += "</table><h2>Alerts (newest first, last 300). Full export: /export.tsv?token=...</h2><table><tr><th>Received</th><th>Agent</th><th>Time</th><th>Action</th><th>File path</th><th>Before hash</th><th>After hash</th><th>Process</th><th>TFC status</th><th>TFC path</th></tr>";
    for l in alerts.lines().rev().take(300) {
        let f: Vec<&str> = l.split('\t').collect();
        if f.len() < 14 { continue; }
        h += &format!("<tr><td>{}</td><td>{}</td><td>{}</td><td class={}>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>",
            fmt(f[0].parse().unwrap_or(0)), esc(f[1]), esc(f[3]), if f[4] == "FILE-CHANGE" { "bad" } else { "w" }, esc(super::label(f[4])), esc(f[6]), esc(f[7]), esc(f[8]), esc(f[9]), esc(f[10]), esc(f[11]));
    }
    h + "</table>"
}
