use inotify::{EventMask, Inotify, WatchDescriptor, WatchMask};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::ffi::CString;
use std::fs;
use std::io::{self, BufRead, Read, Seek, SeekFrom, Write};
use std::os::raw::{c_char, c_int, c_void};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::os::unix::io::AsRawFd;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

const VER: &str = env!("CARGO_PKG_VERSION");
const STATE: &str = "/var/lib/fimeyfim";
const PID: &str = "/var/lib/fimeyfim/daemon.pid";
const LOGDIR: &str = "/var/log/fimeyfim";
const LOG: &str = "/var/log/fimeyfim/alerts.log";
const DELETED: &str = "/var/log/fimeyfim/deleted.log";
const BIN: &str = "/usr/local/bin/fimeyfim";
const UNIT: &str = "/etc/systemd/system/fimeyfim.service";
const RECHECK_SECS: i32 = 120;

// ---------- helpers ----------
fn hex(b: &[u8]) -> String { b.iter().map(|x| format!("{x:02x}")).collect() }
fn sha_str(s: &str) -> String { hex(&Sha256::digest(s.as_bytes())) }
fn sha_file(p: &Path) -> io::Result<String> {
    let mut f = fs::File::open(p)?;
    let mut h = Sha256::new();
    let mut b = [0u8; 65536];
    loop { let n = f.read(&mut b)?; if n == 0 { break; } h.update(&b[..n]); }
    Ok(hex(&h.finalize()))
}
fn vault(p: &str) -> String { format!("{STATE}/vault/{}", sha_str(p)) }
fn sysctl(a: &[&str]) -> bool { Command::new("systemctl").args(a).stdout(Stdio::null()).stderr(Stdio::null()).status().map(|s| s.success()).unwrap_or(false) }
fn rep(r: io::Result<()>, ok: &str) { match r { Ok(_) => println!("{} {ok}", paint("32", "[+]")), Err(e) => err(&e.to_string()) } }
fn err(s: &str) { println!("{} {s}", paint("31", "[-]")); }
fn info(s: &str) { println!("{} {s}", paint("34", "[*]")); }
fn paint(code: &str, s: &str) -> String { if unsafe { libc::isatty(1) } == 1 { format!("\x1b[{code}m{s}\x1b[0m") } else { s.to_string() } }
fn write_private(path: &str, data: &[u8]) -> io::Result<()> {
    let mut f = fs::OpenOptions::new().write(true).create(true).truncate(true).mode(0o600).open(path)?;
    f.write_all(data)?; f.sync_all()
}
fn copy_private(src: &str, dst: &str) -> io::Result<()> {
    let mut i = fs::File::open(src)?;
    let mut o = fs::OpenOptions::new().write(true).create(true).truncate(true).mode(0o600).open(dst)?;
    io::copy(&mut i, &mut o)?; o.sync_all()
}
fn bad_name(s: &str) -> bool { s.contains('\n') || s.contains('\t') || s.contains('\r') }
fn sleep(ms: u64) { std::thread::sleep(std::time::Duration::from_millis(ms)); }

// ---------- system-password authentication (PAM: same password as sudo/su) ----------
#[repr(C)] struct PamMsg { style: c_int, msg: *const c_char }
#[repr(C)] struct PamResp { resp: *mut c_char, rc: c_int }
#[repr(C)] struct PamConv { f: extern "C" fn(c_int, *mut *const PamMsg, *mut *mut PamResp, *mut c_void) -> c_int, data: *mut c_void }
#[link(name = ":libpam.so.0", kind = "dylib")]
extern "C" {
    fn pam_start(svc: *const c_char, user: *const c_char, conv: *const PamConv, h: *mut *mut c_void) -> c_int;
    fn pam_authenticate(h: *mut c_void, flags: c_int) -> c_int;
    fn pam_acct_mgmt(h: *mut c_void, flags: c_int) -> c_int;
    fn pam_end(h: *mut c_void, status: c_int) -> c_int;
}
extern "C" fn pam_cb(n: c_int, msgs: *mut *const PamMsg, out: *mut *mut PamResp, data: *mut c_void) -> c_int {
    unsafe {
        let r = libc::calloc(n as usize, std::mem::size_of::<PamResp>()) as *mut PamResp;
        if r.is_null() { return 5; }
        for i in 0..n as isize {
            let st = (**msgs.offset(i)).style;
            if st == 1 || st == 2 { (*r.offset(i)).resp = libc::strdup(data as *const c_char); }
        }
        *out = r;
    }
    0
}
fn pam_check(user: &str, pw: &str) -> bool {
    let (Ok(u), Ok(p)) = (CString::new(user), CString::new(pw)) else { return false };
    let svc = CString::new(if Path::new("/etc/pam.d/sudo").exists() { "sudo" } else { "login" }).unwrap();
    let conv = PamConv { f: pam_cb, data: p.as_ptr() as *mut c_void };
    let mut h: *mut c_void = std::ptr::null_mut();
    unsafe {
        if pam_start(svc.as_ptr(), u.as_ptr(), &conv, &mut h) != 0 { return false; }
        let ok = pam_authenticate(h, 0) == 0 && pam_acct_mgmt(h, 0) == 0;
        pam_end(h, 0);
        ok
    }
}
fn auth() -> bool {
    let user = std::env::var("SUDO_USER").ok().filter(|u| !u.is_empty()).unwrap_or_else(|| "root".into());
    for _ in 0..3 {
        let pw = rpassword::prompt_password(format!("[fimeyfim] password for {user}: ")).unwrap_or_default();
        if pam_check(&user, &pw) { return true; }
        println!("Sorry, try again.");
    }
    false
}
fn confirm(q: &str) -> bool {
    print!("{q} [y/N]: "); let _ = io::stdout().flush();
    let mut s = String::new(); let _ = io::stdin().read_line(&mut s);
    s.trim().eq_ignore_ascii_case("y")
}

// ---------- state ----------
struct Conf { tfc: Option<String>, bin: String }
fn load_conf() -> Option<Conf> {
    let s = fs::read_to_string(format!("{STATE}/conf")).ok()?;
    let mut c = Conf { tfc: None, bin: String::new() };
    for l in s.lines() { match l.split_once('=') { Some(("tfc", v)) => c.tfc = Some(v.into()), Some(("bin", v)) => c.bin = v.into(), _ => {} } }
    Some(c)
}
fn save_atomic(name: &str, data: String) -> io::Result<()> {
    let t = format!("{STATE}/{name}.tmp");
    write_private(&t, data.as_bytes())?;
    fs::rename(t, format!("{STATE}/{name}"))
}
fn save_conf(c: &Conf) -> io::Result<()> {
    let mut s = format!("version=3\nbin={}\n", c.bin);
    if let Some(t) = &c.tfc { s += &format!("tfc={t}\n"); }
    save_atomic("conf", s)
}
fn load_db() -> io::Result<BTreeMap<String, String>> {
    let s = match fs::read_to_string(format!("{STATE}/db")) {
        Ok(s) => s, Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(BTreeMap::new()), Err(e) => return Err(e),
    };
    let mut m = BTreeMap::new();
    for l in s.lines() {
        let (h, p) = l.split_once('\t').ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "corrupt database line"))?;
        m.insert(p.to_string(), h.to_string());
    }
    Ok(m)
}
fn save_db(d: &BTreeMap<String, String>) -> io::Result<()> { save_atomic("db", d.iter().map(|(p, h)| format!("{h}\t{p}\n")).collect()) }

fn current(p: &str) -> String {
    match sha_file(Path::new(p)) {
        Ok(h) => h,
        Err(e) if e.kind() == io::ErrorKind::NotFound => "MISSING".into(),
        Err(e) => format!("UNREADABLE({:?})", e.kind()),
    }
}
fn state(p: &str, h: &str) -> String {
    let cur = current(p);
    if cur == h { "OK".into() } else if cur == "MISSING" || cur.starts_with("UNREADABLE") { cur.split('(').next().unwrap().into() } else { "MODIFIED".into() }
}

// ---------- alerting ----------
struct Rec { id: u32, ts: String, action: String, name: String, path: String, before: String, after: String, who: String, st: String, tpath: String, tname: String, tdir: String, closed: Option<(String, String)> }
fn clean(s: &str) -> String { s.replace(['\t', '\n', '\r'], " ") }
fn to_line(r: &Rec) -> String {
    [r.id.to_string(), r.ts.clone(), r.action.clone(), r.name.clone(), r.path.clone(), r.before.clone(), r.after.clone(), r.who.clone(), r.st.clone(), r.tpath.clone(), r.tname.clone(), r.tdir.clone()].join("\t") + "\n"
}
fn parse(l: &str) -> Option<Rec> {
    let f: Vec<&str> = l.split('\t').collect();
    if f.len() != 12 { return None; }
    Some(Rec { id: f[0].parse().ok()?, ts: f[1].into(), action: f[2].into(), name: f[3].into(), path: f[4].into(), before: f[5].into(), after: f[6].into(), who: f[7].into(), st: f[8].into(), tpath: f[9].into(), tname: f[10].into(), tdir: f[11].into(), closed: None })
}
fn load_alerts() -> Vec<Rec> {
    let mut v: Vec<Rec> = fs::read_to_string(LOG).unwrap_or_default().lines().filter_map(parse).collect();
    for l in fs::read_to_string(DELETED).unwrap_or_default().lines() {
        let f: Vec<&str> = l.split('\t').collect();
        if f.len() == 14 { if let Ok(id) = f[0].parse::<u32>() { if let Some(r) = v.iter_mut().find(|r| r.id == id) { r.closed = Some((f[12].into(), f[13].into())); } } }
    }
    v
}
fn label(a: &str) -> &str { match a { "WRITE-OPEN" => "FILE OPEN IN WRITE MODE", "FILE-CHANGE" => "FILE MODIFICATION", x => x } }
fn render(r: &Rec, color: bool) -> String {
    let act = label(&r.action);
    let state = match &r.closed { None => "ACTIVE".to_string(), Some((t, b)) => format!("CLOSED {t} by {b}") };
    let rows: Vec<(&str, String)> = vec![("Timestamp", r.ts.clone()), ("Action detected", act.into()), ("File name", r.name.clone()), ("File path", r.path.clone()),
        ("Before hash", r.before.clone()), ("After hash", r.after.clone()), ("Process", r.who.clone()), ("TFC status", r.st.clone()),
        ("TFC path", r.tpath.clone()), ("TFC file name", r.tname.clone()), ("TFC file directory", r.tdir.clone())];
    let lines: Vec<String> = rows.iter().map(|(k, v)| format!("{k:<19}: {v}")).collect();
    let title = format!(" ALERT #{} | {state} ", r.id);
    let w = lines.iter().map(|l| l.chars().count()).chain([title.chars().count()]).max().unwrap();
    let tc = if r.closed.is_some() { "32" } else if r.action == "WRITE-OPEN" { "1;33" } else { "1;31" };
    let t = if color { paint(tc, &title) } else { title.clone() };
    let mut o = format!("┌─{t}{}┐\n", "─".repeat(w + 1 - title.chars().count()));
    for l in &lines { o += &format!("│ {l:<w$} │\n"); }
    o + &format!("└{}┘", "─".repeat(w + 2))
}
fn fire(mut c: Command) { std::thread::spawn(move || { let _ = c.stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null()).status(); }); }
fn which(c: &str) -> bool { std::env::var("PATH").unwrap_or_default().split(':').chain(["/usr/bin", "/usr/local/bin", "/bin"]).any(|d| Path::new(d).join(c).exists()) }
fn sessions() -> Vec<(String, String)> {
    let mut v = vec![];
    if let Ok(rd) = fs::read_dir("/run/user") {
        for e in rd.flatten() {
            let uid = e.file_name().to_string_lossy().into_owned();
            if !Path::new(&format!("/run/user/{uid}/bus")).exists() { continue; }
            if let Ok(o) = Command::new("id").args(["-nu", &uid]).output() { let u = String::from_utf8_lossy(&o.stdout).trim().to_string(); if !u.is_empty() { v.push((uid, u)); } }
        }
    }
    v
}
// OS-level alert: terminal broadcast (wall) + desktop popup (notify-send, or zenity dialog) in every logged-in desktop session
fn notify(r: &Rec) {
    let mut w = Command::new("wall"); w.arg("-n").arg(render(r, false)); fire(w);
    let title = format!("FIMEY-FIM ALERT #{}: {}", r.id, label(&r.action));
    let body = format!("File: {}\nBefore: {}\nAfter: {}\nProcess: {}\nTFC: {} {}", r.path, r.before, r.after, r.who, r.st, r.tpath);
    for (uid, user) in sessions() {
        let home = fs::read_to_string("/etc/passwd").unwrap_or_default().lines().find_map(|l| { let f: Vec<&str> = l.split(':').collect(); (f.len() > 5 && f[0] == user).then(|| f[5].to_string()) }).unwrap_or_default();
        let xa = [format!("/run/user/{uid}/gdm/Xauthority"), format!("{home}/.Xauthority")].into_iter().find(|p| Path::new(p).exists()).unwrap_or_default();
        let mut n = Command::new("runuser");
        n.args(["-u", &user, "--", "env", &format!("DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/{uid}/bus"), &format!("XDG_RUNTIME_DIR=/run/user/{uid}"), "DISPLAY=:0"]);
        if !xa.is_empty() { n.arg(format!("XAUTHORITY={xa}")); }
        if which("notify-send") { n.args(["notify-send", "-u", "critical", "-a", "FIMEY-FIM", "-i", "dialog-warning", &title, &body]); }
        else if which("zenity") { n.args(["zenity", "--warning", "--width=520", "--title", &title, "--text", &body]); }
        else { continue; }
        fire(n);
    }
}
// action: WRITE-OPEN or FILE-CHANGE. TFC copy = baseline original, stored as <tfc>/<ext>/<name>_tfc_copy.<ext>
fn alert(c: &Conf, kind: &str, p: &str, before: &str, after: &str, who: &str) {
    let ts = chrono::Local::now();
    let path = Path::new(p);
    let name = path.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
    let (mut st, mut tpath, mut tname, mut tdir) = ("NOT CONFIGURED".to_string(), "-".to_string(), "-".to_string(), "-".to_string());
    if let Some(t) = &c.tfc {
        let stem = path.file_stem().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
        let ext = path.extension().map(|e| e.to_string_lossy().into_owned()).filter(|e| !e.is_empty());
        let dir = format!("{t}/{}", ext.as_ref().map(|e| e.to_lowercase()).unwrap_or_else(|| "noext".into()));
        let res = (|| -> io::Result<(String, String)> {
            fs::DirBuilder::new().recursive(true).mode(0o700).create(&dir)?;
            for n in 1u32.. {
                let sfx = if n == 1 { String::new() } else { format!("_{n}") };
                let fname = match &ext { Some(e) => format!("{stem}_tfc_copy{sfx}.{e}"), None => format!("{stem}_tfc_copy{sfx}") };
                let dst = format!("{dir}/{fname}");
                match sha_file(Path::new(&dst)) {
                    Ok(h) if h == before => return Ok((dir.clone(), fname)), // this original is already preserved
                    Ok(_) => continue,                                        // name taken by a different file
                    Err(e) if e.kind() == io::ErrorKind::NotFound => {
                        copy_private(&vault(p), &dst)?;
                        if sha_file(Path::new(&dst))? == before { return Ok((dir.clone(), fname)); }
                        let _ = fs::remove_file(&dst);
                        return Err(io::Error::new(io::ErrorKind::Other, "preserved copy hash mismatch"));
                    }
                    Err(e) => return Err(e),
                }
            }
            unreachable!()
        })();
        st = match res {
            Ok((d, f)) => { tpath = format!("{d}/{f}"); tdir = d; tname = f; "PRESERVED (hash verified)".to_string() }
            Err(e) => format!("FAILED ({e})"),
        };
    }
    let id = fs::read_to_string(LOG).map(|s| s.lines().count() as u32).unwrap_or(0) + 1;
    let r = Rec { id, ts: ts.format("%Y-%m-%d %H:%M:%S %z").to_string(), action: kind.into(), name, path: p.into(), before: before.into(), after: after.into(), who: clean(who), st, tpath, tname, tdir, closed: None };
    if let Ok(mut f) = fs::OpenOptions::new().create(true).append(true).mode(0o600).open(LOG) { let _ = f.write_all(to_line(&r).as_bytes()); }
    println!("{}", render(&r, true));
    let _ = io::stdout().flush();
    notify(&r);
}
fn check(c: &Conf, p: &str, base: &str, seen: &mut HashMap<String, String>, who: &str) {
    let cur = current(p);
    if cur == base { seen.remove(p); return; }
    if seen.get(p) == Some(&cur) { return; }
    seen.insert(p.into(), cur.clone());
    alert(c, "FILE-CHANGE", p, base, &cur, who);
}

// finds processes that currently hold a protected file open for writing
fn writers(db: &BTreeMap<String, String>) -> HashMap<String, (u32, String)> {
    let mut m = HashMap::new();
    let Ok(rd) = fs::read_dir("/proc") else { return m };
    let me = std::process::id();
    for e in rd.flatten() {
        let Some(pid) = e.file_name().to_str().and_then(|s| s.parse::<u32>().ok()) else { continue };
        if pid == me { continue; }
        let Ok(fds) = fs::read_dir(format!("/proc/{pid}/fd")) else { continue };
        for fd in fds.flatten() {
            let Ok(t) = fs::read_link(fd.path()) else { continue };
            let Some(ts) = t.to_str() else { continue };
            if !db.contains_key(ts) { continue; }
            let fl = fs::read_to_string(format!("/proc/{pid}/fdinfo/{}", fd.file_name().to_string_lossy())).ok()
                .and_then(|s| s.lines().find_map(|l| l.strip_prefix("flags:").and_then(|v| u32::from_str_radix(v.trim(), 8).ok()))).unwrap_or(0);
            if fl & 3 != 0 {
                let comm = fs::read_to_string(format!("/proc/{pid}/comm")).unwrap_or_default().trim().to_string();
                m.entry(ts.to_string()).or_insert((pid, comm));
            }
        }
    }
    m
}

// ---------- daemon ----------
fn watch_all(ino: &mut Inotify, db: &BTreeMap<String, String>, dirs: &mut HashMap<WatchDescriptor, PathBuf>, mask: WatchMask) {
    let mut nd = HashMap::new();
    for p in db.keys() {
        if let Some(d) = Path::new(p).parent() { if let Ok(wd) = ino.watches().add(d, mask) { nd.insert(wd, d.to_path_buf()); } }
    }
    for wd in dirs.keys() { if !nd.contains_key(wd) { let _ = ino.watches().remove(wd.clone()); } }
    *dirs = nd;
}

fn fa_mark(fa: i32, p: &str) { if let Ok(c) = CString::new(p) { unsafe { libc::fanotify_mark(fa, libc::FAN_MARK_ADD, libc::FAN_OPEN, libc::AT_FDCWD, c.as_ptr()); } } }
fn fa_events(fa: i32) -> Vec<(String, i32)> {
    let (mut out, mut buf) = (vec![], [0u8; 8192]);
    let hs = std::mem::size_of::<libc::fanotify_event_metadata>();
    loop {
        let n = unsafe { libc::read(fa, buf.as_mut_ptr() as *mut c_void, buf.len()) };
        if n <= 0 { break; }
        let (mut off, n) = (0usize, n as usize);
        while off + hs <= n {
            let m = unsafe { std::ptr::read_unaligned(buf.as_ptr().add(off) as *const libc::fanotify_event_metadata) };
            if (m.event_len as usize) < hs { break; }
            if m.fd >= 0 {
                if let Ok(p) = fs::read_link(format!("/proc/self/fd/{}", m.fd)) { out.push((p.to_string_lossy().into_owned(), m.pid)); }
                unsafe { libc::close(m.fd); }
            }
            off += m.event_len as usize;
        }
    }
    out
}
fn is_editor(c: &str) -> bool {
    const E: [&str; 32] = ["mousepad", "gedit", "gnome-text-edit", "nano", "pico", "vim", "vi", "nvim", "view", "gvim", "emacs", "kate", "kwrite", "xed", "pluma", "leafpad", "geany", "code", "codium", "micro", "joe", "ed", "subl", "sublime_text", "atom", "libreoffice", "soffice.bin", "featherpad", "l3afpad", "notepadqq", "textedit", "qtcreator"];
    E.iter().any(|e| c == *e || (e.len() > 4 && c.starts_with(e)) || c.starts_with("vim."))
}
fn daemon() {
    let mask = WatchMask::OPEN | WatchMask::CLOSE_WRITE | WatchMask::MOVED_TO | WatchMask::MOVED_FROM | WatchMask::DELETE | WatchMask::ATTRIB;
    let _ = fs::write(PID, std::process::id().to_string());
    let mut ino = Inotify::init().expect("inotify init");
    let sw = ino.watches().add(STATE, WatchMask::MOVED_TO | WatchMask::CLOSE_WRITE).expect("watch state dir");
    let fd = ino.as_raw_fd();
    let mut dirs: HashMap<WatchDescriptor, PathBuf> = HashMap::new();
    let (mut seen, mut wopen, mut lastw): (HashMap<String, String>, HashSet<String>, HashMap<String, String>) = Default::default();
    let (mut db, mut c) = (BTreeMap::new(), load_conf().expect("not initialized"));
    let fa = unsafe { libc::fanotify_init(libc::FAN_CLASS_NOTIF | libc::FAN_CLOEXEC | libc::FAN_NONBLOCK, (libc::O_RDONLY | libc::O_LARGEFILE) as u32) };
    if fa < 0 { eprintln!("fanotify unavailable: editor-open detection disabled"); }
    let me = std::process::id() as i32;
    let mut edit: HashMap<String, (std::time::Instant, String)> = HashMap::new();
    let mut recent: HashMap<String, (i32, String, std::time::Instant)> = HashMap::new();
    let (mut reload, mut buf) = (true, [0u8; 16384]);
    let internal = EventMask::MOVED_TO | EventMask::MOVED_FROM | EventMask::DELETE | EventMask::ATTRIB;
    loop {
        if reload {
            if let Some(n) = load_conf() { c = n; }
            match load_db() { Ok(d) => db = d, Err(e) => eprintln!("database load error (keeping previous): {e}") }
            watch_all(&mut ino, &db, &mut dirs, mask);
            if fa >= 0 { for p in db.keys() { fa_mark(fa, p); } }
            for (p, h) in &db { check(&c, p, h, &mut seen, "unknown"); } // startup / overflow / periodic full pass
            reload = false;
        }
        let mut pf = [libc::pollfd { fd, events: libc::POLLIN, revents: 0 }, libc::pollfd { fd: fa, events: libc::POLLIN, revents: 0 }];
        let r = unsafe { libc::poll(pf.as_mut_ptr(), 2, RECHECK_SECS * 1000) };
        if r == 0 { reload = true; continue; }
        if r < 0 { sleep(1000); continue; }
        if fa >= 0 && pf[1].revents & libc::POLLIN != 0 {
            for (p, pid) in fa_events(fa) {
                if pid == me { continue; }
                let Some(h) = db.get(&p) else { continue };
                let comm = fs::read_to_string(format!("/proc/{pid}/comm")).unwrap_or_default().trim().to_string();
                if !comm.is_empty() { recent.insert(p.clone(), (pid, comm.clone(), std::time::Instant::now())); }
                if !is_editor(&comm) { continue; }
                if edit.get(&p).map_or(false, |(t, w)| t.elapsed().as_secs() < 5 && w.starts_with(&format!("pid {pid} "))) { continue; }
                let w = format!("pid {pid} ({comm}) - file opened in an editor");
                alert(&c, "WRITE-OPEN", &p, h, &current(&p), &w);
                edit.insert(p, (std::time::Instant::now(), w));
            }
        }
        if pf[0].revents & libc::POLLIN == 0 { continue; }
        let evs: Vec<_> = match ino.read_events(&mut buf) {
            Ok(e) => e.map(|e| (e.wd, e.mask, e.name.map(|n| n.to_os_string()))).collect(),
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => continue,
            Err(_) => { sleep(1000); reload = true; continue; }
        };
        let mut opened = false;
        for (wd, m, name) in evs {
            if m.contains(EventMask::Q_OVERFLOW) || m.contains(EventMask::IGNORED) || wd == sw { reload = true; continue; }
            let (Some(d), Some(n)) = (dirs.get(&wd), name) else { continue };
            let p = d.join(n).to_string_lossy().into_owned();
            let Some(h) = db.get(&p) else { continue };
            if m.contains(EventMask::OPEN) { opened = true; }
            let writer = m.contains(EventMask::CLOSE_WRITE) || m.contains(EventMask::MOVED_TO);
            if writer && !wopen.remove(&p) {
                match edit.get(&p) {
                    Some((t, w)) if t.elapsed().as_secs() < 3600 => { lastw.insert(p.clone(), w.clone()); }
                    _ => {
                        let w = if m.contains(EventMask::MOVED_TO) { "unknown (file replaced by a writer)".to_string() } else { match recent.get(&p) { Some((pid, cm, t)) if t.elapsed().as_secs() < 5 => format!("pid {pid} ({cm}) [probable: last opener]"), _ => "unknown (opener exited before detection)".to_string() } };
                        alert(&c, "WRITE-OPEN", &p, h, &current(&p), &w);
                        lastw.insert(p.clone(), w);
                    }
                }
            }
            if m.contains(EventMask::MOVED_TO) && fa >= 0 { fa_mark(fa, &p); }
            if writer || !(m & internal).is_empty() {
                let w = lastw.get(&p).cloned().unwrap_or_else(|| "unknown".into());
                check(&c, &p, h, &mut seen, &w);
                if writer { lastw.remove(&p); edit.remove(&p); }
            }
        }
        if opened {
            for (p, (pid, comm)) in writers(&db) {
                if wopen.insert(p.clone()) {
                    let w = format!("pid {pid} ({comm})");
                    if let Some(h) = db.get(&p) { alert(&c, "WRITE-OPEN", &p, h, &current(&p), &w); }
                    lastw.insert(p, w);
                }
            }
        }
    }
}

fn running() -> Option<u32> {
    let p: u32 = fs::read_to_string(PID).ok()?.trim().parse().ok()?;
    let ok = unsafe { libc::kill(p as i32, 0) } == 0 && fs::read_to_string(format!("/proc/{p}/comm")).map(|s| s.trim() == "fimeyfim").unwrap_or(false);
    if ok { Some(p) } else { None }
}
fn spawn_daemon() {
    let mut cmd = Command::new(BIN);
    cmd.arg("--daemon").stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null());
    unsafe { cmd.pre_exec(|| { libc::setsid(); Ok(()) }); }
    let _ = cmd.spawn();
}
fn start_daemon() -> bool {
    if running().is_some() { return true; }
    sysctl(&["start", "fimeyfim"]); sleep(1000);
    if running().is_none() { spawn_daemon(); sleep(1000); }
    running().is_some()
}
fn stop_daemon() {
    sysctl(&["stop", "fimeyfim"]);
    if let Some(p) = running() { unsafe { libc::kill(p as i32, libc::SIGTERM); } }
    sleep(500);
}

// ---------- commands ----------
fn init() {
    let had = load_conf();
    let r = (|| -> io::Result<()> {
        fs::create_dir_all(format!("{STATE}/vault"))?;
        fs::create_dir_all(LOGDIR)?;
        fs::set_permissions(STATE, fs::Permissions::from_mode(0o700))?;
        fs::set_permissions(LOGDIR, fs::Permissions::from_mode(0o700))?;
        let exe = std::env::current_exe()?;
        if exe != Path::new(BIN) { let _ = fs::remove_file(BIN); fs::copy(&exe, BIN)?; fs::set_permissions(BIN, fs::Permissions::from_mode(0o755))?; }
        save_conf(&Conf { tfc: had.as_ref().and_then(|c| c.tfc.clone()), bin: format!("{};{}", exe_id(&exe), exe_id(Path::new(BIN))) })?;
        fs::write(UNIT, format!("[Unit]\nDescription=FIMEY-FIM File Integrity Monitor\nAfter=local-fs.target\n\n[Service]\nExecStart={BIN} --daemon\nRestart=always\nRestartSec=2\nMemoryMax=32M\n\n[Install]\nWantedBy=multi-user.target\n"))
    })();
    if let Err(e) = r { return err(&e.to_string()); }
    sysctl(&["daemon-reload"]);
    let boot = sysctl(&["enable", "fimeyfim"]);
    let up = start_daemon();
    let st = format!("Monitor: {}. Auto-start at boot: {}.", if up { "RUNNING" } else { "NOT RUNNING (try: fim start)" }, if boot { "enabled" } else { "NOT enabled (systemd unavailable)" });
    match had {
        Some(c) => println!("{} Reconnected. {} protected file(s) restored, TFC: {}. {st}", paint("32", "[+]"), load_db().map(|d| d.len()).unwrap_or(0), c.tfc.as_deref().unwrap_or("not configured")),
        None => { println!("{} Initialized. {st}", paint("32", "[+]")); info("Next (required): fim add -tfc <dir>   then add files with fim add -a / -all"); }
    }
}

fn uninit() {
    if !confirm("Disconnect FIMEY-FIM? Monitoring stops; protected-file records and the TFC setting are kept.") || !auth() { return info("Cancelled."); }
    stop_daemon(); sysctl(&["disable", "fimeyfim"]); let _ = fs::remove_file(UNIT); sysctl(&["daemon-reload"]);
    info("Disconnected. Records kept. Run 'fim init' to resume protection; previous files stay under FIM control.");
}

fn walk(d: &Path, out: &mut Vec<PathBuf>) {
    if let Ok(rd) = fs::read_dir(d) {
        for e in rd.flatten() { if let Ok(t) = e.file_type() { if t.is_file() { out.push(e.path()) } else if t.is_dir() { walk(&e.path(), out) } } }
    }
}

fn add_file(p: &Path, tfc: &str, db: &mut BTreeMap<String, String>) -> Result<Option<String>, String> {
    let p = fs::canonicalize(p).map_err(|e| format!("{}: {e}", p.display()))?;
    if !p.is_file() { return Err(format!("{}: not a regular file", p.display())); }
    let s = p.to_str().ok_or("path is not valid UTF-8")?.to_string();
    if bad_name(&s) { return Err(format!("{s}: unsupported characters in path")); }
    if !tfc.is_empty() && p.starts_with(tfc) { return Err(format!("{s}: inside the TFC directory")); }
    if db.contains_key(&s) { return Ok(None); }
    let h = sha_file(&p).map_err(|e| format!("{s}: {e}"))?;
    let v = vault(&s);
    copy_private(&s, &v).map_err(|e| format!("{s}: vault copy failed: {e}"))?;
    if sha_file(Path::new(&v)).map_err(|e| e.to_string())? != h { let _ = fs::remove_file(&v); return Err(format!("{s}: changed while being added, retry")); }
    db.insert(s.clone(), h);
    Ok(Some(s))
}

static QUIET: AtomicBool = AtomicBool::new(false);
static LAST: AtomicUsize = AtomicUsize::new(0);
fn hsize(n: u64) -> String { let u = ["B", "KB", "MB", "GB"]; let (mut v, mut i) = (n as f64, 0); while v >= 1024.0 && i < 3 { v /= 1024.0; i += 1; } if i == 0 { format!("{n} B") } else { format!("{v:.1} {}", u[i]) } }
fn table(h: &[&str], rows: &[Vec<String>]) {
    let w: Vec<usize> = (0..h.len()).map(|i| rows.iter().map(|r| r[i].chars().count()).chain([h[i].chars().count()]).max().unwrap()).collect();
    let rule = |a: &str, b: &str, c: &str| println!("{a}{}{c}", w.iter().map(|x| "─".repeat(x + 2)).collect::<Vec<_>>().join(b));
    rule("┌", "┬", "┐");
    println!("│{}│", h.iter().zip(&w).map(|(c, w)| paint("1", &format!(" {c:<w$} "))).collect::<Vec<_>>().join("│"));
    rule("├", "┼", "┤");
    for r in rows {
        println!("│{}│", r.iter().zip(&w).map(|(c, w)| { let p = format!(" {c:<w$} "); match c.as_str() { "OK" => paint("32", &p), "MODIFIED" | "MISSING" | "UNREADABLE" => paint("1;31", &p), _ => p } }).collect::<Vec<_>>().join("│"));
    }
    rule("└", "┴", "┘");
}
fn file_table(db: &BTreeMap<String, String>, st: bool) -> (usize, usize) {
    let (mut ok, mut bad) = (0, 0);
    let rows: Vec<Vec<String>> = db.iter().enumerate().map(|(i, (p, h))| {
        let name = Path::new(p).file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
        let mut r = vec![(i + 1).to_string()];
        if st { let s = state(p, h); if s == "OK" { ok += 1 } else { bad += 1 } r.push(s); }
        r.extend([name, fs::metadata(p).map(|m| hsize(m.len())).unwrap_or("-".into()), h.clone(), p.clone()]);
        r
    }).collect();
    let mut hd = vec!["NO"]; if st { hd.push("STATE"); }
    hd.extend(["FILE NAME", "SIZE", "SHA-256 (BASELINE)", "FILE PATH"]);
    table(&hd, &rows);
    (ok, bad)
}
fn exe_id(p: &Path) -> String {
    use std::os::unix::fs::MetadataExt;
    let Ok(m) = fs::metadata(p) else { return String::new() };
    let t = m.created().or_else(|_| m.modified()).ok().and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok()).map(|d| d.as_nanos()).unwrap_or(0);
    format!("{}|{}|{t}", p.display(), m.ino())
}
fn archive_old() -> Option<String> {
    let ts = chrono::Local::now().format("%Y%m%d%H%M%S").to_string();
    let m: Vec<String> = [STATE, LOGDIR].iter().filter(|d| Path::new(d).exists()).filter_map(|d| { let t = format!("{d}.archive-{ts}"); fs::rename(d, &t).ok().map(|_| t) }).collect();
    if m.is_empty() { None } else { Some(m.join(", ")) }
}
fn upgrade_self() {
    let Some(mut c) = load_conf() else { return err("Nothing installed to upgrade. Run: fim init") };
    let exe = std::env::current_exe().unwrap_or_default();
    stop_daemon();
    let r = (|| -> io::Result<()> { if exe != Path::new(BIN) { let _ = fs::remove_file(BIN); fs::copy(&exe, BIN)?; fs::set_permissions(BIN, fs::Permissions::from_mode(0o755))?; } Ok(()) })();
    match r {
        Ok(_) => { c.bin = format!("{};{}", exe_id(&exe), exe_id(Path::new(BIN))); let _ = save_conf(&c); info(if start_daemon() { "Upgraded; monitor running. Records kept." } else { "Upgraded; monitor not running (try: fim start)." }) }
        Err(e) => err(&e.to_string()),
    }
}
fn wipe_install() {
    stop_daemon(); sysctl(&["disable", "fimeyfim"]); let _ = fs::remove_file(UNIT); sysctl(&["daemon-reload"]); let _ = fs::remove_file(BIN);
    match archive_old() { Some(a) => info(&format!("Previous installation removed. Records archived for audit: {a}")), None => info("Previous installation removed.") }
}
// A copy of the tool that is not the configured one (deleted + re-downloaded), or records whose installed program is gone, means a new installation: start from scratch.
fn fresh_check() {
    let exe = std::env::current_exe().unwrap_or_default();
    let id = exe_id(&exe);
    let stale = match load_conf() { Some(c) => !Path::new(BIN).exists() || !c.bin.split(';').any(|i| i == id), None => Path::new(STATE).exists() || Path::new(LOGDIR).exists() };
    if stale { info("New installation detected (this copy is not the one that was configured)."); wipe_install(); info("Starting from scratch: run 'fim init', then 'fim add -tfc <dir>', then add your files."); }
}
fn clear_screen() {
    if !Command::new("clear").status().map(|s| s.success()).unwrap_or(false) { print!("\x1b[3J\x1b[H\x1b[2J"); }
    print!("\x1b[3J"); let _ = io::stdout().flush();
}
fn watcher() {
    LAST.store(load_alerts().len(), Ordering::SeqCst);
    std::thread::spawn(|| loop {
        sleep(1000);
        if QUIET.load(Ordering::SeqCst) { continue; }
        let a = load_alerts();
        let l = LAST.load(Ordering::SeqCst);
        if a.len() > l {
            for r in &a[l..] { print!("\r\x1b[K{} #{} {} {}\n", paint("1;31", "[!] NEW ALERT"), r.id, label(&r.action), r.path); }
            print!("{} > ", paint("1;4", "fimey")); let _ = io::stdout().flush();
        }
        LAST.store(a.len(), Ordering::SeqCst);
    });
}
fn getkey(ms: i32) -> Option<u8> {
    let mut old: libc::termios = unsafe { std::mem::zeroed() };
    let tty = unsafe { libc::tcgetattr(0, &mut old) } == 0;
    if tty { let mut t = old; unsafe { libc::cfmakeraw(&mut t); t.c_oflag |= libc::OPOST; libc::tcsetattr(0, libc::TCSANOW, &t); } }
    let mut p = libc::pollfd { fd: 0, events: libc::POLLIN, revents: 0 };
    let r = unsafe { libc::poll(&mut p, 1, ms) };
    let mut b = [0u8; 1];
    let n = if r > 0 { unsafe { libc::read(0, b.as_mut_ptr() as *mut c_void, 1) } } else if r == 0 { -2 } else { -1 };
    if tty { unsafe { libc::tcsetattr(0, libc::TCSANOW, &old); } }
    match n { 1 => Some(b[0]), -2 => Some(0), _ => None }
}
fn close_alerts(rs: &[&Rec]) {
    let by = std::env::var("SUDO_USER").unwrap_or_else(|_| "root".into());
    let ts = chrono::Local::now().format("%Y-%m-%d %H:%M:%S %z").to_string();
    if let Ok(mut f) = fs::OpenOptions::new().create(true).append(true).mode(0o600).open(DELETED) {
        for r in rs { let _ = f.write_all(format!("{}\t{ts}\t{by}\n", to_line(r).trim_end()).as_bytes()); }
    }
}
fn alerts_ui() {
    QUIET.store(true, Ordering::SeqCst);
    let (mut closed_tab, mut idx, mut sig, mut dirty) = (false, 0usize, String::new(), true);
    loop {
        let all = load_alerts();
        let nc = all.iter().filter(|r| r.closed.is_some()).count();
        let na = all.len() - nc;
        let sg = format!("{}/{nc}", all.len());
        let list: Vec<&Rec> = all.iter().rev().filter(|r| r.closed.is_some() == closed_tab).collect();
        if idx >= list.len() { idx = list.len().saturating_sub(1); }
        if dirty || sg != sig {
            let fresh = !dirty && !sig.is_empty();
            sig = sg; dirty = false;
            LAST.store(all.len(), Ordering::SeqCst);
            print!("\x1b[2J\x1b[H");
            println!("{}  {}   {}\n", paint(if closed_tab { "2" } else { "1;7" }, &format!(" ACTIVE ({na}) ")), paint(if closed_tab { "1;7" } else { "2" }, &format!(" CLOSED ({nc}) ")), paint("2", "auto-refresh every 2s"));
            if fresh { println!("{}\n", paint("1;31", "[!] Alert list updated")); }
            if list.is_empty() { println!("No {} alerts.", if closed_tab { "closed" } else { "active" }); }
            else {
                let st = idx / 8 * 8;
                let rows: Vec<Vec<String>> = list.iter().enumerate().skip(st).take(8).map(|(i, r)| vec![(if i == idx { "▶" } else { " " }).into(), format!("#{}", r.id), r.ts.clone(), label(&r.action).to_string(), r.path.clone(),
                    r.closed.as_ref().map(|(t, b)| format!("CLOSED {t} by {b}")).unwrap_or_else(|| "ACTIVE".into())]).collect();
                table(&["", "ID", "TIMESTAMP", "ACTION", "FILE PATH", "STATUS"], &rows);
                println!("Alert {}/{} (page {}/{})\n{}", idx + 1, list.len(), idx / 8 + 1, (list.len() + 7) / 8, render(list[idx], true));
            }
            println!("\n[n]ext [p]rev [a]ctive [c]losed [r]efresh {}[q]uit", if closed_tab { "" } else { "[x] close  [X] close all  " });
            print!("> "); let _ = io::stdout().flush();
        }
        match getkey(2000) {
            None | Some(b'q') | Some(b'Q') => break,
            Some(0) => {}
            Some(b'r') | Some(b'R') => dirty = true,
            Some(b'a') => { closed_tab = false; idx = 0; dirty = true; }
            Some(b'c') => { closed_tab = true; idx = 0; dirty = true; }
            Some(b'n') | Some(b' ') | Some(b'j') => { idx += 1; dirty = true; }
            Some(b'p') | Some(b'k') => { idx = idx.saturating_sub(1); dirty = true; }
            Some(b'x') if !closed_tab && !list.is_empty() => {
                println!("\n\nClosing alert #{} moves it to the CLOSED tab and records it in deleted.log (audit).", list[idx].id);
                if auth() { close_alerts(&[list[idx]]); }
                dirty = true;
            }
            Some(b'X') if !closed_tab && !list.is_empty() => {
                println!("\n\nClosing ALL {} active alert(s); they are recorded in deleted.log (audit).", list.len());
                if auth() { close_alerts(&list); }
                dirty = true;
            }
            _ => {}
        }
    }
    LAST.store(load_alerts().len(), Ordering::SeqCst);
    QUIET.store(false, Ordering::SeqCst);
    println!();
}
static STOP: AtomicBool = AtomicBool::new(false);
extern "C" fn on_int(_: c_int) { STOP.store(true, Ordering::SeqCst); }
fn follow() {
    info("Live alert feed. Press Ctrl-C to return to the prompt.");
    STOP.store(false, Ordering::SeqCst);
    unsafe { libc::signal(libc::SIGINT, on_int as libc::sighandler_t); }
    let mut pos = fs::metadata(LOG).map(|m| m.len()).unwrap_or(0);
    while !STOP.load(Ordering::SeqCst) {
        sleep(300);
        let len = fs::metadata(LOG).map(|m| m.len()).unwrap_or(0);
        if len < pos { pos = 0; }
        if len > pos {
            if let Ok(mut f) = fs::File::open(LOG) {
                let mut s = String::new();
                if f.seek(SeekFrom::Start(pos)).is_ok() && f.read_to_string(&mut s).is_ok() { for l in s.lines() { if let Some(r) = parse(l) { println!("{}", render(&r, true)); } } }
            }
            pos = len;
        }
    }
    unsafe { libc::signal(libc::SIGINT, libc::SIG_DFL); }
    println!();
}

const HELP: &str = "
  Core commands
  -------------
  fim init                          Install service, enable boot start
  fim -x init                       Disconnect: stop monitoring, keep records [password]
  fim uninstall                     Remove from host; next install starts fresh [password]
  fim add -a <file>                 Protect a file
  fim add -all <dir>                Protect every file in a directory
  fim remove -r <file>              Release a file from FIM control    [password]
  fim remove -all <dir>             Release a directory                [password]
  fim add -tfc <dir>                Set the Tampered File Copy dir     [password]
  fim change -tfc -s <old> -d <new> Move the TFC directory             [password]
  fim inspect all                   List protected files and hashes
  fim status                        Monitor status and file states
  fim verify                        Integrity verification pass
  fim start | fim stop              Start monitor / stop monitor       [stop: password]
  fim notify-test                   Send a test OS popup to verify alert delivery

  Console
  -------
  alerts        alert viewer (auto-refresh): [r] refresh [x] close [X] close all [q] quit
  audit         closed-alert audit table (ledger: deleted.log)
  monitor       live alert feed
  clear         clear the screen        banner    redraw banner
  exit | quit   leave (monitor keeps running in the background)

  Alerts: FILE OPEN IN WRITE MODE (also when an editor opens the file) and FILE MODIFICATION (hash changed).
  Both preserve the original as <tfc>/<ext>/<name>_tfc_copy.<ext> and raise an OS popup.
";

fn banner() {
    let n = load_db().map(|d| d.len()).unwrap_or(0);
    let al = load_alerts().iter().filter(|r| r.closed.is_none()).count();
    let mon = match running() { Some(p) => paint("32", &format!("RUNNING (pid {p})")), None => paint("31", "NOT RUNNING") };
    let tfc = load_conf().and_then(|c| c.tfc).unwrap_or_else(|| "not configured".into());
    println!("{}", paint("1;31", r#"
  _____ ___ __  __ _____ __   __     _____ ___ __  __
 |  ___|_ _|  \/  | ____|\ \ / /    |  ___|_ _|  \/  |
 | |_   | || |\/| |  _|   \ V /_____| |_   | || |\/| |
 |  _|  | || |  | | |___   | |______|  _|  | || |  | |
 |_|   |___|_|  |_|_____|  |_|       |_|   |___|_|  |_|
"#));
    println!("       =[ {} v{VER} - File Integrity Monitor + Tampered File Copy ]", paint("1", "FIMEY-FIM"));
    println!("+ -- --=[ {n} protected file(s) | {al} active alert(s)");
    println!("+ -- --=[ monitor: {mon} | TFC: {tfc}");
    println!("+ -- --=[ detects: write-open + file alteration | SHA-256 | systemd boot start\n");
    match load_conf() {
        None => println!("{} Not configured yet. Run: fim init  then  fim add -tfc <dir>  then add files.\n", paint("1;33", "[!]")),
        Some(c) if c.tfc.is_none() => println!("{} TFC directory not set (required). Run: fim add -tfc <dir>\n", paint("1;33", "[!]")),
        _ => {}
    }
    println!("Type {} for commands. Sensitive actions ask for your system password.\n", paint("1", "help"));
}

fn run(a: &[&str]) {
    if unsafe { libc::geteuid() } != 0 { return err("run as root (sudo)."); }
    if a == ["fim", "init"] { return init(); }
    let Some(mut c) = load_conf() else { return err("Not initialized. Run: fim init") };
    let mut db = match load_db() { Ok(d) => d, Err(e) => return err(&format!("cannot read baseline database: {e}")) };
    match a {
        ["alerts"] => alerts_ui(),
        ["monitor"] => follow(),
        ["fim", "-x", "init"] => uninit(),
        ["fim", "start"] => info(if start_daemon() { "Monitor is running." } else { "Could not start the monitor." }),
        ["fim", "stop"] => { if !auth() { return info("Cancelled."); } stop_daemon(); info("Monitor stopped."); }
        ["fim", "uninstall"] => {
            if !confirm("Uninstall FIMEY-FIM from this host? Records are archived for audit; a new install starts from scratch.") || !auth() { return info("Cancelled."); }
            wipe_install();
        }
        ["fim", "add", "-a", f] => {
            if c.tfc.is_none() { return err("Set the Tampered File Copy directory first: fim add -tfc <dir>"); }
            let tfc = c.tfc.clone().unwrap_or_default();
            match add_file(Path::new(f), &tfc, &mut db) {
                Ok(Some(k)) => match save_db(&db) { Ok(_) => println!("{} Protected: {k}", paint("32", "[+]")), Err(e) => { let _ = fs::remove_file(vault(&k)); err(&e.to_string()) } },
                Ok(None) => info("Already protected; baseline unchanged."),
                Err(e) => err(&e),
            }
        }
        ["fim", "add", "-all", d] => {
            if c.tfc.is_none() { return err("Set the Tampered File Copy directory first: fim add -tfc <dir>"); }
            let Ok(d) = fs::canonicalize(d) else { return err("invalid directory") };
            if !d.is_dir() { return err("not a directory"); }
            let mut fl = vec![]; walk(&d, &mut fl);
            let tfc = c.tfc.clone().unwrap_or_default();
            let (mut new, mut skip, mut bad) = (vec![], 0, 0);
            for f in fl {
                if !tfc.is_empty() && f.starts_with(&tfc) { continue; }
                match add_file(&f, &tfc, &mut db) { Ok(Some(k)) => new.push(k), Ok(None) => skip += 1, Err(e) => { bad += 1; err(&e) } }
            }
            match save_db(&db) {
                Ok(_) => println!("{} Added {} file(s), {skip} already protected, {bad} error(s).", paint("32", "[+]"), new.len()),
                Err(e) => { for k in &new { let _ = fs::remove_file(vault(k)); } err(&e.to_string()) }
            }
        }
        ["fim", "remove" | "release", "-r", f] | ["fim", "release", f] => {
            let p = fs::canonicalize(f).map(|p| p.to_string_lossy().into_owned()).unwrap_or(f.to_string());
            if !db.contains_key(&p) { return err("not under FIM control"); }
            if !confirm(&format!("Release {p} from FIM control?")) || !auth() { return info("Cancelled."); }
            db.remove(&p);
            match save_db(&db) { Ok(_) => { let _ = fs::remove_file(vault(&p)); info("Released.") } Err(e) => err(&format!("{e}; nothing changed")) }
        }
        ["fim", "remove" | "release", "-all", d] => {
            let pre = format!("{}/", fs::canonicalize(d).map(|p| p.to_string_lossy().into_owned()).unwrap_or(d.to_string()).trim_end_matches('/'));
            let keys: Vec<String> = db.keys().filter(|k| k.starts_with(&pre)).cloned().collect();
            if keys.is_empty() { return err("nothing under that directory is protected"); }
            if !confirm(&format!("Release {} file(s) under {pre}?", keys.len())) || !auth() { return info("Cancelled."); }
            for k in &keys { db.remove(k); }
            match save_db(&db) {
                Ok(_) => { for k in &keys { let _ = fs::remove_file(vault(k)); } info(&format!("Released {} file(s).", keys.len())) }
                Err(e) => err(&format!("{e}; nothing changed")),
            }
        }
        ["fim", "add", "-tfc", d] => match fs::canonicalize(d) {
            Ok(p) if p.is_dir() => {
                let s = p.to_string_lossy().into_owned();
                if bad_name(&s) { return err("unsupported characters in path"); }
                if db.keys().any(|k| Path::new(k).starts_with(&p)) { return err("protected files exist inside that directory"); }
                if !auth() { return info("Cancelled."); }
                c.tfc = Some(s);
                rep(save_conf(&c), &format!("TFC directory set: {}", p.display()));
            }
            _ => err("invalid directory"),
        },
        ["fim", "change", "-tfc", "-s", s, "-d", d] => {
            if fs::create_dir_all(d).is_err() { return err("invalid destination"); }
            let (Ok(s), Ok(d)) = (fs::canonicalize(s), fs::canonicalize(d)) else { return err("invalid path") };
            if c.tfc.as_deref() != Some(&*s.to_string_lossy()) { return err("source is not the current TFC directory"); }
            if d.starts_with(&s) || s.starts_with(&d) { return err("source and destination must not be nested"); }
            if bad_name(&d.to_string_lossy()) || db.keys().any(|k| Path::new(k).starts_with(&d)) { return err("unsuitable destination"); }
            if !auth() { return info("Cancelled."); }
            let mut fl = vec![]; walk(&s, &mut fl);
            for f in fl {
                let t = d.join(f.strip_prefix(&s).unwrap());
                if let Some(pp) = t.parent() { let _ = fs::create_dir_all(pp); }
                if fs::rename(&f, &t).is_err() && fs::copy(&f, &t).and_then(|_| fs::remove_file(&f)).is_err() { return err(&format!("moving {}; TFC setting unchanged", f.display())); }
            }
            c.tfc = Some(d.to_string_lossy().into_owned());
            rep(save_conf(&c), "TFC directory changed.");
        }
        ["fim", "inspect", "all"] => {
            let dirs: std::collections::HashSet<&Path> = db.keys().filter_map(|k| Path::new(k).parent()).collect();
            println!("{}\n  Generated : {}\n  TFC dir   : {}\n  Protected : {} file(s) in {} director(ies)\n", paint("1", "FIM INSPECTION REPORT"), chrono::Local::now().format("%Y-%m-%d %H:%M:%S %z"), c.tfc.as_deref().unwrap_or("not configured"), db.len(), dirs.len());
            if db.is_empty() { return info("Nothing is under FIM control."); }
            file_table(&db, false);
        }
        ["fim", "status"] => {
            let mon = match running() { Some(p) => format!("{} (pid {p})", paint("32", "RUNNING")), None => format!("{} (run: fim start)", paint("31", "NOT RUNNING")) };
            let act = load_alerts().iter().filter(|r| r.closed.is_none()).count();
            println!("{}\n  Monitoring    : {mon}\n  Boot start    : {}\n  TFC dir       : {}\n  Active alerts : {act}\n  Protected     : {} file(s)\n", paint("1", "FIM STATUS REPORT"), if sysctl(&["is-enabled", "fimeyfim"]) { "enabled" } else { "not enabled" }, c.tfc.as_deref().unwrap_or("not configured"), db.len());
            if db.is_empty() { return info("Nothing is under FIM control."); }
            let (ok, bad) = file_table(&db, true);
            println!("Summary: {ok} OK | {bad} not OK");
        }
        ["audit"] | ["fim", "audit"] => {
            let rows: Vec<Vec<String>> = load_alerts().iter().filter(|r| r.closed.is_some()).map(|r| { let (t, b) = r.closed.clone().unwrap(); vec![format!("#{}", r.id), r.ts.clone(), label(&r.action).to_string(), r.path.clone(), t, b] }).collect();
            println!("{}  ({} record(s); ledger: {DELETED})\n", paint("1", "CLOSED ALERT AUDIT"), rows.len());
            if rows.is_empty() { info("No closed alerts yet."); } else { table(&["ID", "ALERT TIME", "ACTION", "FILE PATH", "CLOSED AT", "CLOSED BY"], &rows); }
        }
        ["fim", "notify-test"] => {
            let r = Rec { id: 0, ts: chrono::Local::now().format("%Y-%m-%d %H:%M:%S %z").to_string(), action: "TEST".into(), name: "test.txt".into(), path: "/tmp/test.txt".into(), before: "-".into(), after: "-".into(), who: "fim notify-test".into(), st: "TEST".into(), tpath: "-".into(), tname: "-".into(), tdir: "-".into(), closed: None };
            println!("{}", render(&r, true)); notify(&r);
            let yn = |b: bool| if b { "yes" } else { "NO" };
            println!("notify-send: {} | zenity: {} | wall: {} | desktop sessions: {}", yn(which("notify-send")), yn(which("zenity")), yn(which("wall")), sessions().len());
            if sessions().is_empty() { info("No logged-in desktop session found; popups need a graphical login."); }
        }
        ["fim", "verify"] => {
            let mut bad = 0;
            for (p, h) in &db { let s = state(p, h); if s != "OK" { bad += 1; println!("{}: {p}\n  before={h}\n  after ={}", paint("31", &s), current(p)); } }
            println!("Verified {} file(s): {} violation(s).", db.len(), bad);
        }
        _ => err("Unknown or malformed command. Type 'help'."),
    }
}

fn main() {
    let a: Vec<String> = std::env::args().skip(1).collect();
    if a.first().map(|s| s.as_str()) == Some("--daemon") { return daemon(); }
    if unsafe { libc::geteuid() } != 0 {
        eprintln!("FIMEY-FIM needs administrator privileges - elevating with sudo (enter your password)...");
        let e = Command::new("sudo").arg(std::env::current_exe().unwrap_or_default()).args(&a).exec();
        return eprintln!("cannot elevate: {e}");
    }
    if a.first().map(|s| s.as_str()) == Some("--upgrade") { return upgrade_self(); }
    fresh_check();
    if !a.is_empty() { let v: Vec<&str> = a.iter().map(|s| s.as_str()).collect(); return run(&v); }
    banner();
    watcher();
    let stdin = io::stdin();
    loop {
        print!("{} > ", paint("1;4", "fimey"));
        let _ = io::stdout().flush();
        let mut l = String::new();
        if stdin.lock().read_line(&mut l).unwrap_or(0) == 0 { break; }
        let t: Vec<&str> = l.split_whitespace().collect();
        match t.as_slice() {
            [] => {}
            ["exit"] | ["quit"] => break,
            ["help"] | ["?"] => println!("{HELP}"),
            ["clear"] | ["cls"] => clear_screen(),
            ["banner"] => banner(),
            a => { QUIET.store(true, Ordering::SeqCst); run(a); QUIET.store(false, Ordering::SeqCst); }
        }
    }
}
