// The broker: the power structure as a machine, not a policy.
//
// Intelligence proposes; the owner disposes. Every action an
// unprivileged proposer (the model service, a grown program, a
// script) wants performed passes through here, and the broker
// classifies it by its own table - the proposer cannot relabel an
// action to slip its class.
//
// - routine actions execute on proposal. They are the owner's
//   standing orders, listed in the table below.
// - consequential actions run the two-attempt sequence the charter
//   prescribes. The first proposal is answered with a warning and
//   nothing happens. The warning is a signed receipt: the proposer
//   cannot later claim it was never warned, and cannot forge one.
//   The action then executes only when the owner confirms it, in a
//   separate act the proposer cannot perform: "broker confirm"
//   mints a one-shot token bound to the action's hash, and
//   "broker execute" spends it. Tokens expire and never transfer
//   to a different action.
//
// Every transition is chained into an audit log on the same
// hash-linked pattern as the editions log.
//
// State lives in one directory (--home, default ./broker-home):
// key (the broker's Ed25519 pair), state.json, audit.log, and the
// outbox the demo actions write to.
//
//   broker init
//   broker propose <action.json>
//   broker confirm <action-hash>
//   broker execute <action.json> --token <token>
//   broker audit
//
// An action is JSON: {"kind": "note", "text": "..."} or
// {"kind": "grow", "derivation": "<path>", "store": "<dir>"}.

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{exit, Command};
use std::time::{SystemTime, UNIX_EPOCH};

fn fail(msg: &str) -> ! {
    eprintln!("broker: {msg}");
    exit(1);
}

fn sha256_bytes(bytes: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(bytes);
    h.finalize().iter().map(|b| format!("{b:02x}")).collect()
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn hex_decode(text: &str) -> Option<Vec<u8>> {
    let text = text.trim();
    if !text.len().is_multiple_of(2) {
        return None;
    }
    let mut out = Vec::with_capacity(text.len() / 2);
    let bytes = text.as_bytes();
    for i in (0..bytes.len()).step_by(2) {
        let hi = (bytes[i] as char).to_digit(16)?;
        let lo = (bytes[i + 1] as char).to_digit(16)?;
        out.push((hi * 16 + lo) as u8);
    }
    Some(out)
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn random_hex(n: usize) -> String {
    let mut buf = vec![0u8; n];
    let mut urandom = fs::File::open("/dev/urandom")
        .unwrap_or_else(|e| fail(&format!("cannot open /dev/urandom: {e}")));
    std::io::Read::read_exact(&mut urandom, &mut buf)
        .unwrap_or_else(|e| fail(&format!("cannot read randomness: {e}")));
    hex_encode(&buf)
}

// ---------------------------------------------------------------------
// Actions and their classes. The table is the standing orders: it is
// part of the trusted core, and a proposal carries no say in it.

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Action {
    kind: String,
    #[serde(default)]
    text: String,
    #[serde(default)]
    derivation: String,
    #[serde(default)]
    store: String,
}

#[derive(Debug, PartialEq)]
enum Class {
    Routine,
    Consequential,
}

fn classify(action: &Action) -> Class {
    match action.kind.as_str() {
        "note" => Class::Routine,
        "grow" => Class::Consequential,
        _ => Class::Consequential, // unknown kinds default to caution
    }
}

fn reason(action: &Action) -> String {
    match action.kind.as_str() {
        "grow" => format!(
            "growing code runs a build: {}",
            action.derivation
        ),
        other => format!("{other} is not a standing order"),
    }
}

/// The canonical identity of an action: two proposals are the same
/// action only if every field matches, byte for byte after sorting.
fn action_hash(action: &Action) -> String {
    let text = serde_json::to_string(action).unwrap();
    sha256_bytes(text.as_bytes())
}

// ---------------------------------------------------------------------
// State

#[derive(Debug, Default, Serialize, Deserialize)]
struct Attempt {
    warned_at: u64,
    warning_sig: String,
    #[serde(default)]
    token_hash: Option<String>,
    #[serde(default)]
    token_expires: u64,
    #[serde(default)]
    executed: bool,
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct State {
    attempts: HashMap<String, Attempt>,
}

#[derive(Debug, Serialize, Deserialize)]
struct AuditEntry {
    seq: u64,
    at: u64,
    event: String,
    action: String,
    detail: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct AuditLine {
    prev: String,
    entry: AuditEntry,
    hash: String,
}

fn audit_line_hash(prev: &str, entry: &AuditEntry) -> String {
    let body = serde_json::to_string(entry).unwrap();
    sha256_bytes(format!("{prev}:{body}").as_bytes())
}

struct Home {
    dir: PathBuf,
}

impl Home {
    fn path(&self, name: &str) -> PathBuf {
        self.dir.join(name)
    }
    fn load_state(&self) -> State {
        let p = self.path("state.json");
        if !p.exists() {
            return State::default();
        }
        let raw = fs::read(&p).unwrap_or_else(|e| fail(&format!("cannot read state: {e}")));
        serde_json::from_slice(&raw).unwrap_or_else(|e| fail(&format!("state unreadable: {e}")))
    }
    fn save_state(&self, state: &State) {
        let text = serde_json::to_string_pretty(state).unwrap();
        fs::write(self.path("state.json"), text + "\n")
            .unwrap_or_else(|e| fail(&format!("cannot write state: {e}")));
    }
    fn key(&self) -> SigningKey {
        let text = fs::read_to_string(self.path("key")).unwrap_or_else(|_| {
            fail("broker home is not initialized - run broker init first")
        });
        for line in text.lines() {
            // Key files written before the rename carry the idem- prefix.
            let hex = line
                .strip_prefix("fixity-ed25519-secret ")
                .or_else(|| line.strip_prefix("idem-ed25519-secret "));
            if let Some(hex) = hex {
                let bytes = hex_decode(hex)
                    .filter(|b| b.len() == 32)
                    .unwrap_or_else(|| fail("broker key is malformed"));
                let mut seed = [0u8; 32];
                seed.copy_from_slice(&bytes);
                return SigningKey::from_bytes(&seed);
            }
        }
        fail("broker key carries no secret line")
    }
    fn audit(&self, event: &str, action: &str, detail: &str) {
        let path = self.path("audit.log");
        let text = fs::read_to_string(&path).unwrap_or_default();
        let lines: Vec<AuditLine> = text
            .lines()
            .filter(|l| !l.trim().is_empty())
            .map(|l| serde_json::from_str(l).unwrap_or_else(|e| fail(&format!("audit unreadable: {e}"))))
            .collect();
        let prev = lines
            .last()
            .map(|l| l.hash.clone())
            .unwrap_or_else(|| "GENESIS".to_string());
        let entry = AuditEntry {
            seq: lines.len() as u64 + 1,
            at: now(),
            event: event.to_string(),
            action: action.to_string(),
            detail: detail.to_string(),
        };
        let hash = audit_line_hash(&prev, &entry);
        let line = AuditLine { prev, entry, hash };
        let mut out = text;
        if !out.is_empty() && !out.ends_with('\n') {
            out.push('\n');
        }
        out.push_str(&serde_json::to_string(&line).unwrap());
        out.push('\n');
        fs::write(&path, out).unwrap_or_else(|e| fail(&format!("cannot write audit: {e}")));
    }
}

// ---------------------------------------------------------------------
// Performing an action - the only place effects happen.

fn perform(home: &Home, action: &Action) -> String {
    match action.kind.as_str() {
        "note" => {
            let line = format!("{}\n", action.text);
            let outbox = home.path("outbox.txt");
            let mut text = fs::read_to_string(&outbox).unwrap_or_default();
            text.push_str(&line);
            fs::write(&outbox, text)
                .unwrap_or_else(|e| fail(&format!("cannot write outbox: {e}")));
            format!("noted: {}", action.text)
        }
        "grow" => {
            // The grower is found beside the broker, or on PATH.
            let exe = env::current_exe()
                .ok()
                .and_then(|p| p.parent().map(|d| d.join("grower")))
                .filter(|p| p.exists())
                .unwrap_or_else(|| PathBuf::from("grower"));
            let output = Command::new(&exe)
                .arg("--store")
                .arg(&action.store)
                .arg("grow")
                .arg(&action.derivation)
                .output()
                .unwrap_or_else(|e| fail(&format!("cannot run the grower: {e}")));
            if !output.status.success() {
                fail(&format!(
                    "the grower refused: {}",
                    String::from_utf8_lossy(&output.stderr).trim()
                ));
            }
            String::from_utf8_lossy(&output.stdout).trim().to_string()
        }
        other => fail(&format!("unknown action kind {other}")),
    }
}

// ---------------------------------------------------------------------
// Commands

fn cmd_init(home: &Home) {
    fs::create_dir_all(&home.dir)
        .unwrap_or_else(|e| fail(&format!("cannot create broker home: {e}")));
    let key_path = home.path("key");
    if key_path.exists() {
        fail("broker home already holds a key - refusing to replace it");
    }
    let mut seed = [0u8; 32];
    let mut urandom = fs::File::open("/dev/urandom")
        .unwrap_or_else(|e| fail(&format!("cannot open /dev/urandom: {e}")));
    std::io::Read::read_exact(&mut urandom, &mut seed)
        .unwrap_or_else(|e| fail(&format!("cannot read randomness: {e}")));
    let key = SigningKey::from_bytes(&seed);
    let public = hex_encode(key.verifying_key().as_bytes());
    let text = format!(
        "fixity-ed25519-secret {}\nfixity-ed25519-public {public}\n",
        hex_encode(&seed)
    );
    fs::write(&key_path, text).unwrap_or_else(|e| fail(&format!("cannot write key: {e}")));
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(&key_path, fs::Permissions::from_mode(0o600));
    }
    home.audit("init", "", &format!("broker initialized, public key {public}"));
    println!("broker initialized: {}", home.dir.display());
    println!("public key: {public}");
}

fn load_action(path: &Path) -> Action {
    let raw = fs::read(path).unwrap_or_else(|e| fail(&format!("cannot read action: {e}")));
    serde_json::from_slice(&raw).unwrap_or_else(|e| fail(&format!("action is not JSON: {e}")))
}

fn cmd_propose(home: &Home, action_path: &Path) {
    let key = home.key();
    let action = load_action(action_path);
    let hash = action_hash(&action);
    match classify(&action) {
        Class::Routine => {
            let detail = perform(home, &action);
            home.audit("executed", &hash, &detail);
            println!("done: {detail}");
        }
        Class::Consequential => {
            let mut state = home.load_state();
            if let Some(attempt) = state.attempts.get(&hash) {
                if attempt.executed {
                    // A fresh proposal of an already-executed action
                    // starts the sequence over: it is a new intent.
                    state.attempts.remove(&hash);
                } else if attempt.token_hash.is_some() && attempt.token_expires > now() {
                    println!("already warned, and a confirmation token is outstanding.");
                    println!("execute with that token to proceed: the action has not run.");
                    return;
                } else {
                    println!("already warned - this action still has not run.");
                    println!("it runs only after the owner confirms it (broker confirm {hash})");
                    return;
                }
            }
            let why = reason(&action);
            let sig = key.sign(format!("warn:{hash}:{why}").as_bytes());
            let warning_sig = hex_encode(&sig.to_bytes());
            state.attempts.insert(
                hash.clone(),
                Attempt {
                    warned_at: now(),
                    warning_sig,
                    token_hash: None,
                    token_expires: 0,
                    executed: false,
                },
            );
            home.save_state(&state);
            home.audit("warned", &hash, &why);
            println!("WARNING: {why}");
            println!("the action has NOT run. warning receipt: {hash}");
            println!("if the owner means it, they confirm it themselves; proposing again changes nothing.");
        }
    }
}

fn cmd_confirm(home: &Home, hash: &str) {
    let mut state = home.load_state();
    let attempt = state
        .attempts
        .get_mut(hash)
        .unwrap_or_else(|| fail("no warning stands for that action - nothing to confirm"));
    if attempt.executed {
        fail("that action already executed under an earlier confirmation");
    }
    let token = random_hex(24);
    attempt.token_hash = Some(sha256_bytes(token.as_bytes()));
    attempt.token_expires = now() + 600;
    home.save_state(&state);
    home.audit("confirmed", hash, "owner minted a one-shot token, 600 seconds");
    println!("token: {token}");
    println!("bound to action {hash}, one use, ten minutes.");
}

fn cmd_execute(home: &Home, action_path: &Path, token: &str) {
    let key = home.key();
    let action = load_action(action_path);
    let hash = action_hash(&action);
    if classify(&action) == Class::Routine {
        let detail = perform(home, &action);
        home.audit("executed", &hash, &detail);
        println!("done: {detail}");
        return;
    }
    let mut state = home.load_state();
    let attempt = state
        .attempts
        .get_mut(&hash)
        .unwrap_or_else(|| fail("this action was never proposed - no warning stands, so it cannot run"));
    // The warning must be the broker's own: verify its signature.
    let sig_bytes = hex_decode(&attempt.warning_sig)
        .filter(|b| b.len() == 64)
        .unwrap_or_else(|| fail("stored warning is malformed"));
    let mut sb = [0u8; 64];
    sb.copy_from_slice(&sig_bytes);
    let sig = Signature::from_bytes(&sb);
    let verifying: VerifyingKey = key.verifying_key();
    if verifying
        .verify(format!("warn:{hash}:{}", reason(&action)).as_bytes(), &sig)
        .is_err()
    {
        fail("stored warning does not verify against the broker key - state is not trustworthy");
    }
    match &attempt.token_hash {
        None => fail("warned, but the owner has not confirmed this action - it does not run"),
        Some(want) => {
            if attempt.token_expires <= now() {
                fail("the confirmation token has expired - confirm again");
            }
            if &sha256_bytes(token.as_bytes()) != want {
                fail("that token does not belong to this action");
            }
        }
    }
    if attempt.executed {
        fail("this action already executed - a spent confirmation does not spend twice");
    }
    attempt.token_hash = None; // spend before performing: no re-entry
    attempt.executed = true;
    home.save_state(&state);
    let detail = perform(home, &action);
    home.audit("executed", &hash, &detail);
    println!("done: {detail}");
}

fn cmd_audit(home: &Home) {
    let path = home.path("audit.log");
    let text = fs::read_to_string(&path).unwrap_or_default();
    let mut prev = "GENESIS".to_string();
    let mut count = 0;
    for line in text.lines() {
        if line.trim().is_empty() {
            continue;
        }
        let parsed: AuditLine =
            serde_json::from_str(line).unwrap_or_else(|e| fail(&format!("audit unreadable: {e}")));
        if parsed.prev != prev || audit_line_hash(&parsed.prev, &parsed.entry) != parsed.hash {
            fail(&format!("audit chain broken at entry {}", parsed.entry.seq));
        }
        println!(
            "- {} {} {} {}",
            parsed.entry.seq, parsed.entry.event, parsed.entry.action, parsed.entry.detail
        );
        prev = parsed.hash.clone();
        count += 1;
    }
    println!("audit verified: {count} entries, chain unbroken");
}

fn flag_value(rest: &[String], flag: &str) -> Option<String> {
    rest.windows(2).find(|w| w[0] == flag).map(|w| w[1].clone())
}

fn usage() -> ! {
    eprintln!("usage:");
    eprintln!("  broker [--home DIR] init");
    eprintln!("  broker [--home DIR] propose <action.json>");
    eprintln!("  broker [--home DIR] confirm <action-hash>");
    eprintln!("  broker [--home DIR] execute <action.json> --token <token>");
    eprintln!("  broker [--home DIR] audit");
    exit(2);
}

fn main() {
    let args: Vec<String> = env::args().skip(1).collect();
    let mut home_dir = PathBuf::from("broker-home");
    let mut rest: Vec<String> = Vec::new();
    let mut it = args.iter().peekable();
    while let Some(a) = it.next() {
        if a == "--home" {
            home_dir = PathBuf::from(it.next().unwrap_or_else(|| fail("--home needs a directory")));
        } else {
            rest.push(a.clone());
        }
    }
    if rest.is_empty() {
        usage();
    }
    let home = Home { dir: home_dir };
    match rest[0].as_str() {
        "init" => cmd_init(&home),
        "propose" => {
            if rest.len() < 2 {
                usage();
            }
            cmd_propose(&home, Path::new(&rest[1]));
        }
        "confirm" => {
            if rest.len() < 2 {
                usage();
            }
            cmd_confirm(&home, &rest[1]);
        }
        "execute" => {
            if rest.len() < 2 {
                usage();
            }
            let token = flag_value(&rest, "--token").unwrap_or_else(|| fail("execute needs --token"));
            cmd_execute(&home, Path::new(&rest[1]), &token);
        }
        "audit" => cmd_audit(&home),
        _ => usage(),
    }
}
