// grower - the idem growth engine, v0.
//
// A derivation is a JSON file: a name, the need that called it, the
// inputs it is made from (each pinned by sha256), the steps that build
// it (argv arrays, never a shell), and the outputs it declares.
//
// grow:    check every input against its pinned hash (the gate),
//          build in a clean work directory, hash the outputs into the
//          content-addressed store, and write the receipt. If a receipt
//          already exists for this derivation, the fresh build must
//          reproduce its output hashes exactly, or the gate fails.
//          Trust by reproduction, not by signature.
// verify:  re-hash the inputs and the stored outputs against a receipt.
// compost: remove a receipt's outputs from the store, back to seed.
//          Outputs another receipt still answers to are kept.
//
// The store layout, under the store directory (flag --store, else the
// IDEM_STORE environment variable, else ./store):
//   objects/<sha256>        grown outputs, named by their hash
//   receipts/<deriv>.json   one receipt per derivation hash
//   work/<deriv>/           scratch: in/, out/ (kept for inspection)

use serde::{Deserialize, Serialize};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::env;
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{exit, Command};

#[derive(Debug, Deserialize)]
struct Input {
    path: String,
    sha256: String,
}

#[derive(Debug, Deserialize)]
struct Derivation {
    name: String,
    need: String,
    inputs: Vec<Input>,
    steps: Vec<Vec<String>>,
    outputs: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct ReceiptInput {
    path: String,
    sha256: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct ReceiptOutput {
    name: String,
    sha256: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct Receipt {
    name: String,
    need: String,
    derivation_sha256: String,
    grower: String,
    inputs: Vec<ReceiptInput>,
    steps: Vec<Vec<String>>,
    outputs: Vec<ReceiptOutput>,
}

fn sha256_file(path: &Path) -> std::io::Result<String> {
    let mut f = fs::File::open(path)?;
    let mut h = Sha256::new();
    let mut buf = [0u8; 65536];
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            break;
        }
        h.update(&buf[..n]);
    }
    Ok(format!("{:x}", h.finalize()))
}

fn sha256_bytes(bytes: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(bytes);
    format!("{:x}", h.finalize())
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

fn fail(msg: &str) -> ! {
    eprintln!("grower: {msg}");
    exit(1);
}

struct Args {
    store: PathBuf,
    rest: Vec<String>,
}

fn parse_args() -> Args {
    let argv: Vec<String> = env::args().skip(1).collect();
    let mut store: Option<PathBuf> = None;
    let mut rest: Vec<String> = Vec::new();
    let mut i = 0;
    while i < argv.len() {
        if argv[i] == "--store" {
            i += 1;
            if i >= argv.len() {
                fail("--store needs a directory");
            }
            store = Some(PathBuf::from(&argv[i]));
        } else {
            rest.push(argv[i].clone());
        }
        i += 1;
    }
    let store = store
        .or_else(|| env::var_os("IDEM_STORE").map(PathBuf::from))
        .unwrap_or_else(|| PathBuf::from("store"));
    Args { store, rest }
}

fn load_derivation(path: &Path) -> (Derivation, String) {
    let raw = fs::read(path).unwrap_or_else(|e| fail(&format!("cannot read {}: {e}", path.display())));
    let deriv: Derivation = serde_json::from_slice(&raw)
        .unwrap_or_else(|e| fail(&format!("{} is not a derivation: {e}", path.display())));
    (deriv, sha256_bytes(&raw))
}

// Resolve an input path relative to the derivation file's directory.
fn input_path(deriv_path: &Path, rel: &str) -> PathBuf {
    let base = deriv_path.parent().unwrap_or_else(|| Path::new("."));
    base.join(rel)
}

fn cmd_grow(store: &Path, deriv_path: &Path) {
    let (deriv, deriv_hash) = load_derivation(deriv_path);

    // The gate, part one: the material must be what the derivation says.
    for input in &deriv.inputs {
        let p = input_path(deriv_path, &input.path);
        let actual = sha256_file(&p)
            .unwrap_or_else(|e| fail(&format!("cannot read input {}: {e}", p.display())));
        if actual != input.sha256 {
            fail(&format!(
                "gate: input {} hashes to {actual}, derivation pins {}",
                input.path, input.sha256
            ));
        }
    }

    let objects = store.join("objects");
    let receipts = store.join("receipts");
    let work = store.join("work").join(&deriv_hash);
    let in_dir = work.join("in");
    let out_dir = work.join("out");
    for d in [&objects, &receipts, &in_dir, &out_dir] {
        fs::create_dir_all(d).unwrap_or_else(|e| fail(&format!("cannot create {}: {e}", d.display())));
    }

    // Stage the inputs under fixed names so steps are path independent.
    let mut staged: Vec<String> = Vec::new();
    for (i, input) in deriv.inputs.iter().enumerate() {
        let dst = in_dir.join(format!("in{i}"));
        fs::copy(input_path(deriv_path, &input.path), &dst)
            .unwrap_or_else(|e| fail(&format!("cannot stage input {}: {e}", input.path)));
        staged.push(dst.to_string_lossy().into_owned());
    }

    // Build.
    for step in &deriv.steps {
        if step.is_empty() {
            fail("gate: derivation carries an empty step");
        }
        let mut argv: Vec<String> = Vec::new();
        for token in step {
            let mut t = token
                .replace("{out}", &out_dir.to_string_lossy())
                .replace("{work}", &work.to_string_lossy());
            for (i, s) in staged.iter().enumerate() {
                t = t.replace(&format!("{{in{i}}}"), s);
            }
            argv.push(t);
        }
        let status = Command::new(&argv[0])
            .args(&argv[1..])
            .current_dir(&work)
            .status()
            .unwrap_or_else(|e| fail(&format!("cannot run step {argv:?}: {e}")));
        if !status.success() {
            fail(&format!("step failed: {argv:?}"));
        }
    }

    // Hash the declared outputs into the store.
    let mut outputs: Vec<ReceiptOutput> = Vec::new();
    for name in &deriv.outputs {
        let produced = out_dir.join(name);
        if !produced.is_file() {
            fail(&format!("declared output {name} was not produced"));
        }
        let hash = sha256_file(&produced).unwrap_or_else(|e| fail(&format!("cannot hash output: {e}")));
        let object = objects.join(&hash);
        if !object.exists() {
            fs::copy(&produced, &object).unwrap_or_else(|e| fail(&format!("cannot store output: {e}")));
        }
        outputs.push(ReceiptOutput { name: name.clone(), sha256: hash });
    }

    let receipt_path = receipts.join(format!("{deriv_hash}.json"));
    let fresh = Receipt {
        name: deriv.name.clone(),
        need: deriv.need.clone(),
        derivation_sha256: deriv_hash.clone(),
        grower: format!("grower {}", env!("CARGO_PKG_VERSION")),
        inputs: deriv
            .inputs
            .iter()
            .map(|i| ReceiptInput { path: i.path.clone(), sha256: i.sha256.clone() })
            .collect(),
        steps: deriv.steps.clone(),
        outputs,
    };

    // The gate, part two: a regrowth must reproduce the first growth.
    if receipt_path.exists() {
        let old_raw = fs::read(&receipt_path).unwrap_or_else(|e| fail(&format!("cannot read receipt: {e}")));
        let old: Receipt = serde_json::from_slice(&old_raw)
            .unwrap_or_else(|e| fail(&format!("receipt is unreadable: {e}")));
        let same = old.outputs.len() == fresh.outputs.len()
            && old
                .outputs
                .iter()
                .zip(fresh.outputs.iter())
                .all(|(a, b)| a.name == b.name && a.sha256 == b.sha256);
        if !same {
            fail("gate: regrowth did not reproduce the receipt's outputs");
        }
        println!(
            "regrown and reproduced: {} (derivation {})",
            fresh.name, deriv_hash
        );
        for o in &fresh.outputs {
            println!("- {} -> {}", o.name, o.sha256);
        }
        return;
    }

    let text = serde_json::to_string_pretty(&fresh).unwrap();
    fs::write(&receipt_path, text + "\n")
        .unwrap_or_else(|e| fail(&format!("cannot write receipt: {e}")));
    println!("grown: {} (derivation {})", fresh.name, deriv_hash);
    for o in &fresh.outputs {
        println!("- {} -> {}", o.name, o.sha256);
    }
    println!("receipt: {}", receipt_path.display());
}

fn load_receipt(path: &Path) -> Receipt {
    let raw = fs::read(path).unwrap_or_else(|e| fail(&format!("cannot read {}: {e}", path.display())));
    serde_json::from_slice(&raw).unwrap_or_else(|e| fail(&format!("{} is not a receipt: {e}", path.display())))
}

fn cmd_verify(store: &Path, receipt_path: &Path, deriv_path: Option<&Path>) {
    let receipt = load_receipt(receipt_path);
    let objects = store.join("objects");
    let mut bad = 0;
    for o in &receipt.outputs {
        let object = objects.join(&o.sha256);
        if !object.is_file() {
            println!("missing from store: {} ({})", o.name, o.sha256);
            bad += 1;
            continue;
        }
        let actual = sha256_file(&object).unwrap_or_else(|e| fail(&format!("cannot hash object: {e}")));
        if actual != o.sha256 {
            println!("store object for {} does not hash to its name", o.name);
            bad += 1;
        }
    }
    if let Some(dp) = deriv_path {
        for input in &receipt.inputs {
            let p = input_path(dp, &input.path);
            match sha256_file(&p) {
                Ok(actual) if actual == input.sha256 => {}
                Ok(actual) => {
                    println!("input {} now hashes to {actual}, receipt pins {}", input.path, input.sha256);
                    bad += 1;
                }
                Err(_) => {
                    println!("input {} is not present to check", input.path);
                    bad += 1;
                }
            }
        }
    }
    if bad > 0 {
        fail(&format!("verify: {bad} check(s) failed for {}", receipt.name));
    }
    println!("verified: {} - every output in the store answers to its receipt", receipt.name);
}

fn cmd_compost(store: &Path, receipt_path: &Path) {
    let receipt = load_receipt(receipt_path);
    // Which hashes do other receipts still answer to?
    let mut keep: BTreeMap<String, bool> = BTreeMap::new();
    let receipts_dir = store.join("receipts");
    if let Ok(entries) = fs::read_dir(&receipts_dir) {
        for entry in entries.flatten() {
            let p = entry.path();
            if p == receipt_path {
                continue;
            }
            if let Ok(raw) = fs::read(&p) {
                if let Ok(other) = serde_json::from_slice::<Receipt>(&raw) {
                    for o in &other.outputs {
                        keep.insert(o.sha256.clone(), true);
                    }
                }
            }
        }
    }
    let objects = store.join("objects");
    for o in &receipt.outputs {
        if keep.contains_key(&o.sha256) {
            println!("kept (another receipt answers to it): {} ({})", o.name, o.sha256);
            continue;
        }
        let object = objects.join(&o.sha256);
        if object.exists() {
            fs::remove_file(&object).unwrap_or_else(|e| fail(&format!("cannot compost object: {e}")));
            println!("composted: {} ({})", o.name, o.sha256);
        } else {
            println!("already gone: {} ({})", o.name, o.sha256);
        }
    }
}


// ---------------------------------------------------------------------
// Editions: sealed capsules that travel by wire or by hand and are
// accepted only by reproduction. A capsule carries a derivation and
// its inputs, rewritten to point inside the capsule, plus a manifest
// pinning every file and the outputs the derivation must produce.
// Accepting an edition means growing it again and matching those
// outputs exactly, then chaining a line into the append-only log:
// each line carries the hash of the line before it.

#[derive(Debug, Serialize, Deserialize)]
struct CapsuleFile {
    path: String,
    sha256: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct Manifest {
    name: String,
    need: String,
    derivation_sha256: String,
    grower: String,
    files: Vec<CapsuleFile>,
    outputs: Vec<ReceiptOutput>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    signer: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    signature: Option<String>,
}

/// The bytes a signature answers to: every committed field of the
/// manifest, one per line, in a fixed order. Signer and signature are
/// not part of it, for the obvious reason.
fn manifest_body(m: &Manifest) -> Vec<u8> {
    let mut body = String::new();
    body.push_str(&format!("name: {}\n", m.name));
    body.push_str(&format!("need: {}\n", m.need));
    body.push_str(&format!("derivation: {}\n", m.derivation_sha256));
    body.push_str(&format!("grower: {}\n", m.grower));
    for f in &m.files {
        body.push_str(&format!("file: {} {}\n", f.path, f.sha256));
    }
    for o in &m.outputs {
        body.push_str(&format!("output: {} {}\n", o.name, o.sha256));
    }
    body.into_bytes()
}

fn load_signing_key(path: &Path) -> SigningKey {
    let text = fs::read_to_string(path)
        .unwrap_or_else(|e| fail(&format!("cannot read key file {}: {e}", path.display())));
    for line in text.lines() {
        if let Some(hex) = line.strip_prefix("idem-ed25519-secret ") {
            let bytes = hex_decode(hex)
                .filter(|b| b.len() == 32)
                .unwrap_or_else(|| fail("key file secret is not 32 bytes of hex"));
            let mut seed = [0u8; 32];
            seed.copy_from_slice(&bytes);
            return SigningKey::from_bytes(&seed);
        }
    }
    fail("key file carries no idem-ed25519-secret line")
}

fn cmd_keygen(path: &Path) {
    if path.exists() {
        fail(&format!("key file {} already exists - refusing to overwrite a key", path.display()));
    }
    let mut seed = [0u8; 32];
    let mut urandom = fs::File::open("/dev/urandom")
        .unwrap_or_else(|e| fail(&format!("cannot open /dev/urandom: {e}")));
    std::io::Read::read_exact(&mut urandom, &mut seed)
        .unwrap_or_else(|e| fail(&format!("cannot read randomness: {e}")));
    let key = SigningKey::from_bytes(&seed);
    let public = hex_encode(key.verifying_key().as_bytes());
    let text = format!(
        "idem-ed25519-secret {}\nidem-ed25519-public {public}\n",
        hex_encode(&seed)
    );
    fs::write(path, text).unwrap_or_else(|e| fail(&format!("cannot write key file: {e}")));
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o600));
    }
    println!("key written: {}", path.display());
    println!("public key: {public}");
}

fn run_self(store: &Path, deriv_path: &Path) -> Receipt {
    let exe = env::current_exe().unwrap_or_else(|e| fail(&format!("cannot find self: {e}")));
    let output = Command::new(&exe)
        .arg("--store")
        .arg(store)
        .arg("grow")
        .arg(deriv_path)
        .output()
        .unwrap_or_else(|e| fail(&format!("cannot run growth: {e}")));
    if !output.status.success() {
        fail(&format!(
            "growth failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    let receipts = store.join("receipts");
    let mut found: Option<Receipt> = None;
    if let Ok(entries) = fs::read_dir(&receipts) {
        for entry in entries.flatten() {
            if let Ok(raw) = fs::read(entry.path()) {
                if let Ok(r) = serde_json::from_slice::<Receipt>(&raw) {
                    if found.is_none() {
                        found = Some(r);
                    }
                }
            }
        }
    }
    found.unwrap_or_else(|| fail("growth wrote no receipt"))
}

fn cmd_edition_pack(deriv_path: &Path, capsule_dir: &Path, sign_key: Option<&Path>) {
    let (deriv, _hash) = load_derivation(deriv_path);
    for input in &deriv.inputs {
        let p = input_path(deriv_path, &input.path);
        let actual = sha256_file(&p)
            .unwrap_or_else(|e| fail(&format!("cannot read input {}: {e}", p.display())));
        if actual != input.sha256 {
            fail(&format!(
                "gate: input {} hashes to {actual}, derivation pins {}",
                input.path, input.sha256
            ));
        }
    }

    // Grow once into a scratch store to learn the outputs.
    let scratch = env::temp_dir().join(format!("idem-pack-{}", std::process::id()));
    let receipt = run_self(&scratch, deriv_path);
    let _ = fs::remove_dir_all(&scratch);

    // Seal the capsule: inputs under files/<i>, the derivation
    // rewritten to point at them, the manifest over everything.
    let files_dir = capsule_dir.join("files");
    fs::create_dir_all(&files_dir)
        .unwrap_or_else(|e| fail(&format!("cannot create capsule: {e}")));
    let raw = fs::read(deriv_path).unwrap_or_else(|e| fail(&format!("cannot read derivation: {e}")));
    let mut value: serde_json::Value =
        serde_json::from_slice(&raw).unwrap_or_else(|e| fail(&format!("derivation is not JSON: {e}")));
    let mut files: Vec<CapsuleFile> = Vec::new();
    for (i, input) in deriv.inputs.iter().enumerate() {
        let capsule_path = format!("files/{i}");
        fs::copy(
            input_path(deriv_path, &input.path),
            capsule_dir.join(&capsule_path),
        )
        .unwrap_or_else(|e| fail(&format!("cannot seal input {}: {e}", input.path)));
        files.push(CapsuleFile {
            path: capsule_path.clone(),
            sha256: input.sha256.clone(),
        });
        value["inputs"][i]["path"] = serde_json::Value::String(capsule_path);
    }
    let capsule_deriv = serde_json::to_string_pretty(&value).unwrap() + "\n";
    fs::write(capsule_dir.join("derivation.json"), &capsule_deriv)
        .unwrap_or_else(|e| fail(&format!("cannot write capsule derivation: {e}")));
    let deriv_hash = sha256_bytes(capsule_deriv.as_bytes());

    let mut manifest = Manifest {
        name: receipt.name.clone(),
        need: receipt.need.clone(),
        derivation_sha256: deriv_hash,
        grower: format!("grower {}", env!("CARGO_PKG_VERSION")),
        files,
        outputs: receipt.outputs,
        signer: None,
        signature: None,
    };
    if let Some(key_path) = sign_key {
        let key = load_signing_key(key_path);
        let signature = key.sign(&manifest_body(&manifest));
        manifest.signer = Some(hex_encode(key.verifying_key().as_bytes()));
        manifest.signature = Some(hex_encode(&signature.to_bytes()));
    }
    let text = serde_json::to_string_pretty(&manifest).unwrap();
    fs::write(capsule_dir.join("manifest.json"), text + "\n")
        .unwrap_or_else(|e| fail(&format!("cannot write manifest: {e}")));
    println!(
        "packed: {} into {} (derivation {})",
        manifest.name,
        capsule_dir.display(),
        manifest.derivation_sha256
    );
    match &manifest.signer {
        Some(signer) => println!("signed by: {signer}"),
        None => println!("unsigned - acceptance will need --allow-unsigned"),
    }
    for o in &manifest.outputs {
        println!("- {} -> {}", o.name, o.sha256);
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct LogEntry {
    seq: u64,
    name: String,
    manifest_sha256: String,
    outputs: Vec<ReceiptOutput>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    signer: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct LogLine {
    prev: String,
    entry: LogEntry,
    hash: String,
}

fn log_line_hash(prev: &str, entry: &LogEntry) -> String {
    let body = serde_json::to_string(entry).unwrap();
    sha256_bytes(format!("{prev}:{body}").as_bytes())
}

fn read_log(path: &Path) -> Vec<LogLine> {
    if !path.exists() {
        return Vec::new();
    }
    let text = fs::read_to_string(path).unwrap_or_else(|e| fail(&format!("cannot read log: {e}")));
    let mut out = Vec::new();
    for line in text.lines() {
        if line.trim().is_empty() {
            continue;
        }
        let parsed: LogLine = serde_json::from_str(line)
            .unwrap_or_else(|e| fail(&format!("log line is unreadable: {e}")));
        out.push(parsed);
    }
    out
}

fn cmd_edition_accept(store: &Path, capsule_dir: &Path, log_path: &Path, trust: Option<&Path>, allow_unsigned: bool) {
    let manifest_raw = fs::read(capsule_dir.join("manifest.json"))
        .unwrap_or_else(|e| fail(&format!("cannot read manifest: {e}")));
    let manifest: Manifest = serde_json::from_slice(&manifest_raw)
        .unwrap_or_else(|e| fail(&format!("manifest is unreadable: {e}")));

    // Who stands behind this capsule, checked before anything grows.
    // A signature must verify, and its signer must be named in the
    // trust file. An unsigned capsule is accepted only when the owner
    // says so for this capsule, out loud, with --allow-unsigned.
    match (&manifest.signer, &manifest.signature) {
        (Some(signer), Some(signature)) => {
            let trust_path = trust.unwrap_or_else(|| {
                fail("capsule is signed but no --trust file was given - name the keys you accept")
            });
            let trust_text = fs::read_to_string(trust_path)
                .unwrap_or_else(|e| fail(&format!("cannot read trust file: {e}")));
            let trusted: Vec<String> = trust_text
                .lines()
                .map(|l| l.trim().to_lowercase())
                .filter(|l| !l.is_empty() && !l.starts_with('#'))
                .collect();
            if !trusted.iter().any(|t| t == &signer.to_lowercase()) {
                fail(&format!("signer {signer} is not in the trust file"));
            }
            let key_bytes = hex_decode(signer)
                .filter(|b| b.len() == 32)
                .unwrap_or_else(|| fail("manifest signer is not 32 bytes of hex"));
            let mut kb = [0u8; 32];
            kb.copy_from_slice(&key_bytes);
            let verifying = VerifyingKey::from_bytes(&kb)
                .unwrap_or_else(|_| fail("manifest signer is not a valid public key"));
            let sig_bytes = hex_decode(signature)
                .filter(|b| b.len() == 64)
                .unwrap_or_else(|| fail("manifest signature is not 64 bytes of hex"));
            let mut sb = [0u8; 64];
            sb.copy_from_slice(&sig_bytes);
            let sig = Signature::from_bytes(&sb);
            if verifying.verify(&manifest_body(&manifest), &sig).is_err() {
                fail("manifest signature does not verify");
            }
            println!("signature verified: {signer}");
        }
        _ => {
            if !allow_unsigned {
                fail("capsule is unsigned - refusing without --allow-unsigned");
            }
            println!("warning: accepting an unsigned capsule on the owner's word");
        }
    }

    // The capsule must answer to its manifest, file by file.
    let deriv_bytes = fs::read(capsule_dir.join("derivation.json"))
        .unwrap_or_else(|e| fail(&format!("cannot read capsule derivation: {e}")));
    if sha256_bytes(&deriv_bytes) != manifest.derivation_sha256 {
        fail("capsule derivation does not answer to its manifest");
    }
    for f in &manifest.files {
        let actual = sha256_file(&capsule_dir.join(&f.path))
            .unwrap_or_else(|e| fail(&format!("cannot read capsule file {}: {e}", f.path)));
        if actual != f.sha256 {
            fail(&format!(
                "capsule file {} hashes to {actual}, manifest pins {}",
                f.path, f.sha256
            ));
        }
    }

    // Acceptance is reproduction: grow it again, compare the outputs.
    let receipt = run_self(store, &capsule_dir.join("derivation.json"));
    let same = receipt.outputs.len() == manifest.outputs.len()
        && receipt
            .outputs
            .iter()
            .zip(manifest.outputs.iter())
            .all(|(a, b)| a.name == b.name && a.sha256 == b.sha256);
    if !same {
        fail("edition did not reproduce the outputs its manifest commits to");
    }

    // Chain the acceptance into the log.
    let lines = read_log(log_path);
    let prev = lines
        .last()
        .map(|l| l.hash.clone())
        .unwrap_or_else(|| "GENESIS".to_string());
    let entry = LogEntry {
        seq: lines.len() as u64 + 1,
        name: manifest.name.clone(),
        manifest_sha256: sha256_bytes(&manifest_raw),
        outputs: manifest.outputs,
        signer: manifest.signer.clone(),
    };
    let hash = log_line_hash(&prev, &entry);
    let line = LogLine { prev, entry, hash };
    let mut text = fs::read_to_string(log_path).unwrap_or_default();
    text.push_str(&serde_json::to_string(&line).unwrap());
    text.push('\n');
    fs::write(log_path, text).unwrap_or_else(|e| fail(&format!("cannot append to log: {e}")));
    println!(
        "accepted: {} as log entry {} ({})",
        line.entry.name, line.entry.seq, line.hash
    );
}

fn cmd_edition_log(log_path: &Path) {
    let lines = read_log(log_path);
    let mut prev = "GENESIS".to_string();
    for line in &lines {
        if line.prev != prev {
            fail(&format!("log chain broken at entry {}", line.entry.seq));
        }
        if log_line_hash(&line.prev, &line.entry) != line.hash {
            fail(&format!("log entry {} does not hash to its line", line.entry.seq));
        }
        println!("- {}: {}", line.entry.seq, line.entry.name);
        prev = line.hash.clone();
    }
    println!("log verified: {} entries, chain unbroken", lines.len());
}

fn edition_usage() -> ! {
    eprintln!("usage:");
    eprintln!("  grower keygen <key-file>");
    eprintln!("  grower edition pack <derivation.json> <capsule-dir> [--key <key-file>]");
    eprintln!("  grower [--store DIR] edition accept <capsule-dir> <log-file> [--trust <trust-file> | --allow-unsigned]");
    eprintln!("  grower edition log <log-file>");
    exit(2);
}

fn flag_value(rest: &[String], flag: &str) -> Option<String> {
    rest.windows(2)
        .find(|w| w[0] == flag)
        .map(|w| w[1].clone())
}

fn usage() -> ! {
    eprintln!("usage:");
    eprintln!("  grower [--store DIR] grow <derivation.json>");
    eprintln!("  grower [--store DIR] verify <receipt.json> [derivation.json]");
    eprintln!("  grower [--store DIR] compost <receipt.json>");
    eprintln!("  grower keygen <key-file>");
    eprintln!("  grower edition pack|accept|log ...");
    exit(2);
}

fn main() {
    let args = parse_args();
    let rest = &args.rest;
    if rest.len() < 2 {
        usage();
    }
    match rest[0].as_str() {
        "keygen" => cmd_keygen(Path::new(&rest[1])),
        "grow" => cmd_grow(&args.store, Path::new(&rest[1])),
        "verify" => cmd_verify(
            &args.store,
            Path::new(&rest[1]),
            rest.get(2).map(|s| Path::new(s.as_str())),
        ),
        "compost" => cmd_compost(&args.store, Path::new(&rest[1])),
        "edition" => {
            if rest.len() < 3 {
                edition_usage();
            }
            match rest[1].as_str() {
                "pack" => {
                    if rest.len() < 4 {
                        edition_usage();
                    }
                    let key = flag_value(rest, "--key");
                    cmd_edition_pack(
                        Path::new(&rest[2]),
                        Path::new(&rest[3]),
                        key.as_deref().map(Path::new),
                    );
                }
                "accept" => {
                    if rest.len() < 4 {
                        edition_usage();
                    }
                    let trust = flag_value(rest, "--trust");
                    let allow_unsigned = rest.iter().any(|a| a == "--allow-unsigned");
                    cmd_edition_accept(
                        &args.store,
                        Path::new(&rest[2]),
                        Path::new(&rest[3]),
                        trust.as_deref().map(Path::new),
                        allow_unsigned,
                    );
                }
                "log" => cmd_edition_log(Path::new(&rest[2])),
                _ => edition_usage(),
            }
        }
        _ => usage(),
    }
}
