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

fn usage() -> ! {
    eprintln!("usage:");
    eprintln!("  grower [--store DIR] grow <derivation.json>");
    eprintln!("  grower [--store DIR] verify <receipt.json> [derivation.json]");
    eprintln!("  grower [--store DIR] compost <receipt.json>");
    exit(2);
}

fn main() {
    let args = parse_args();
    let rest = &args.rest;
    if rest.len() < 2 {
        usage();
    }
    match rest[0].as_str() {
        "grow" => cmd_grow(&args.store, Path::new(&rest[1])),
        "verify" => cmd_verify(
            &args.store,
            Path::new(&rest[1]),
            rest.get(2).map(|s| Path::new(s.as_str())),
        ),
        "compost" => cmd_compost(&args.store, Path::new(&rest[1])),
        _ => usage(),
    }
}
