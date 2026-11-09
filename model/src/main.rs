// The model service: idem's intelligence, kept unprivileged.
//
// Determination 8 gave the shape: a model service that proposes,
// and a trusted-core broker that disposes. This binary is the
// proposing half. It holds no authority of its own - it cannot
// execute anything, confirm anything, or mint a token. It drafts
// actions in the broker's JSON shape and hands them to the
// broker's propose verb, and the broker's standing orders decide
// what happens next: a note is routine and runs, a growth is
// consequential and stops at a signed warning until the owner
// confirms it as a separate act.
//
// Backends sit behind one seam - a draft is an action JSON,
// whoever made it:
//
// - scribe (always aboard): deterministic drafting from material
//   at hand. Notes from text, growth proposals from a derivation
//   it has read and checked, and world drafts for Optic: it reads
//   a document through the optic window and proposes a mutation
//   of it back through the same window, as a proposal the owner
//   keeps or discards.
// - llama (when a machine carries it): free text from a local
//   llama.cpp CLI and a GGUF aboard, wrapped as a note draft.
//   Absent the binary or the model, the backend reports itself
//   unavailable and nothing pretends otherwise. A network model
//   is never a backend: intelligence here is baked in, not rented.
//
// Commands:
//
//   model backends
//   model draft-note --text <text>
//   model draft-grow --derivation <file> --store <dir>
//   model draft-free --prompt <text> [--llama <bin>] [--model <gguf>]
//   model propose-note --home <broker-home> --text <text>
//   model propose-grow --home <broker-home> --derivation <file> --store <dir>
//   model propose-world --world <dir> --doc <name> --op <rotate|echo|trim>

use serde::Serialize;
use sha2::{Digest, Sha256};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{exit, Command, Stdio};

fn fail(msg: &str) -> ! {
    eprintln!("model: {msg}");
    exit(1);
}

#[derive(Serialize)]
struct Action {
    kind: String,
    #[serde(default)]
    text: String,
    #[serde(default)]
    derivation: String,
    #[serde(default)]
    store: String,
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(bytes);
    h.finalize().iter().map(|b| format!("{b:02x}")).collect()
}

fn flag<'a>(args: &'a [String], name: &str) -> Option<&'a str> {
    args.windows(2)
        .find(|w| w[0] == name)
        .map(|w| w[1].as_str())
}

fn need<'a>(args: &'a [String], name: &str) -> &'a str {
    flag(args, name).unwrap_or_else(|| fail(&format!("missing {name}")))
}

// A sibling binary: beside this executable first, then the PATH.
fn sibling(name: &str) -> String {
    if let Ok(exe) = std::env::current_exe() {
        let cand = exe.with_file_name(name);
        if cand.exists() {
            return cand.to_string_lossy().to_string();
        }
    }
    name.to_string()
}

fn run_capture(program: &str, args: &[&str], stdin_text: Option<&str>) -> (bool, String) {
    let mut cmd = Command::new(program);
    cmd.args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if stdin_text.is_some() {
        cmd.stdin(Stdio::piped());
    }
    let mut child = cmd
        .spawn()
        .unwrap_or_else(|e| fail(&format!("cannot run {program}: {e}")));
    if let Some(text) = stdin_text {
        child
            .stdin
            .as_mut()
            .unwrap()
            .write_all(text.as_bytes())
            .unwrap();
    }
    let out = child.wait_with_output().unwrap();
    let mut s = String::from_utf8_lossy(&out.stdout).to_string();
    s.push_str(&String::from_utf8_lossy(&out.stderr));
    (out.status.success(), s)
}

fn llama_cli(explicit: Option<&str>) -> Option<String> {
    if let Some(p) = explicit {
        return if Path::new(p).exists() {
            Some(p.to_string())
        } else {
            None
        };
    }
    if let Ok(p) = std::env::var("LLAMA_CLI") {
        if Path::new(&p).exists() {
            return Some(p);
        }
    }
    for name in ["llama-cli", "llama"] {
        let (ok, _) = run_capture("which", &[name], None);
        if ok {
            return Some(name.to_string());
        }
    }
    None
}

fn cmd_backends(args: &[String]) {
    println!("- scribe: aboard (deterministic drafting from material at hand)");
    match llama_cli(flag(args, "--llama")) {
        Some(p) => println!("- llama: available at {p} (needs a GGUF passed with --model)"),
        None => println!("- llama: not aboard on this machine (no llama-cli found)"),
    }
}

fn draft_note(text: &str) -> Action {
    Action {
        kind: "note".into(),
        text: text.to_string(),
        derivation: String::new(),
        store: String::new(),
    }
}

fn draft_grow(derivation: &str, store: &str) -> Action {
    let bytes = std::fs::read(derivation)
        .unwrap_or_else(|e| fail(&format!("cannot read derivation {derivation}: {e}")));
    let v: serde_json::Value = serde_json::from_slice(&bytes)
        .unwrap_or_else(|e| fail(&format!("derivation {derivation} is not JSON: {e}")));
    let name = v
        .get("name")
        .and_then(|n| n.as_str())
        .unwrap_or_else(|| fail("the derivation names no name - the scribe will not propose what it cannot name"));
    if v.get("inputs").and_then(|i| i.as_array()).is_none() {
        fail("the derivation carries no inputs list - the scribe will not propose what it cannot check");
    }
    println!(
        "- scribe read the derivation: {name}, derivation hash {}",
        sha256_hex(&bytes)
    );
    Action {
        kind: "grow".into(),
        text: String::new(),
        derivation: derivation.to_string(),
        store: store.to_string(),
    }
}

fn propose_via_broker(home: &str, action: &Action) {
    let json = serde_json::to_string(action).unwrap();
    let scratch = std::env::temp_dir().join(format!("idem-model-action-{}.json", std::process::id()));
    std::fs::write(&scratch, &json).unwrap();
    let broker = sibling("broker");
    let (ok, out) = run_capture(
        &broker,
        &["--home", home, "propose", scratch.to_str().unwrap()],
        None,
    );
    std::fs::remove_file(&scratch).ok();
    print!("{out}");
    if !ok {
        fail("the broker refused the proposal");
    }
}

fn apply_op(text: &str, op: &str) -> String {
    let paras: Vec<&str> = text.split("\n\n").collect();
    match op {
        "rotate" if paras.len() > 1 => {
            let mut p = paras.clone();
            let first = p.remove(0);
            p.push(first);
            p.join("\n\n")
        }
        "echo" => {
            let first = text.lines().next().unwrap_or("");
            format!("{}{}\n", text, first)
        }
        "trim" if paras.len() > 1 => paras[..paras.len() - 1].join("\n\n") + "\n",
        "rotate" | "trim" => fail(&format!("{op} needs a document of more than one paragraph")),
        other => fail(&format!("unknown op {other} - rotate, echo or trim")),
    }
}

fn cmd_propose_world(args: &[String]) {
    let world = need(args, "--world");
    let doc = need(args, "--doc");
    let op = flag(args, "--op").unwrap_or("rotate");
    let optic = sibling("optic");
    let (ok, text) = run_capture(&optic, &["view", world, doc], None);
    if !ok {
        fail(&format!("the window would not show {doc}: {}", text.trim()));
    }
    let draft = apply_op(&text, op);
    println!("- scribe drafted a {op} of {doc} through the window");
    let (ok, out) = run_capture(&optic, &["propose", world, doc], Some(&draft));
    print!("{out}");
    if !ok {
        fail("the window refused the draft");
    }
}

fn cmd_draft_free(args: &[String]) {
    let prompt = need(args, "--prompt");
    let model_path = need(args, "--model");
    let cli = llama_cli(flag(args, "--llama"))
        .unwrap_or_else(|| fail("no llama backend aboard on this machine - see: model backends"));
    if !Path::new(model_path).exists() {
        fail(&format!("no GGUF at {model_path}"));
    }
    let (ok, out) = run_capture(
        &cli,
        &["-m", model_path, "-p", prompt, "--no-display-prompt", "-n", "128"],
        None,
    );
    if !ok {
        fail(&format!("the llama backend failed: {}", out.trim()));
    }
    let action = draft_note(out.trim());
    println!("{}", serde_json::to_string(&action).unwrap());
}

fn usage() -> ! {
    eprintln!("usage:");
    eprintln!("  model backends");
    eprintln!("  model draft-note --text <text>");
    eprintln!("  model draft-grow --derivation <file> --store <dir>");
    eprintln!("  model draft-free --prompt <text> --model <gguf> [--llama <bin>]");
    eprintln!("  model propose-note --home <broker-home> --text <text>");
    eprintln!("  model propose-grow --home <broker-home> --derivation <file> --store <dir>");
    eprintln!("  model propose-world --world <dir> --doc <name> [--op rotate|echo|trim]");
    exit(2);
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.is_empty() {
        usage();
    }
    let rest = &args[1..];
    match args[0].as_str() {
        "backends" => cmd_backends(rest),
        "draft-note" => {
            let a = draft_note(need(rest, "--text"));
            println!("{}", serde_json::to_string(&a).unwrap());
        }
        "draft-grow" => {
            let a = draft_grow(need(rest, "--derivation"), need(rest, "--store"));
            println!("{}", serde_json::to_string(&a).unwrap());
        }
        "draft-free" => cmd_draft_free(rest),
        "propose-note" => {
            let a = draft_note(need(rest, "--text"));
            propose_via_broker(need(rest, "--home"), &a);
        }
        "propose-grow" => {
            let a = draft_grow(need(rest, "--derivation"), need(rest, "--store"));
            propose_via_broker(need(rest, "--home"), &a);
        }
        "propose-world" => cmd_propose_world(rest),
        _ => usage(),
    }
}
