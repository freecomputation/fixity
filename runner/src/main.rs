// The runner: where grown code is allowed to execute.
//
// The grower decides what may be built and proves it reproduces.
// The runner decides what built code may do while it runs, and the
// answer is: only arithmetic, inside a meter, with no hands. A grown
// module gets no imports at all in this prototype - no files, no
// network, no clock, no host functions - so it holds no ambient
// authority to abuse. It runs under a fuel budget and a memory cap,
// and it is deterministic: the same module and budget give the same
// result and the same fuel reading, every time.
//
// Convention: a runnable module exports "main", a function taking
// nothing and returning one i32.
//
// Components (the WASI 0.2 shape) run under the same discipline: a
// runnable component exports "main", a component function returning
// one s32, and the component linker is as empty as the core one - a
// component importing a WASI interface is asking for authority the
// same way, and none is on offer until a broker grants it. That is
// the staged path: components now, capabilities by grant later,
// never ambient.
//
//   runner run <file.wasm|file.wat> [--fuel N] [--memory-mb N]
//   runner run --object <sha256> --store <dir> [--fuel N]
//   runner run-component <file.wasm|file.wat> [--fuel N] [--memory-mb N]
//   runner run-component --object <sha256> --store <dir> [--fuel N]
//   runner assemble <file.wat> <out.wasm>

use std::path::PathBuf;
use std::process::exit;
use wasmtime::component::{Component, Linker as ComponentLinker, Val};
use wasmtime::{Config, Engine, Linker, Module, ResourceLimiter, Store};

fn fail(msg: &str) -> ! {
    eprintln!("runner: {msg}");
    exit(1);
}

struct Limits {
    max_memory: usize,
    memories_seen: usize,
}

impl ResourceLimiter for Limits {
    fn memory_growing(
        &mut self,
        _current: usize,
        desired: usize,
        _maximum: Option<usize>,
    ) -> wasmtime::Result<bool> {
        self.memories_seen += 1;
        Ok(desired <= self.max_memory)
    }

    fn table_growing(
        &mut self,
        _current: usize,
        desired: usize,
        _maximum: Option<usize>,
    ) -> wasmtime::Result<bool> {
        Ok(desired <= 10_000)
    }
}

struct State {
    limits: Limits,
}

struct Opts {
    fuel: u64,
    memory_mb: usize,
    target: Target,
}

enum Target {
    File(PathBuf),
    Object { store: PathBuf, sha: String },
}

fn parse_run_args(rest: &[String]) -> Opts {
    let mut fuel: u64 = 1_000_000;
    let mut memory_mb: usize = 16;
    let mut file: Option<PathBuf> = None;
    let mut object: Option<(PathBuf, String)> = None;
    let mut it = rest.iter().peekable();
    // rest[0] is "run"; walk the rest.
    let mut store: Option<PathBuf> = None;
    let mut sha: Option<String> = None;
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "--fuel" => {
                fuel = it
                    .next()
                    .and_then(|v| v.parse().ok())
                    .unwrap_or_else(|| fail("--fuel needs a number"));
            }
            "--memory-mb" => {
                memory_mb = it
                    .next()
                    .and_then(|v| v.parse().ok())
                    .unwrap_or_else(|| fail("--memory-mb needs a number"));
            }
            "--store" => {
                store = Some(PathBuf::from(
                    it.next().unwrap_or_else(|| fail("--store needs a directory")),
                ));
            }
            "--object" => {
                sha = Some(
                    it.next()
                        .unwrap_or_else(|| fail("--object needs a sha256"))
                        .clone(),
                );
            }
            other if !other.starts_with("--") && file.is_none() => {
                file = Some(PathBuf::from(other));
            }
            other => fail(&format!("unknown argument {other}")),
        }
    }
    if let (Some(store), Some(sha)) = (store, sha) {
        object = Some((store, sha));
    }
    let target = match (file, object) {
        (Some(f), None) => Target::File(f),
        (None, Some((store, sha))) => Target::Object { store, sha },
        _ => fail("run needs exactly one of a file or --object with --store"),
    };
    Opts {
        fuel,
        memory_mb,
        target,
    }
}

fn load_bytes(opts: &Opts) -> Vec<u8> {
    match &opts.target {
        Target::File(path) => std::fs::read(path)
            .unwrap_or_else(|e| fail(&format!("cannot read {}: {e}", path.display()))),
        Target::Object { store, sha } => {
            let path = store.join("objects").join(sha);
            std::fs::read(&path).unwrap_or_else(|e| {
                fail(&format!(
                    "cannot read object {sha} from {}: {e}",
                    path.display()
                ))
            })
        }
    }
}

fn make_engine() -> Engine {
    let mut config = Config::new();
    config.consume_fuel(true);
    config.wasm_multi_memory(false);
    config.wasm_threads(false);
    config.wasm_component_model(true);
    Engine::new(&config).unwrap_or_else(|e| fail(&format!("engine: {e}")))
}

fn make_store(engine: &Engine, opts: &Opts) -> Store<State> {
    let mut store = Store::new(
        engine,
        State {
            limits: Limits {
                max_memory: opts.memory_mb * 1024 * 1024,
                memories_seen: 0,
            },
        },
    );
    store.limiter(|state| &mut state.limits);
    store
        .set_fuel(opts.fuel)
        .unwrap_or_else(|e| fail(&format!("fuel: {e}")));
    store
}

fn report(store: &Store<State>, opts: &Opts, before: u64, result: Result<i32, wasmtime::Error>) {
    match result {
        Ok(value) => {
            let after = store.get_fuel().unwrap_or(0);
            println!("result: {value}");
            println!("fuel used: {}", before - after);
        }
        Err(e) => {
            let chain = format!("{e:?}").to_lowercase();
            if chain.contains("fuel") {
                fail(&format!(
                    "out of fuel after {} units - the meter stopped it",
                    opts.fuel
                ));
            }
            fail(&format!("trapped: {e}"));
        }
    }
}

fn cmd_run(rest: &[String]) {
    let opts = parse_run_args(rest);
    let bytes = load_bytes(&opts);
    let engine = make_engine();
    let module = Module::new(&engine, &bytes)
        .unwrap_or_else(|e| fail(&format!("not a runnable module: {e}")));
    let mut store = make_store(&engine, &opts);

    // The linker is empty on purpose: a module that asks for an
    // import is asking for authority, and none is on offer.
    let linker = Linker::new(&engine);
    let instance = linker
        .instantiate(&mut store, &module)
        .unwrap_or_else(|e| fail(&format!("module refused: {e}")));
    let main = instance
        .get_typed_func::<(), i32>(&mut store, "main")
        .unwrap_or_else(|e| fail(&format!("module exports no main () -> i32: {e}")));

    let before = store.get_fuel().unwrap_or(0);
    let result = main.call(&mut store, ());
    report(&store, &opts, before, result);
}

fn cmd_run_component(rest: &[String]) {
    let opts = parse_run_args(rest);
    let bytes = load_bytes(&opts);
    let engine = make_engine();
    let component = Component::new(&engine, &bytes)
        .unwrap_or_else(|e| fail(&format!("not a runnable component: {e}")));
    let mut store = make_store(&engine, &opts);

    // Empty, like the core linker: an imported interface is a
    // request for authority, and none is on offer.
    let linker = ComponentLinker::new(&engine);
    let instance = linker
        .instantiate(&mut store, &component)
        .unwrap_or_else(|e| fail(&format!("component refused: {e}")));
    let main = instance
        .get_func(&mut store, "main")
        .unwrap_or_else(|| fail("component exports no main () -> s32"));

    let before = store.get_fuel().unwrap_or(0);
    let mut results = [Val::S32(0)];
    let result = main
        .call(&mut store, &[], &mut results)
        .and_then(|()| match results[0] {
            Val::S32(v) => Ok(v),
            ref other => Err(wasmtime::Error::msg(format!(
                "main returned {other:?}, not an s32"
            ))),
        });
    report(&store, &opts, before, result);
}

fn cmd_assemble(rest: &[String]) {
    if rest.len() < 3 {
        eprintln!("usage: runner assemble <file.wat> <out.wasm>");
        exit(2);
    }
    let text = std::fs::read_to_string(&rest[1])
        .unwrap_or_else(|e| fail(&format!("cannot read {}: {e}", rest[1])));
    let bytes = wat::parse_str(&text).unwrap_or_else(|e| fail(&format!("not valid wat: {e}")));
    std::fs::write(&rest[2], &bytes)
        .unwrap_or_else(|e| fail(&format!("cannot write {}: {e}", rest[2])));
    println!("assembled: {} ({} bytes)", rest[2], bytes.len());
}

fn usage() -> ! {
    eprintln!("usage:");
    eprintln!("  runner run <file.wasm|file.wat> [--fuel N] [--memory-mb N]");
    eprintln!("  runner run --object <sha256> --store <dir> [--fuel N] [--memory-mb N]");
    eprintln!("  runner run-component <file.wasm|file.wat> [--fuel N] [--memory-mb N]");
    eprintln!("  runner run-component --object <sha256> --store <dir> [--fuel N] [--memory-mb N]");
    eprintln!("  runner assemble <file.wat> <out.wasm>");
    exit(2);
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.is_empty() {
        usage();
    }
    match args[0].as_str() {
        "run" => cmd_run(&args[1..]),
        "run-component" => cmd_run_component(&args[1..]),
        "assemble" => cmd_assemble(&args),
        _ => usage(),
    }
}
