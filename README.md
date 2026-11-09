# idem

idem is a system that is not shipped complete. It is shipped able to
complete itself: it grows the code it needs, on the machine, from
material aboard, and everything it grows carries a receipt - the need
that called it, what it was made from, the hash it answers to - and
passes a growth gate before it runs. Where growth is derivation from
aboard sources, the same seed meeting the same need grows bit-identical
code on any machine. What stops being needed composts back to seed.

The name is the acceptance test: idem, the same. Apply the system to
itself and the result is bit-for-bit the same, or it is not ours.

Umiak, the standalone offline browser in its own repository, is idem's
first form. This repository holds the layer underneath: the grower.

## The grower

The grower is the small core that grows everything else, kept small
enough for one person to read end to end. Version 0 is one Rust
binary. It grows, verifies, and composts, and it packs and accepts
editions.

A derivation is a JSON file: a name, the need that called it, its
inputs each pinned by sha256, its build steps as plain argument lists
(never a shell), and the outputs it declares. The recipes directory
carries two: hello, a first grown thing, and grower, the grower
growing itself.

"grower grow <derivation>" checks every input against its pinned hash
before building - that is the gate - then builds in a clean work
directory, hashes the declared outputs into a content-addressed store,
and writes the receipt. Growing the same derivation a second time
rebuilds from scratch and must reproduce the first receipt's output
hashes exactly, or the gate fails. Trust by reproduction, not by
signature.

"grower verify <receipt> [derivation]" re-hashes the stored outputs,
and the inputs too when the derivation is given, and answers whether
everything still matches its receipt. "grower compost <receipt>"
removes a receipt's outputs from the store, back to seed, keeping any
output another receipt still answers to.

The store is a directory chosen by --store, the IDEM_STORE
environment variable, or ./store by default. Inside it: objects named
by their sha256, one receipt per derivation hash, and the work
directories kept for inspection.

## Editions

"grower edition pack <derivation> <capsule-dir>" seals a derivation
and its inputs into a capsule: the inputs copied in, the derivation
rewritten to point at them, and a manifest pinning every file by hash
together with the outputs the derivation must produce, learned by
growing it once at pack time.

"grower edition accept <capsule-dir> <log-file>" is the gate an
edition passes when it arrives, by wire or by hand. The capsule must
answer to its manifest file by file; then it is grown again, and the
fresh outputs must match the manifest's committed outputs exactly -
acceptance by reproduction. An accepted edition is
chained into an append-only log, each line carrying the hash of the
line before it, and "grower edition log <log-file>" verifies the
chain end to end. A capsule with one byte changed is refused before
anything grows.

Reproduction says what a capsule is; a signature says who stands
behind it, and an edition should answer both questions. "grower
keygen <key-file>" writes an Ed25519 key pair. "edition pack
--key <key-file>" signs the manifest, and "edition accept --trust
<trust-file>" refuses a signed capsule whose signer the trust file
does not name, or whose signature does not verify, before anything
grows. An unsigned capsule is refused unless the owner passes
--allow-unsigned for that capsule, out loud. The log records the
signer of every accepted edition.

A hash chain proves a log was not edited only to someone who trusts
their copy of its head. A witness closes that gap: "grower edition
witness <log-file> <key-file>" has an independent key co-sign the
log's current head, and the witness line travels in the same file,
so the proof moves offline with the log itself. "edition log" then
verifies every witness line where it stands - the head it names
must be the head the chain reaches at that point, and the signature
must verify. Rewrite an entry and the chain breaks; forge the
witness and the signature fails; move the witness line and it
stands over a head that is not there. One key witnessing the same
head twice is noted and not repeated.

## Recipes from the outside world

"grower recipe from-buildinfo <file.buildinfo> <out.json>" transcribes
a Debian .buildinfo file - the closest thing the outside world already
keeps to a receipt. The recipe pins the build's outputs by hash and
its whole environment as exact package versions. It also states its
own limit in the file: the source inputs are pinned by the package's
.dsc, not by the .buildinfo, so a derivation cannot be sealed from
this file alone. Pass "--dsc <file.dsc>" and the converter reads the
other half: the .dsc must name the same source and version, and its
pinned source files join the recipe, which then states that its
inputs are known - inputs, environment, and outputs all pinned, the
complete receipt. recipes/hello-buildinfo.json is the worked example,
transcribed from the signed buildinfo and the signed .dsc of hello
2.12.3-1, both kept beside it in recipes/material/.

## The runner

The grower decides what may be built. The runner - runner/, on
Wasmtime - decides what built code may do while it runs, and the
answer is: arithmetic, inside a meter, with no hands. A grown module
exports "main", takes nothing, and returns one i32. It runs under a
fuel budget and a memory cap, and the runner's linker is empty on
purpose: a module that asks for an import is asking for authority,
and none is on offer - no files, no network, no clock. Runs are
deterministic: the same module under the same budget returns the
same result and the same fuel reading. "runner run --object <sha256>
--store <dir>" executes a module straight out of a grower store, so
the path from derivation to sandboxed execution never leaves the
system's own discipline. The four guests in runner/examples/ each
demonstrate one wall: the honest one computes, the runaway dies by
fuel, the glutton is refused by the memory cap, the petitioner is
refused at the door for asking.

Components - the WASI 0.2 shape - run under the same discipline via
"runner run-component": a component exports "main" returning one
s32, runs under the same fuel meter and memory cap, from a file or
from a store object, and the component linker is as empty as the
core one. A component that imports a WASI interface is asking for
authority the same way, and none is on offer until a broker grants
it: components now, capabilities by grant later, never ambient.
runner/examples/ carries an answer component and an importing
component that is refused at the door.

## The broker

Intelligence proposes; the owner disposes - as a machine, not a
policy. The broker - broker/ - classifies every proposed action by
its own table; the proposer cannot relabel an action to slip its
class. Routine actions (a note into the outbox) are standing orders
and execute on proposal. Consequential actions (a growth) run the
charter's two-attempt sequence: the first proposal is answered with
a signed warning and nothing happens; the action executes only when
the owner confirms it in a separate act - "broker confirm" mints a
one-shot token bound to the action's hash, ten minutes to live - and
"broker execute" spends it. A spent, expired, or foreign token is
refused, and proposing an executed action again starts the sequence
over. Every transition chains into a hash-linked audit log.

## The model service

The proposing half of determination 8 lives at model/. It holds
no authority: it cannot execute, confirm, or mint a token. It
drafts actions in the broker's JSON shape and hands them to the
broker's propose verb, where the standing orders decide. Backends
sit behind one seam. The scribe is always aboard - deterministic
drafting from material at hand: notes from text, growth proposals
from a derivation it has read and checked, and world drafts for
Optic, where it reads a document through the optic window and
proposes a mutation back through the same window, to be kept or
discarded by the owner there. The llama backend wraps a local
llama.cpp CLI and a GGUF aboard as free-text note drafts, and
reports itself unavailable on machines that do not carry it - on
the machine this was built, scribe is aboard and llama is not,
and the service says so. A network model is never a backend.

Proven end to end with the real binaries: a note the model
proposed executed at once through the broker, as standing orders
allow; a growth the model proposed stopped at the broker's
signed warning with nothing grown; the owner's confirm and
execute then grew hello at its acceptance hash. The model
service itself grows bit-identically from recipes/model.json -
51d0afe0 under rustc 1.99.1 with its pinned dependencies.

## The seed manifest

The size law binds the seed and the grower, so what the seed carries
is a checkable document. "grower seed write <dir> <out.json>" pins
every file in a tree by hash and size, with the total the law
governs; "grower seed check <dir> <manifest.json>" walks the tree
again and names every missing, changed, or extra file. seed.json at
the root of this repository is the manifest of the seed you are
reading - run the check against a clone and it answers.

## The acceptance test

The grower recipe grows the grower from its own source. Built with
rustc 1.99.1 and the dependency versions pinned in grower/Cargo.lock,
the grown binary and the binary that grew it hash identically:

fbd7b6e84fbd967c1bdc47f11dbd48507e0d70c211f185c646225283f443da49

A second growth of the same derivation reproduces that hash, and a
one-line change to any pinned input makes the gate refuse the build.
The broker and the runner grow the same way, from recipes/broker.json
(broker 27d19a11dd952c1a41240810245ea51624c780527113c7086020fb44c33a98f0)
and recipes/runner.json (runner
bdc5747547c3fab91899dc1d066cf4ec4bfed55009dd5b97d8b186500fdf05e8) -
every tool the system trusts is one it can regrow from pinned source.
The runner's hash is stated under one condition: its dependency tree
includes a code generator that embeds the build directory in the
binary, so the runner recipe is grown with RUSTFLAGS carrying
--remap-path-prefix <build-dir>=/idem. With the prefix remapped, the
grown runner and a direct build hash identically; without it, the
two differ only in those embedded paths. That is the whole claim of the system, demonstrated at the smallest
scale before anything larger is built on it.

## Building

"cargo build --release" inside the grower directory builds the
binary. Cargo must be on the path when the grower recipe runs, since
its steps call cargo like any other tool.
