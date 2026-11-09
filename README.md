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
acceptance by reproduction, not by signature. An accepted edition is
chained into an append-only log, each line carrying the hash of the
line before it, and "grower edition log <log-file>" verifies the
chain end to end. A capsule with one byte changed is refused before
anything grows.

## The acceptance test

The grower recipe grows the grower from its own source. Built with
rustc 1.99.1 and the dependency versions pinned in grower/Cargo.lock,
the grown binary and the binary that grew it hash identically:

49f1a8cc55dbaf2cc6688daa3d52e0d3d70031222d6248adc8b5d933330ba04c

A second growth of the same derivation reproduces that hash, and a
one-line change to any pinned input makes the gate refuse the build.
That is the whole claim of the system, demonstrated at the smallest
scale before anything larger is built on it.

## Building

"cargo build --release" inside the grower directory builds the
binary. Cargo must be on the path when the grower recipe runs, since
its steps call cargo like any other tool.
