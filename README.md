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
binary with three commands.

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

## The acceptance test

The grower recipe grows the grower from its own source. Built with
rustc 1.99.1 and the dependency versions pinned in grower/Cargo.lock,
the grown binary and the binary that grew it hash identically:

b176620ff72e30a858b1d96ae731b06ad60d8879fcc6d9e77d23f0161f7eac7e

A second growth of the same derivation reproduces that hash, and a
one-line change to any pinned input makes the gate refuse the build.
That is the whole claim of the system, demonstrated at the smallest
scale before anything larger is built on it.

## Building

"cargo build --release" inside the grower directory builds the
binary. Cargo must be on the path when the grower recipe runs, since
its steps call cargo like any other tool.
