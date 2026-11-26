# capability_table

[![check](https://github.com/partsfoundry/capability_table/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/partsfoundry/capability_table/actions/workflows/ci.yml?query=branch%3Amain)
[![proofs](https://github.com/partsfoundry/capability_table/actions/workflows/proofs.yml/badge.svg?branch=main)](https://github.com/partsfoundry/capability_table/actions/workflows/proofs.yml?query=branch%3Amain)
[![license](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](https://github.com/partsfoundry/capability_table#license)
[![minimum Rust version](https://img.shields.io/badge/rust-1.85%2B-blue.svg)](https://github.com/partsfoundry/capability_table/blob/main/Cargo.toml)

A capability table for a kernel: a file descriptor table that can point at anything, where each
entry carries the rights its holder has over the object. The table lives in the kernel's memory and
a program sees only a slot number, so no program can forge a capability. A holder can only pass one
on, and a capability passed on never carries more than its source held. The crate is `no_std`, allocates
nothing, has no dependency and contains no `unsafe` code. The owner supplies the object type and the
size, which is part of the type.

## What it does

- `Rights` is a set of six rights (`READ`, `WRITE`, `GRANT`, `ENUMERATE`, `BIND`, `REVOKE`) with
  `union`, `intersect`, `allows` and `is_subset_of`, and no operation that widens. `from_bits`
  takes any 32-bit word, such as a system call register, and keeps only the defined bits.
- `Capability<O>` is an object and its rights. `delegate` copies it with narrower rights, and only
  when it holds `GRANT`. `mint_child` gives a new object the parent's rights exactly.
- `CapabilityTable<O, N>` has storage for `N` capabilities (at most `MAXIMUM_SLOTS`, 256) and a
  size chosen at creation: `new` takes all `N`, and `with_size` takes fewer. The size never changes,
  and no slot at or above it is ever filled. The free slots are a set of four 64-bit words, so
  finding one reads at most four words, and a lookup by slot costs one bounds check. `insert` takes the lowest free slot, `insert_at_or_above` the lowest at or above a
  floor, and `insert_at` a named empty slot; none overwrites a live capability. `derive` returns
  a copy of a slot with narrowed rights, for the caller to file in this table or another,
  `delete` empties a slot, `delete_matching` empties every slot whose object matches, and `iter`
  walks the occupied slots in order. `used` and `capacity` count the slots in use and the size.
- With the `peak` feature, `highest_seen` answers the highest occupancy any table in the program
  has reached, with that table's capacity.

## EXAMPLES

Rights narrow by intersection, so a capability passed on never carries more than its holder had.

```rust
use capability_table::Rights;

let held = Rights::READ.union(Rights::WRITE);
assert!(held.allows(Rights::READ));
assert!(!held.allows(Rights::GRANT));

// Handing it on with a mask can only ever narrow it.
let passed_on = held.intersect(Rights::READ.union(Rights::GRANT));
assert_eq!(passed_on, Rights::READ);
assert!(passed_on.is_subset_of(held));
```

No operation widens:

```rust
use capability_table::Rights;

let read_only = Rights::READ;
// The best you can do with ALL on the other side is get back what you already had.
assert_eq!(read_only.intersect(Rights::ALL), read_only);
assert!(!read_only.intersect(Rights::ALL).allows(Rights::WRITE));
```

## What is proven

Twelve [Kani](https://github.com/model-checking/kani) harnesses, in `mod verification` at the end of
`src/lib.rs`. The rights proofs hold for every one of the 2^31 words a `Rights` can hold (its top
bit is a marker, not a right). Each table proof states its bound as an assumption. It covers every size up to
67 slots and every state of two windows of three slots, with every other slot empty. One window
is the first three slots; the other is where the first free-slot word ends and the second begins
(62, 63 and 64). That
includes every state of every table of up to three slots, and every slot index.

- `subset_is_reflexive`: every set of rights is a subset of itself.
- `subset_is_transitive`: if B is within A and C within B, C is within A, so a chain of
  delegations can only narrow.
- `from_bits_cannot_forge_a_right`: for every 32-bit word, `from_bits` holds only defined rights.
- `subset_matches_allows`: `a.is_subset_of(b)` is exactly `b.allows(a)`.
- `the_count_is_the_slots`: `used` equals the number of occupied slots after every mutator.
- `the_free_mask_is_the_empty_slots`: the free-slot words are exactly the set of empty slots, hold
  no bit at or above the size, and no slot at or above the size is ever filled, after every
  mutator.
- `the_peak_never_falls_and_a_floor_insert_stays_above_its_floor`: no operation lowers a table's
  high-water mark, and `insert_at_or_above` never lands below its floor.
- `a_deleted_capability_stays_deleted`: once `delete` succeeds, the slot answers `NoSuchSlot` to
  `get` and to a second `delete`.
- `delete_touches_only_its_slot`: deleting a slot leaves every other slot as it was.
- `derive_never_widens_rights`: a successful `derive` returns exactly the rights asked for, and they
  are within the source's.
- `delegation_needs_grant_and_never_widens`: `delegate` succeeds exactly when the source holds
  `GRANT` and the request is within the source, and the copy holds exactly the request.
- `split_never_widens_rights`: `mint_child` gives the child exactly the parent's rights.

Each harness has a patch in `falsifications/` that breaks the property it proves, and the proof
fails on the patched code. Three things lie outside the proofs. Two are
tables past 67 slots and slots occupied outside the two windows, such as a full first word that
sends a plain `insert` into the second; the unit tests cover both up to `MAXIMUM_SLOTS`. The third
is `highest_seen`, which is one value shared by every table.

## Building and testing

```sh
cargo build
cargo test
rustup target add x86_64-unknown-none aarch64-unknown-none-softfloat riscv64imac-unknown-none-elf
cargo build --lib --target x86_64-unknown-none   # also aarch64-unknown-none-softfloat, riscv64imac-unknown-none-elf
```

Run `rustup target add` once, before the first bare-metal build. Without it, that build stops with
`can't find crate for core`. The tests run on the host in a fraction of a second.

### Running the proofs

The proofs need Kani, which `rustup` does not install. Install it once, with network access. Run
`cargo install --locked
kani-verifier --version 0.68.0`, then `cargo kani setup`, which downloads a model checker. CI uses
version 0.68.0, and another version may verify differently.

Then `cargo kani`, from the crate's directory, runs all twelve harnesses in under half a minute on
one development machine, most of it compiling. CI runs plain
`cargo kani`, with no extra flags. To run one harness, give its full path and `--exact`:

```sh
cargo kani --harness verification::derive_never_widens_rights --exact
```

A passing run prints several lines that look alarming. All of them are expected:

- `warning: use of an unstable feature`, about `#![feature(register_tool)]`, which Kani sets.
- `warning: Found the following unsupported constructs`, followed by "Verification will fail if
  one or more of these constructs is reachable". A run that ends in `VERIFICATION:- SUCCESSFUL`
  never reached them.
- Hundreds of `aborting path on assume(false)` lines. They mark paths that a harness's assumptions
  rule out.
- A check described as unreachable code. It reports code that cannot run, and it is no failure.
- Source paths under `/home/runner/.rustup`, a directory that does not exist on your machine. They
  come from the toolchain Kani ships.

Trust the last line of the run: `Complete - 12 successfully verified harnesses, 0 failures, 12 total.`

### Running one falsification patch

```sh
patch -p1 --no-backup-if-mismatch < falsifications/verification.derive_never_widens_rights.patch
cargo kani --harness verification::derive_never_widens_rights --exact   # ends VERIFICATION:- FAILED
git checkout -- src
```

The harness name is the part of the patch's file name after `verification.`. The run ends with
`Complete - 0 successfully verified harnesses, 1 failures, 1 total.`, and the failed check names
the assertion that the patch breaks. `git checkout -- src` reverts the patch.

## BUGS

- No table holds more than `MAXIMUM_SLOTS` (256) slots, and `CapabilityTable::new` refuses a larger
  `N` at compile time. The bound may grow and never shrinks. Every table carries all four free-slot
  words, 32 bytes, whatever its size.
- The storage is `N` slots whatever the size, so a table created smaller than `N` still occupies all
  `N`.
- `REVOKE` is a right like the others; this crate does not say which objects consult it.
- `highest_seen` is one value for the whole program, across every table of every size, which suits
  a kernel and surprises a library. It is behind the `peak` feature, off by default, and exists only
  on targets with 32-bit atomics.
- No enum is `#[non_exhaustive]`, so a variant added to `Error` after the first release breaks a
  caller's `match`.

## Minimum Rust version

1.85. To check it, install that toolchain and its bare-metal target, then test and build with it:

```sh
rustup toolchain install 1.85 --profile minimal --target x86_64-unknown-none
cargo +1.85 test
cargo +1.85 build --lib --target x86_64-unknown-none
```

## License

Licensed under either of the MIT license ([LICENSE-MIT](LICENSE-MIT)) or the Apache License,
Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE)), at your option.
