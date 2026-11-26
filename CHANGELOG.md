# Changelog

Dates are UTC. One line per release, what changed and why, so a reader of the diff has the
sentence beside it.

## Unreleased

- First version.
- A table's size is chosen at creation (`with_size`) and never changes; `capacity` answers it.
- The free-slot set is four words, and `MAXIMUM_SLOTS` is 256: 39 slots is the largest table
  measured in use, and the bound gives it six times the room.
- A sixth right, `REVOKE`, bit 5. `Rights::ALL` includes it, and `from_bits` keeps it.
- `derive` takes a source slot and rights and returns the narrowed copy, for the caller to file in
  whichever table receives it: a delegation usually lands in another table, which the old
  slot-to-slot `derive` could not reach.
- `put` and the per-table `peak` are gone: no slot is overwritten any more, and a program reads the
  high-water mark through `highest_seen`, behind the `peak` feature.

## BUGS

- The template's lag check guards the CI pin, not this file; a change that matters to a user of
  the crate belongs in a release line here.
