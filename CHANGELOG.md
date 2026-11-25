# Changelog

Dates are UTC. One line per release, what changed and why, so a reader of the diff has the
sentence beside it.

## Unreleased

- First version.
- A sixth right, `REVOKE`, bit 5. `Rights::ALL` includes it, and `from_bits` keeps it.

## BUGS

- The template's lag check guards the CI pin, not this file; a change that matters to a user of
  the crate belongs in a release line here.
