# Ticket 005: Harden anonym JSON overflow/surrogates, symlink ancestors/inodes, and alias/user validation

- **ID**: ticket-005
- **Owner**: tom
- **Status**: DONE
- **Workflow state**: MERGED
- **Created**: 2026-11-11

## Goal and scope

Harden `operations/conformance.py` against `10**400` JSON integer overflow,
lone UTF-16 surrogates across `strict_loads`, `validate_envelope`, and
`render_preview`, symlink ancestor traversal and `(st_dev, st_ino)` file-swap
races in `read_regular_utf8`, unsafe whitespace/slash/control characters in
`MappingContext` usernames, and `$` line-end regex anchors; expand
`operations/test_anonym_hardening.py`; and mark merged `ticket-004` `DONE`.

## Acceptance criteria

- [x] AC-01: Reject `10**400` integers, lone UTF-16 surrogates, symlink
      ancestors, `lstat`/`fstat` inode mismatches, and unsafe username
      characters, and pass `ruff check operations`, `pytest -q`, and
      `python3 operations/conformance.py self-test`.
- [x] AC-02: Mark merged `ticket-004` `DONE` and pass
      `./project/governance-check.sh --base origin/main` and `wellman check`.

## Tracking boundary

This directory contains the minimal reviewed intent. Optional participant prose
and raw command logs are not required delivery output.
