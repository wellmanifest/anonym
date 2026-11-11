# Ticket 004: Harden anonym regular-file IO, strict JSON bounds, and key/category guards

- **ID**: ticket-004
- **Owner**: tom
- **Status**: IN_PROGRESS
- **Workflow state**: PUBLICATION
- **Created**: 2026-11-11

## Goal and scope

Harden `operations/conformance.py` against symlink/FIFO/oversized file and
stdin reads, non-finite or deeply nested JSON payloads, non-string object keys
in `validate_envelope`, invalid alias categories in `MappingContext`, and bare
string or non-string token iterables in `Anonymizer.resolve_selected`, add
regression tests in `operations/test_anonym_hardening.py`, and mark merged
`ticket-003` `DONE`.

## Acceptance criteria

- [x] AC-01: Enforce `O_NOFOLLOW | O_NONBLOCK` 4 MiB regular-file and bounded
      stdin reads, reject `NaN`/`Infinity`/`1e999`/`> 64` JSON depth, guard
      non-string envelope keys, category identifiers, and token iterables, and
      pass `ruff check operations`, `pytest -q`, and
      `python3 operations/conformance.py self-test`.
- [x] AC-02: Pass `./project/governance-check.sh --base origin/main` and
      `wellman check`.

## Tracking boundary

This directory contains the minimal reviewed intent. Optional participant prose
and raw command logs are not required delivery output.
