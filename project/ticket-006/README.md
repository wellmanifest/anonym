# Ticket 006: Modularize anonym_io and harden relative symlink traversal, JSON digit/surrogate bounds, and bracketed home paths

- **ID**: ticket-006
- **Owner**: tom
- **Status**: DONE
- **Workflow state**: DONE
- **Created**: 2026-11-11

## Goal and scope

SESSION_EXECUTION_AUTHORIZATION: On 2026-11-11 user authorized auditing, fixing bugs, optimizing, and hardening `wellmanifest/*` standard repositories.

Extract bounded regular-file/stdin UTF-8 I/O and strict JSON parsing into `operations/anonym_io.py` so `operations/conformance.py` drops well below 500 lines; prevent relative `sym_dir/..` symlink-parent traversal in `read_regular_utf8`; bound JSON integer digit length before `int()` conversion in `strict_loads`; reject `[` / `]` alias-delimiter characters and lone UTF-16 surrogates in usernames as well as `Anonymizer.anonymize`, `Anonymizer.resolve_selected`, and `MappingContext.numbered_alias`; preserve closing brackets on bracketed Unix home paths while keeping `HOME_RE` idempotent; expand `operations/test_anonym_hardening.py`; and reconcile merged `project/ticket-005/README.md` status to `DONE`.

## Acceptance criteria

- [x] AC-01: Extract `operations/anonym_io.py` (< 500L), block `sym_dir/..` relative symlink traversal in `read_regular_utf8`, bound JSON integer digits before `int()`, reject bracket characters in usernames and lone UTF-16 surrogates across `Anonymizer`/`MappingContext`, anonymize bracketed Unix home paths idempotently without consuming outer `]`, and mark `project/ticket-005/README.md` `DONE`.
- [x] AC-02: All Python modules in `operations/` remain strictly `< 500` lines and pass `ruff check --no-cache operations`, `PYTHONDONTWRITEBYTECODE=1 python3 -m pytest -q -p no:cacheprovider`, `python3 operations/conformance.py self-test`, `./project/governance-check.sh --base origin/main`, and `wellman check` with 0 errors.

## Tracking boundary

This directory contains the minimal reviewed intent. Optional participant prose
and raw command logs are not required delivery output.
