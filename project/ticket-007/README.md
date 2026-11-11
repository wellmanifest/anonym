# Ticket 007: Harden anonym_io symlink-parent traversal, reverse_map invariants, and envelope bounds

- **ID**: ticket-007
- **Owner**: tom
- **Status**: IN_PROGRESS
- **Workflow state**: EDIT
- **Created**: 2026-11-11

## Goal and scope

SESSION_EXECUTION_AUTHORIZATION: On 2026-11-11 user authorized auditing, fixing bugs, optimizing, and hardening `wellmanifest/*` standard repositories.

Harden `_check_no_symlink_ancestors` in `operations/anonym_io.py` against un-normalized absolute (`sym_dir/../real`) and sibling relative (`../sym_dir`) symlink-parent traversal before `os.path.abspath` and declare `__all__`; enforce `MappingContext.reverse_map` token/UTF-8 invariants in `__post_init__` and `Anonymizer.resolve_selected`; bound programmatic `validate_envelope` payload byte length (`<= MAX_FILE_BYTES`) and pass `allow_nan=False` in `conformance.main`; expand `operations/test_anonym_hardening.py`; and reconcile merged `project/ticket-006/README.md` status to `DONE`.

## Acceptance criteria

- [x] AC-01: Reject un-normalized absolute and sibling relative symlink-parent traversal in `_check_no_symlink_ancestors`, declare `anonym_io.__all__`, enforce `reverse_map` alias/UTF-8 invariants in `MappingContext.__post_init__` and `Anonymizer.resolve_selected`, bound `validate_envelope` payload byte length, pass `allow_nan=False` in `main`, and mark `project/ticket-006/README.md` `DONE`.
- [x] AC-02: All Python modules in `operations/` remain strictly `< 500` lines and pass `ruff check --no-cache operations`, `PYTHONDONTWRITEBYTECODE=1 python3 -m pytest -q -p no:cacheprovider`, `python3 operations/conformance.py self-test`, `./project/governance-check.sh --base origin/main`, and `wellman check` with 0 errors.

## Tracking boundary

This directory contains the minimal reviewed intent. Optional participant prose
and raw command logs are not required delivery output.
