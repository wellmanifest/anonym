# Ticket 003: Harden anonym conformance against alias re-expansion, path leaks, and duplicate JSON keys

- **ID**: ticket-003
- **Owner**: tom
- **Status**: DONE
- **Workflow state**: PUBLICATION
- **Created**: 2026-11-11

## Goal and scope

Harden `wellmanifest/anonym` conformance in `operations/conformance.py` against
multi-pass alias re-expansion in `Anonymizer.resolve_selected`, colon/comma
home-path leaks and nested subpath misclassification in `HOME_RE`, duplicate
JSON keys and uncaught CLI input errors in `_read_json` / `main()`, and boolean
or non-string arguments in `render_preview`, `envelope`, and `MappingContext`.
Expand `operations/conformance_test.py`, add `pyproject.toml` for standalone
`pytest` execution, and reconcile `ticket-001` and `ticket-002`.

## Acceptance criteria

- [x] AC-01: Replace multi-pass `.replace()` in `Anonymizer.resolve_selected`
      with single-pass `ALIAS_RE.sub(...)` so resolved values containing shorter
      alias substrings cannot be re-expanded, and harden `HOME_RE` so
      `:`/`,`/`)`-delimited home paths are fully anonymized without misclassifying
      nested `/home/` subpaths.
- [x] AC-02: Enforce duplicate-key-rejecting `strict_loads` in `_read_json`,
      structured JSON error reporting in `main()`, and strict runtime type checks
      in `render_preview`, `envelope`, and `MappingContext`.
- [x] AC-03: Add regression tests in `operations/conformance_test.py`, add
      `pyproject.toml`, close `ticket-001` and `ticket-002`, and pass
      `ruff check operations`, `pytest -q`,
      `python3 operations/conformance.py self-test`,
      `./project/governance-check.sh --base origin/main`, and `wellman check`.

## Tracking boundary

This directory contains the minimal reviewed intent. Optional participant prose
and raw command logs are not required delivery output.
