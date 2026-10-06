# Ticket 001: Define context-preserving anonymization standard

- **ID**: ticket-001
- **Owner**: unresolved:human
- **Status**: IN_PROGRESS
- **Workflow state**: VALIDATION
- **Created**: 2026-09-01

## Goal and scope

Define a portable, machine-checkable anonymization contract derived from the
tested FixOS boundary and the reversible mapping behavior in `semcod/llx`.
The standard must preserve operational context without sending original
identifiers or a reverse map to an LLM.

The contract covers stable aliases within one explicit mapping context,
structure-preserving home paths, semantic IP classes, UUID identity, local
deanonymization and faithful previews. It is a Wellmanifest domain pack; it
does not execute commands or host an anonymization service.

## Acceptance criteria

- [x] AC-01: Repeated entities receive stable aliases within one mapping
  context, while unrelated contexts do not claim global identity stability.
- [x] AC-02: Home paths preserve their non-sensitive suffix and distinguish
  the primary user from foreign users without replacing the path by `...`.
- [x] AC-03: Any, loopback and limited-broadcast IPs retain semantic tokens;
  private, public, link-local, multicast and reserved addresses receive stable
  class-scoped aliases.
- [x] AC-04: The reverse map remains local and absent from the transport
  envelope; resolving selected paths does not grant command authority and
  rejects unknown or unselected aliases.
- [x] AC-05: Preview formatting preserves alias bytes such as `[USER]` and is
  bound to the exact outgoing payload digest.
- [x] AC-06: Re-anonymizing an already anonymized payload is idempotent.
- [x] AC-07: A closed JSON Schema and dependency-free reference conformance
  suite cover the normative behavior and reject tampering.
- [x] AC-08: Conformance, syntax, JSON, diff and managed governance checks pass.

## Session authorization and boundary

The user explicitly requested this standard in `wellmanifest/anonym`, based on
the already tested project behavior. This is recorded as
`SESSION_EXECUTION_AUTHORIZATION` for local repository bootstrap and bounded
implementation. It does not authorize creation of a GitHub repository, push,
pull request, merge, tag or release.

No secret-file access, provider request, system cleanup or deanonymized command
execution belongs to this ticket.

## Validation evidence

- Reference conformance: 14 tests passed.
- Built-in mutation/self-test: passed.
- Draft 2020-12 schema check and JSON parse: passed.
- Python compilation, Ruff check and Ruff format check: passed.
- Managed governance and diff checks: passed with zero findings.
- Publication is not attempted because the named GitHub repository does not
  exist and remote creation was not part of the recorded authorization.

## Placement

- HOME: `wellmanifest`
- SHAPE: `domain_pack`
- Runtime owner: `semcod`
- ADOPT: `wellmanifest/new-project`, `wellmanifest/dsl`, `wellmanifest/logs`
- Accepted local base: `b6a241744abc216118461b07fd70d3e532a419ac`

## Tracking boundary

This directory contains the minimal reviewed intent. Optional participant prose
and raw command logs are not required delivery output.
