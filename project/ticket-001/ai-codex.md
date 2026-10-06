---
participant-id: agent:codex
participant: codex
role: agent
ticket: ticket-001
---
# Participant: codex

## Understanding

FixOS already anonymizes every LLM boundary, but its fallback home-path regex
collapses useful suffixes to a generic user-home ellipsis, IPv4 masking loses entity
identity and semantic addresses, and the preview parser temporarily removes
placeholder brackets. LLX demonstrates the useful complementary property: a
local token-to-original mapping can make selected output reversible.

The standard combines these lessons without copying runtime authority. Alias
stability is scoped to one mapping context, the transmitted envelope never
contains the reverse map, and resolving a path still requires the adopter's
normal command validation and human/agent authority checks.

## Execution plan

1. Define the threat model, alias vocabulary and mapping lifecycle.
2. Specify structure-preserving home paths and semantic network aliases.
3. Specify transport/preview parity and a closed envelope schema.
4. Add a dependency-free reference implementation and mutation tests.
5. Run deterministic conformance and the managed governance gate.

## Authorization

`SESSION_EXECUTION_AUTHORIZATION` comes from the request to add this standard
to `wellmanifest/anonym`. It covers the local baseline and bounded ticket
implementation only. The repository does not exist on GitHub, so remote
creation and publication remain outside this authorization.

## Actual changes

- Defined `wellmanifest.anonym/v1` with scoped stable aliases and explicit
  non-global identity semantics.
- Preserved home-path suffixes while reserving `[USER]` for the primary user
  and starting foreign users at `[USER-2]`.
- Defined semantic and numbered IPv4 classes plus stable UUID aliases.
- Separated the closed transport envelope from local reverse-map state.
- Made selected-token resolution fail closed for unknown, semantic-only and
  unselected aliases without granting command authority.
- Bound faithful previews to the exact outgoing payload digest and prohibited
  display-only bracket stripping.
- Added a dependency-free reference implementation and 14 conformance tests.
