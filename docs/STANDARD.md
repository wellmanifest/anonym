# Wellmanifest Context-Preserving Anonymization Standard

Version: 0.1.0-dev
Contract: `wellmanifest.anonym/v1`

## Purpose

This domain pack defines how an adopting runtime removes sensitive identity
from diagnostic or operational text without destroying the relationships an
LLM needs to reason about it. It standardizes anonymized aliases, mapping
scope, transport separation, faithful previews and bounded deanonymization.

The standard does not execute commands, grant remediation authority, persist
secrets or host an anonymization service. An adopter such as FixOS or LLX owns
the runtime implementation and every effect boundary.

## Threat model and trust boundary

The trusted side may observe raw system diagnostics, paths and identifiers.
The untrusted side includes an LLM provider, prompts, remote telemetry,
provider-visible logs and any preview exported outside the local process.

An adopter MUST assume that:

1. repeated identifiers are useful for diagnosis;
2. raw identifiers and the reverse map are sensitive;
3. an LLM may invent or alter aliases;
4. model output is not execution authority;
5. formatting code can accidentally weaken anonymization even if transport
   code is correct.

## Terms

- **mapping context**: one explicitly identified local lifetime in which an
  original value maps to one stable alias;
- **alias**: an opaque token visible in the anonymized payload;
- **semantic token**: a non-numbered token that preserves a safe meaning but
  intentionally cannot identify or restore one original value;
- **reverse map**: local `alias -> original` state used only at a trusted
  boundary;
- **transport envelope**: the closed `wellmanifest.anonym/v1` object that may
  cross the LLM boundary and never contains the reverse map;
- **faithful preview**: a view derived from the already anonymized payload that
  does not rewrite alias bytes.

## Core requirements

1. Every anonymization operation MUST belong to a non-empty mapping context.
2. The same original entity and category MUST receive the same alias for the
   lifetime of that context.
3. Different contexts MUST NOT claim that equal aliases represent the same
   original entity. A protected persistent identity store is a separate
   adopter policy, not a default of this standard.
4. Aliases MUST be allocated independently per category in first-observation
   order. Allocation MUST NOT expose a hash, prefix or length of the original.
5. Already valid aliases MUST be protected from a second anonymization pass.
   Re-anonymizing an anonymized payload MUST preserve its text.
6. The reverse map MUST remain on the trusted side. It MUST NOT appear in the
   envelope, prompt, remote log, telemetry or preview.
7. Counts and digests MAY cross the boundary only when they contain no original
   values.

## Alias vocabulary

| Entity | Required token | Reversible |
| --- | --- | --- |
| primary local user | `[USER]` | yes, locally |
| other home user | `[USER-2]`, `[USER-3]`, ... | yes, locally |
| unspecified address `0.0.0.0` | `[IP-ANY]` | no |
| IPv4 loopback `127.0.0.0/8` | `[IP-LOOPBACK]` | no |
| limited broadcast `255.255.255.255` | `[IP-BROADCAST]` | no |
| RFC 1918 address | `[IP-PRIVATE-1]`, ... | yes, locally |
| global address | `[IP-PUBLIC-1]`, ... | yes, locally |
| link-local address | `[IP-LINKLOCAL-1]`, ... | yes, locally |
| multicast address | `[IP-MULTICAST-1]`, ... | yes, locally |
| other reserved/non-global address | `[IP-RESERVED-1]`, ... | yes, locally |
| UUID | `[UUID-1]`, `[UUID-2]`, ... | yes, locally |

`[USER]` is reserved for the adopter-supplied primary identity. Numbered
foreign users start at `2`, so `/home/[USER-2]` can never be mistaken for the
current user's home.

Additional categories such as hostnames, MAC addresses, emails and serials MAY
use the same uppercase, category-scoped numbered form. Credentials and secret
material SHOULD use irreversible redaction rather than a reversible alias.

## Structure-preserving paths

An adopter MUST separate the sensitive identity segment from the useful path
suffix. For example:

```text
/home/primary/.config/fixos/settings.toml
  -> /home/[USER]/.config/fixos/settings.toml

/home/alice/.cache/JetBrains/PyCharm/index
  -> /home/[USER-2]/.cache/JetBrains/PyCharm/index
```

Replacing an entire foreign path with `/home/[USER]/...` is non-conformant:
it merges distinct users and destroys the cache/application context.

Parsing SHOULD operate on structured path fields before regex fallback. A text
fallback MUST preserve separators and every non-sensitive suffix byte it can
unambiguously identify. Quoting and escaping belong to the adopter's command
parser and MUST NOT be invented by deanonymization.

## Network semantics

IPv4 candidates MUST be parsed as addresses, not accepted solely because four
numeric groups match a regex. Invalid candidates remain unchanged or produce a
local diagnostic; they MUST NOT receive a misleading IP alias.

The three semantic tokens retain operational meaning without creating a stable
device identity. Directed subnet broadcast requires prefix information and
MUST NOT be inferred from an address alone. When that context is unavailable,
only `255.255.255.255` is `[IP-BROADCAST]`.

Classification order is: unspecified, loopback, limited broadcast,
link-local, multicast, RFC 1918 private, global public, then reserved. This
order prevents libraries that broadly label non-global ranges as "private"
from erasing useful distinctions.

## Local reverse map and bounded resolution

The reverse map SHOULD be memory-only and scoped to the shortest useful
interaction, normally one HITL session or one agent turn chain. If persistence
is required, the adopter MUST protect it as sensitive local state, apply an
expiry and exclude it from repository history and remote logs.

Resolution MUST satisfy all of the following:

1. the envelope mapping identifier matches the selected local context;
2. every alias being resolved exists in that context;
3. the caller supplies the exact set of aliases allowed for the selected
   target or command;
4. unknown, semantic-only and unselected aliases fail closed;
5. the resolved command passes the adopter's normal validation, risk,
   confirmation and execution gates.

Possession of a reverse map, a valid alias or an LLM-produced command never
grants execution authority.

## Transport envelope

The only baseline transport object is the closed schema in
`models/anonymization-envelope.schema.json`. It contains:

- the contract identifier and policy;
- a non-secret mapping-context identifier;
- the anonymized payload;
- a SHA-256 digest of the exact UTF-8 payload bytes;
- per-category replacement counts.

The object has no extension point for a reverse map. Adopters requiring more
metadata MUST define a new version instead of adding unreviewed fields.

## Preview parity

A preview MUST be created from the already anonymized payload, never by
reanonymizing raw data. It MUST preserve token bytes including brackets and
numeric suffixes. In particular, replacing `[USER]` with `USER` merely to make
a structure parseable is non-conformant because the user no longer sees the
same representation sent to the LLM.

An untruncated preview MUST equal the outgoing payload. A truncated preview MAY
omit complete lines and add an explicit omission marker, but every displayed
payload line and alias MUST remain byte-identical. The preview MUST display or
otherwise bind the full `payloadSha256` so truncation cannot imply that only
the visible subset is transmitted.

## Processing order

An adopter SHOULD use this order:

1. classify structured fields and protect existing aliases;
2. irreversibly redact credentials and secret values;
3. anonymize primary literal identities such as known home and hostname;
4. anonymize structure-preserving paths;
5. parse and alias UUID, network and hardware identifiers;
6. apply bounded text fallbacks;
7. verify no prohibited originals remain;
8. create the envelope and derive the preview from its payload.

The final leak check MUST cover every outbound LLM boundary: initial
diagnostics, follow-up turns, command output, orchestrator evaluation and
retry/fallback requests.

## Conformance

A core-conformant adopter MUST pass the dependency-free suite in
`operations/conformance_test.py` or demonstrate equivalent cases. An
execution-capable adopter MUST additionally prove unknown-token rejection,
selected-token resolution and its independent command authorization gate.

The reference implementation is evidence and a portability aid. It does not
authorize effects and is not a production secret store.

## Responsibility boundaries

- `wellmanifest/anonym` owns alias, envelope, mapping and preview semantics.
- `wellmanifest/logs` owns safe event and diagnostic recording.
- `wellmanifest/dsl` owns machine-readable standard adoption projections.
- FixOS, LLX or another adopter owns detection coverage, local storage, UI,
  command parsing, confirmation and execution.
