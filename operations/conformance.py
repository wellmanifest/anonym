#!/usr/bin/env python3
"""Pure reference conformance for wellmanifest.anonym/v1."""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable


SCHEMA_ID = "wellmanifest.anonym/v1"
POLICY_ID = "context-preserving-v1"
ENVELOPE_FIELDS = {
    "schema",
    "policy",
    "mappingId",
    "payload",
    "payloadSha256",
    "aliasCounts",
}
MAPPING_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
CATEGORY_RE = re.compile(r"^[A-Z][A-Z0-9-]*$")
ALIAS_RE = re.compile(
    r"\[(?:USER(?:-[0-9]+)?|UUID-[0-9]+|"
    r"IP-(?:ANY|LOOPBACK|BROADCAST|"
    r"(?:PRIVATE|PUBLIC|LINKLOCAL|MULTICAST|RESERVED)-[0-9]+))\]"
)
HOME_RE = re.compile(
    r"/home/(?P<user>(?!\[USER(?:-[0-9]+)?\](?:/|$))[^/\s\"'\\]+)"
    r"(?P<suffix>(?:/[^\s\"'\\]*)?)"
)
IPV4_RE = re.compile(
    r"(?<![A-Za-z0-9_.:])(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?![A-Za-z0-9_.:])"
)
UUID_RE = re.compile(
    r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
    r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b"
)
RFC1918 = tuple(
    ipaddress.ip_network(network)
    for network in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")
)
SEMANTIC_IPS = {
    "0.0.0.0": "[IP-ANY]",
    "255.255.255.255": "[IP-BROADCAST]",
}


class ResolutionError(ValueError):
    """Raised when local alias resolution cannot be proven safe."""


@dataclass
class MappingContext:
    """Local-only mapping state; never serialize this object into an envelope."""

    mapping_id: str
    primary_user: str | None = None
    reverse_map: dict[str, str] = field(default_factory=dict)
    _aliases: dict[tuple[str, str], str] = field(default_factory=dict)
    _next_index: dict[str, int] = field(default_factory=dict)
    _occurrences: dict[str, int] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not MAPPING_ID_RE.fullmatch(self.mapping_id):
            raise ValueError("mapping_id must match the envelope mappingId contract")

    def _record(self, category: str) -> None:
        self._occurrences[category] = self._occurrences.get(category, 0) + 1

    def _numbered_alias(self, category: str, original: str, *, start: int = 1) -> str:
        key = (category, original)
        existing = self._aliases.get(key)
        if existing is not None:
            self._record(category)
            return existing

        index = self._next_index.get(category, start)
        token = f"[{category}-{index}]"
        self._next_index[category] = index + 1
        self._aliases[key] = token
        self.reverse_map[token] = original
        self._record(category)
        return token

    def user_alias(self, username: str) -> str:
        if self.primary_user is not None and username == self.primary_user:
            token = "[USER]"
            existing = self.reverse_map.get(token)
            if existing is not None and existing != username:
                raise ValueError("primary user alias collision")
            self.reverse_map[token] = username
            self._aliases[("USER", username)] = token
            self._record("USER")
            return token
        return self._numbered_alias("USER", username, start=2)

    def numbered_alias(self, category: str, original: str) -> str:
        return self._numbered_alias(category, original)

    @property
    def alias_counts(self) -> dict[str, int]:
        return dict(sorted(self._occurrences.items()))


class Anonymizer:
    """Dependency-free reference implementation for the baseline categories."""

    def __init__(self, context: MappingContext):
        self.context = context

    def anonymize(self, text: str) -> str:
        if not isinstance(text, str):
            raise TypeError("text must be a string")
        result = HOME_RE.sub(self._replace_home, text)
        result = UUID_RE.sub(self._replace_uuid, result)
        return IPV4_RE.sub(self._replace_ipv4, result)

    def _replace_home(self, match: re.Match[str]) -> str:
        alias = self.context.user_alias(match.group("user"))
        return f"/home/{alias}{match.group('suffix')}"

    def _replace_uuid(self, match: re.Match[str]) -> str:
        original = match.group(0)
        return self.context.numbered_alias("UUID", original)

    def _replace_ipv4(self, match: re.Match[str]) -> str:
        original = match.group(0)
        try:
            address = ipaddress.IPv4Address(original)
        except ipaddress.AddressValueError:
            return original

        semantic = SEMANTIC_IPS.get(original)
        if semantic is not None:
            self.context._record(semantic[1:-1])
            return semantic
        if address.is_loopback:
            self.context._record("IP-LOOPBACK")
            return "[IP-LOOPBACK]"
        if address.is_link_local:
            category = "IP-LINKLOCAL"
        elif address.is_multicast:
            category = "IP-MULTICAST"
        elif any(address in network for network in RFC1918):
            category = "IP-PRIVATE"
        elif address.is_global:
            category = "IP-PUBLIC"
        else:
            category = "IP-RESERVED"
        return self.context.numbered_alias(category, original)

    def envelope(self, payload: str) -> dict[str, Any]:
        return {
            "schema": SCHEMA_ID,
            "policy": POLICY_ID,
            "mappingId": self.context.mapping_id,
            "payload": payload,
            "payloadSha256": _sha256(payload),
            "aliasCounts": self.context.alias_counts,
        }

    def resolve_selected(self, text: str, allowed_tokens: Iterable[str]) -> str:
        allowed = set(allowed_tokens)
        observed = set(ALIAS_RE.findall(text))
        unknown = sorted(observed - set(self.context.reverse_map))
        if unknown:
            raise ResolutionError(f"unknown_or_semantic_alias:{','.join(unknown)}")
        unselected = sorted(observed - allowed)
        if unselected:
            raise ResolutionError(f"unselected_alias:{','.join(unselected)}")

        result = text
        for token in sorted(observed, key=len, reverse=True):
            result = result.replace(token, self.context.reverse_map[token])
        return result


def _sha256(payload: str) -> str:
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def render_preview(payload: str, max_lines: int = 80) -> dict[str, Any]:
    """Render only anonymized bytes and bind any truncation to the full digest."""
    if max_lines < 3:
        raise ValueError("max_lines must be at least 3")
    lines = payload.splitlines(keepends=True)
    if len(lines) <= max_lines:
        text = payload
        truncated = False
    else:
        kept = max_lines - 1
        first = kept // 2
        last = kept - first
        omitted = len(lines) - kept
        marker = f"[... {omitted} complete lines omitted ...]\n"
        text = "".join(lines[:first] + [marker] + lines[-last:])
        truncated = True
    return {
        "text": text,
        "payloadSha256": _sha256(payload),
        "truncated": truncated,
    }


def validate_envelope(envelope: Any) -> list[str]:
    errors: list[str] = []
    if not isinstance(envelope, dict):
        return ["envelope:not_object"]
    for field_name in sorted(ENVELOPE_FIELDS - set(envelope)):
        errors.append(f"missing:{field_name}")
    for field_name in sorted(set(envelope) - ENVELOPE_FIELDS):
        errors.append(f"unexpected:{field_name}")
    if errors:
        return errors

    if envelope["schema"] != SCHEMA_ID:
        errors.append("schema:unsupported")
    if envelope["policy"] != POLICY_ID:
        errors.append("policy:unsupported")
    if not isinstance(envelope["mappingId"], str) or not MAPPING_ID_RE.fullmatch(
        envelope["mappingId"]
    ):
        errors.append("mappingId:invalid")
    payload = envelope["payload"]
    if not isinstance(payload, str):
        errors.append("payload:not_string")
    digest = envelope["payloadSha256"]
    if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest):
        errors.append("payloadSha256:invalid")
    elif isinstance(payload, str) and digest != _sha256(payload):
        errors.append("payloadSha256:mismatch")

    counts = envelope["aliasCounts"]
    if not isinstance(counts, dict):
        errors.append("aliasCounts:not_object")
    else:
        for category, count in counts.items():
            if not isinstance(category, str) or not CATEGORY_RE.fullmatch(category):
                errors.append("aliasCounts:invalid_category")
            if isinstance(count, bool) or not isinstance(count, int) or count < 1:
                errors.append(f"aliasCounts:invalid_count:{category}")
    return errors


def _self_test() -> None:
    context = MappingContext(mapping_id="self-test", primary_user="local")
    anonymizer = Anonymizer(context)
    raw = "/home/remote/.cache/app peer=192.168.10.2 uuid=123e4567-e89b-12d3-a456-426614174000"
    payload = anonymizer.anonymize(raw)
    envelope = anonymizer.envelope(payload)
    assert not validate_envelope(envelope)
    assert "remote" not in payload and "192.168.10.2" not in payload
    assert "reverse_map" not in envelope
    assert anonymizer.anonymize(payload) == payload


def _read_json(path: str) -> Any:
    if path == "-":
        return json.load(sys.stdin)
    return json.loads(Path(path).read_text(encoding="utf-8"))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser("self-test")
    validate = subparsers.add_parser("validate")
    validate.add_argument("envelope", help="Envelope JSON file or - for stdin")
    args = parser.parse_args()

    if args.command == "self-test":
        _self_test()
        print("anonym conformance self-test: PASS")
        return 0

    errors = validate_envelope(_read_json(args.envelope))
    print(json.dumps({"ok": not errors, "errors": errors}, indent=2))
    return 0 if not errors else 1


if __name__ == "__main__":
    raise SystemExit(main())
