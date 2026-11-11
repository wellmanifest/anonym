#!/usr/bin/env python3
"""Pure reference conformance for wellmanifest.anonym/v1."""

from __future__ import annotations

import argparse
import ipaddress
import json
import re
import sys
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

_OPS_DIR = str(Path(__file__).resolve().parent)
if _OPS_DIR not in sys.path:
    sys.path.insert(0, _OPS_DIR)

from anonym_io import (  # noqa: E402
    MAX_FILE_BYTES,
    MAX_JSON_DEPTH,
    _check_utf8_str,
    _sha256,
    read_json_input,
    read_regular_utf8,
    strict_loads,
)

__all__ = [
    "ALIAS_RE",
    "CATEGORY_RE",
    "ENVELOPE_FIELDS",
    "HOME_RE",
    "IPV4_RE",
    "MAPPING_ID_RE",
    "MAX_FILE_BYTES",
    "MAX_JSON_DEPTH",
    "POLICY_ID",
    "RFC1918",
    "SCHEMA_ID",
    "SEMANTIC_IPS",
    "SHA256_RE",
    "UUID_RE",
    "Anonymizer",
    "MappingContext",
    "ResolutionError",
    "main",
    "read_regular_utf8",
    "render_preview",
    "strict_loads",
    "validate_envelope",
]

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
MAPPING_ID_RE = re.compile(r"\A[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
CATEGORY_RE = re.compile(r"\A[A-Z][A-Z0-9-]*\Z")
SHA256_RE = re.compile(r"\A[0-9a-f]{64}\Z")
ALIAS_RE = re.compile(
    r"\[(?:USER(?:-[0-9]+)?|UUID-[0-9]+|"
    r"IP-(?:ANY|LOOPBACK|BROADCAST|"
    r"(?:PRIVATE|PUBLIC|LINKLOCAL|MULTICAST|RESERVED)-[0-9]+))\]"
)
HOME_RE = re.compile(
    r"(?<![A-Za-z0-9._\-\]])/home/"
    r"(?P<user>(?!\[USER(?:-[0-9]+)?\](?:/|$|[:;,)\]\s\"'\\]))[^/\s\"'\\:;,)[\]]+)"
    r"(?P<suffix>(?:/[^\s\"'\\:;,)[\]]*)?)"
)
IPV4_RE = re.compile(r"(?<![A-Za-z0-9_.:])(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?![A-Za-z0-9_.:])")
UUID_RE = re.compile(
    r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
    r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b"
)
RFC1918 = tuple(
    ipaddress.ip_network(network) for network in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")
)
SEMANTIC_IPS = {
    "0.0.0.0": "[IP-ANY]",
    "255.255.255.255": "[IP-BROADCAST]",
}


class ResolutionError(ValueError):
    """Raised when local alias resolution cannot be proven safe."""


def _is_safe_username(value: Any) -> bool:
    if not isinstance(value, str) or not value:
        return False
    try:
        _check_utf8_str(value)
    except ValueError:
        return False
    return not any(ord(ch) <= 32 or ord(ch) == 127 or ch in "/\\:;,)\"'[]" for ch in value)


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
        if not isinstance(self.mapping_id, str) or not MAPPING_ID_RE.fullmatch(self.mapping_id):
            raise ValueError("mapping_id must match the envelope mappingId contract")
        if self.primary_user is not None and not _is_safe_username(self.primary_user):
            raise ValueError("primary_user must be None or a safe non-empty username")
        if not isinstance(self.reverse_map, dict):
            raise TypeError("reverse_map must be a dict")
        semantic_tokens = {"[IP-ANY]", "[IP-BROADCAST]", "[IP-LOOPBACK]"}
        for tok, orig in self.reverse_map.items():
            if (
                not isinstance(tok, str)
                or tok in semantic_tokens
                or not ALIAS_RE.fullmatch(tok)
                or not isinstance(orig, str)
                or not orig
            ):
                raise ValueError(
                    "reverse_map entries must map valid non-semantic aliases to strings"
                )
            _check_utf8_str(orig)

    def _record(self, category: str) -> None:
        self._occurrences[category] = self._occurrences.get(category, 0) + 1

    def _numbered_alias(self, category: str, original: str, *, start: int = 1) -> str:
        if not isinstance(category, str) or not CATEGORY_RE.fullmatch(category):
            raise ValueError(f"invalid alias category: {category!r}")
        if not isinstance(original, str) or not original:
            raise ValueError("original value must be a non-empty string")
        _check_utf8_str(original)
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
        if not _is_safe_username(username):
            raise ValueError("username must be a safe non-empty string")
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
        _check_utf8_str(text)
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
        if not isinstance(payload, str):
            raise TypeError("payload must be a string")
        return {
            "schema": SCHEMA_ID,
            "policy": POLICY_ID,
            "mappingId": self.context.mapping_id,
            "payload": payload,
            "payloadSha256": _sha256(payload),
            "aliasCounts": self.context.alias_counts,
        }

    def resolve_selected(self, text: str, allowed_tokens: Iterable[str]) -> str:
        if not isinstance(text, str):
            raise TypeError("text must be a string")
        _check_utf8_str(text)
        if isinstance(allowed_tokens, (str, bytes)):
            raise TypeError("allowed_tokens must be an iterable of token strings")
        allowed: set[str] = set()
        for token in allowed_tokens:
            if not isinstance(token, str):
                raise TypeError("allowed_tokens items must be strings")
            allowed.add(token)
        observed = set(ALIAS_RE.findall(text))
        unknown = sorted(observed - set(self.context.reverse_map))
        if unknown:
            raise ResolutionError(f"unknown_or_semantic_alias:{','.join(unknown)}")
        unselected = sorted(observed - allowed)
        if unselected:
            raise ResolutionError(f"unselected_alias:{','.join(unselected)}")

        for tok in observed:
            mapped = self.context.reverse_map[tok]
            if not isinstance(mapped, str) or not mapped:
                raise ResolutionError(f"invalid_reverse_map_value:{tok}")
            try:
                _check_utf8_str(mapped)
            except ValueError as exc:
                raise ResolutionError(f"invalid_reverse_map_value:{tok}") from exc
        return ALIAS_RE.sub(lambda match: self.context.reverse_map[match.group(0)], text)


def render_preview(payload: str, max_lines: int = 80) -> dict[str, Any]:
    """Render only anonymized bytes and bind any truncation to the full digest."""
    if not isinstance(payload, str):
        raise TypeError("payload must be a string")
    if isinstance(max_lines, bool) or not isinstance(max_lines, int):
        raise TypeError("max_lines must be an integer")
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
    if any(not isinstance(key, str) for key in envelope):
        errors.append("envelope:non_string_key")
    str_keys = {key for key in envelope if isinstance(key, str)}
    for field_name in sorted(ENVELOPE_FIELDS - str_keys):
        errors.append(f"missing:{field_name}")
    for field_name in sorted(str_keys - ENVELOPE_FIELDS):
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
    payload_utf8 = False
    if not isinstance(payload, str):
        errors.append("payload:not_string")
    else:
        try:
            _check_utf8_str(payload)
            if len(payload.encode("utf-8")) > MAX_FILE_BYTES:
                errors.append("payload:too_large")
            else:
                payload_utf8 = True
        except ValueError:
            errors.append("payload:invalid_utf8")
    digest = envelope["payloadSha256"]
    if not isinstance(digest, str) or not SHA256_RE.fullmatch(digest):
        errors.append("payloadSha256:invalid")
    elif payload_utf8 and digest != _sha256(payload):
        errors.append("payloadSha256:mismatch")

    counts = envelope["aliasCounts"]
    if not isinstance(counts, dict):
        errors.append("aliasCounts:not_object")
    else:
        for category, count in counts.items():
            if not isinstance(category, str) or not CATEGORY_RE.fullmatch(category):
                errors.append("aliasCounts:invalid_category")
            if type(count) is not int or count < 1 or count > MAX_FILE_BYTES:
                errors.append(f"aliasCounts:invalid_count:{category}")
    return errors


def _self_test() -> None:
    context = MappingContext(mapping_id="self-test", primary_user="local")
    anonymizer = Anonymizer(context)
    raw = (
        "PATH=/home/local/bin:/home/remote/.cache/app "
        "peer=192.168.10.2 uuid=123e4567-e89b-12d3-a456-426614174000"
    )
    payload = anonymizer.anonymize(raw)
    envelope = anonymizer.envelope(payload)
    assert not validate_envelope(envelope)
    assert "local" not in payload and "remote" not in payload and "192.168.10.2" not in payload
    assert "reverse_map" not in envelope
    assert anonymizer.anonymize(payload) == payload


def _read_json(path: str) -> Any:
    return read_json_input(path)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser("self-test")
    validate = subparsers.add_parser("validate")
    validate.add_argument("envelope", help="Envelope JSON file or - for stdin")
    args = parser.parse_args(argv)

    if args.command == "self-test":
        _self_test()
        print("anonym conformance self-test: PASS")
        return 0

    try:
        data = _read_json(args.envelope)
    except (OSError, UnicodeDecodeError, ValueError, TypeError) as exc:
        errors = [f"input:{exc}"]
    else:
        errors = validate_envelope(data)
    print(json.dumps({"ok": not errors, "errors": errors}, indent=2, allow_nan=False))
    return 0 if not errors else 1


if __name__ == "__main__":
    raise SystemExit(main())
