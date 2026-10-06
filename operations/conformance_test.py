#!/usr/bin/env python3

from __future__ import annotations

import json
import unittest
from pathlib import Path

from conformance import (
    Anonymizer,
    MappingContext,
    ResolutionError,
    render_preview,
    validate_envelope,
)


class PathConformanceTest(unittest.TestCase):
    def test_home_suffix_and_user_identity_are_preserved(self) -> None:
        context = MappingContext(mapping_id="paths-1", primary_user="primary")
        anonymizer = Anonymizer(context)
        raw = (
            "/home/primary/.config/fixos/settings.toml "
            "/home/alice/.cache/JetBrains/PyCharm/index "
            "/home/alice/projects/api/pyproject.toml "
            "/home/bob/.local/share/app/state"
        )
        payload = anonymizer.anonymize(raw)

        self.assertIn("/home/[USER]/.config/fixos/settings.toml", payload)
        self.assertIn("/home/[USER-2]/.cache/JetBrains/PyCharm/index", payload)
        self.assertIn("/home/[USER-2]/projects/api/pyproject.toml", payload)
        self.assertIn("/home/[USER-3]/.local/share/app/state", payload)
        self.assertNotIn("/home/[USER]/...", payload)
        self.assertNotIn("alice", payload)

    def test_alias_is_stable_across_turns_in_one_context(self) -> None:
        context = MappingContext(mapping_id="session-42", primary_user="primary")
        anonymizer = Anonymizer(context)
        first = anonymizer.anonymize("/home/alice/.cache/a")
        second = anonymizer.anonymize("/home/alice/.config/b")
        self.assertIn("[USER-2]", first)
        self.assertIn("[USER-2]", second)

    def test_already_anonymized_path_is_idempotent(self) -> None:
        context = MappingContext(mapping_id="idempotent", primary_user="primary")
        anonymizer = Anonymizer(context)
        payload = "/home/[USER]/.cache /home/[USER-2]/.config [IP-PRIVATE-1] [UUID-1]"
        self.assertEqual(anonymizer.anonymize(payload), payload)


class NetworkAndIdentityConformanceTest(unittest.TestCase):
    def test_semantic_and_numbered_ip_aliases(self) -> None:
        context = MappingContext(mapping_id="network", primary_user="primary")
        anonymizer = Anonymizer(context)
        payload = anonymizer.anonymize(
            "0.0.0.0 127.0.0.1 127.0.0.2 255.255.255.255 "
            "192.168.1.10 192.168.1.10 8.8.8.8 169.254.1.4 "
            "224.0.0.1 192.0.2.1"
        )
        self.assertEqual(payload.count("[IP-LOOPBACK]"), 2)
        self.assertIn("[IP-ANY]", payload)
        self.assertIn("[IP-BROADCAST]", payload)
        self.assertEqual(payload.count("[IP-PRIVATE-1]"), 2)
        self.assertIn("[IP-PUBLIC-1]", payload)
        self.assertIn("[IP-LINKLOCAL-1]", payload)
        self.assertIn("[IP-MULTICAST-1]", payload)
        self.assertIn("[IP-RESERVED-1]", payload)

    def test_invalid_ipv4_candidate_is_not_misclassified(self) -> None:
        anonymizer = Anonymizer(MappingContext(mapping_id="invalid-ip"))
        self.assertEqual(anonymizer.anonymize("peer=999.2.3.4"), "peer=999.2.3.4")

    def test_uuid_alias_is_stable(self) -> None:
        anonymizer = Anonymizer(MappingContext(mapping_id="uuid"))
        raw_uuid = "123e4567-e89b-12d3-a456-426614174000"
        payload = anonymizer.anonymize(f"disk={raw_uuid} again={raw_uuid}")
        self.assertEqual(payload.count("[UUID-1]"), 2)
        self.assertNotIn(raw_uuid, payload)


class MappingAndTransportConformanceTest(unittest.TestCase):
    def test_reverse_map_is_local_and_absent_from_envelope(self) -> None:
        context = MappingContext(mapping_id="transport", primary_user="primary")
        anonymizer = Anonymizer(context)
        payload = anonymizer.anonymize("/home/alice/.cache peer=10.1.2.3")
        envelope = anonymizer.envelope(payload)
        serialized = json.dumps(envelope, sort_keys=True)

        self.assertNotIn("reverse_map", envelope)
        self.assertNotIn("reverseMap", envelope)
        self.assertNotIn("alice", serialized)
        self.assertNotIn("10.1.2.3", serialized)
        self.assertEqual(validate_envelope(envelope), [])

    def test_selected_path_can_be_resolved_locally(self) -> None:
        context = MappingContext(mapping_id="resolve", primary_user="primary")
        anonymizer = Anonymizer(context)
        payload = anonymizer.anonymize("rm -rf /home/alice/.cache/example")
        resolved = anonymizer.resolve_selected(payload, {"[USER-2]"})
        self.assertEqual(resolved, "rm -rf /home/alice/.cache/example")

    def test_unknown_unselected_and_semantic_tokens_fail_closed(self) -> None:
        context = MappingContext(mapping_id="reject", primary_user="primary")
        anonymizer = Anonymizer(context)
        known = anonymizer.anonymize("/home/alice/.cache")
        with self.assertRaisesRegex(ResolutionError, "unselected_alias"):
            anonymizer.resolve_selected(known, set())
        with self.assertRaisesRegex(ResolutionError, "unknown_or_semantic_alias"):
            anonymizer.resolve_selected("/home/[USER-99]/.cache", {"[USER-99]"})
        with self.assertRaisesRegex(ResolutionError, "unknown_or_semantic_alias"):
            anonymizer.resolve_selected("listen [IP-ANY]", {"[IP-ANY]"})

    def test_mapping_contexts_do_not_share_identity(self) -> None:
        left = Anonymizer(MappingContext(mapping_id="left", primary_user="primary"))
        right = Anonymizer(MappingContext(mapping_id="right", primary_user="primary"))
        left_payload = left.anonymize("/home/alice/.cache")
        right_payload = right.anonymize("/home/bob/.cache")
        self.assertIn("[USER-2]", left_payload)
        self.assertIn("[USER-2]", right_payload)
        self.assertNotEqual(left.context.reverse_map, right.context.reverse_map)

    def test_preview_keeps_exact_alias_bytes_and_full_digest(self) -> None:
        context = MappingContext(mapping_id="preview", primary_user="primary")
        anonymizer = Anonymizer(context)
        payload = anonymizer.anonymize("cwd=/home/primary/project\npeer=192.168.1.8\n")
        envelope = anonymizer.envelope(payload)
        preview = render_preview(payload)

        self.assertEqual(preview["text"], payload)
        self.assertIn("[USER]", preview["text"])
        self.assertIn("[IP-PRIVATE-1]", preview["text"])
        self.assertEqual(preview["payloadSha256"], envelope["payloadSha256"])
        self.assertFalse(preview["truncated"])

    def test_truncated_preview_preserves_displayed_tokens(self) -> None:
        payload = "\n".join(f"line-{index} [USER-2]" for index in range(10)) + "\n"
        preview = render_preview(payload, max_lines=5)
        self.assertTrue(preview["truncated"])
        self.assertIn("[USER-2]", preview["text"])
        self.assertNotIn("USER-2", preview["text"].replace("[USER-2]", ""))

    def test_envelope_tampering_and_reverse_map_field_are_rejected(self) -> None:
        anonymizer = Anonymizer(MappingContext(mapping_id="tamper"))
        envelope = anonymizer.envelope(anonymizer.anonymize("peer=8.8.8.8"))
        envelope["payload"] += " changed"
        self.assertIn("payloadSha256:mismatch", validate_envelope(envelope))
        envelope["reverseMap"] = {"[IP-PUBLIC-1]": "8.8.8.8"}
        self.assertIn("unexpected:reverseMap", validate_envelope(envelope))

    def test_schema_is_closed_and_names_the_contract(self) -> None:
        schema_path = (
            Path(__file__).parents[1] / "models/anonymization-envelope.schema.json"
        )
        schema = json.loads(schema_path.read_text(encoding="utf-8"))
        self.assertFalse(schema["additionalProperties"])
        self.assertEqual(
            schema["properties"]["schema"]["const"], "wellmanifest.anonym/v1"
        )
        self.assertNotIn("reverseMap", schema["properties"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
