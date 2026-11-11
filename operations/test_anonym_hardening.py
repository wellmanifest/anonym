"""Adversarial regression tests for wellmanifest/anonym JSON, IO, and key/category guards."""

from __future__ import annotations

import io
import json
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from typing import Any

import conformance


class AnonymHardeningTests(unittest.TestCase):
    def test_strict_loads_rejects_non_finite_float_overflow_and_deep_nesting(self) -> None:
        for payload in (
            '{"x": NaN}',
            '{"x": Infinity}',
            '{"x": -Infinity}',
            '{"x": 1e999}',
            '{"x": -1e999}',
            ("[" * 66) + "1" + ("]" * 66),
            ("[" * 1500) + "1" + ("]" * 1500),
        ):
            with self.subTest(payload=payload[:32]):
                with self.assertRaises(ValueError):
                    conformance.strict_loads(payload)

    def test_regular_file_reader_and_cli_reject_symlinks_and_oversized_files(self) -> None:
        ctx = conformance.MappingContext(mapping_id="test-map", primary_user="alice")
        env = conformance.Anonymizer(ctx).envelope("hello")
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            real_path = base / "envelope.json"
            real_path.write_text(json.dumps(env), encoding="utf-8")
            sym_path = base / "sym-envelope.json"
            sym_path.symlink_to(real_path)

            with self.assertRaises(OSError):
                conformance.read_regular_utf8(sym_path)

            out = io.StringIO()
            with redirect_stdout(out):
                rc = conformance.main(["validate", str(sym_path)])
            self.assertEqual(rc, 1)
            report = json.loads(out.getvalue())
            self.assertFalse(report["ok"])
            self.assertTrue(any("symlink" in err.lower() for err in report["errors"]))

            big_path = base / "oversized.json"
            pad = b"x" * (conformance.MAX_FILE_BYTES + 32)
            big_path.write_bytes(b'{"a":"' + pad + b'"}')
            with self.assertRaises(ValueError):
                conformance.read_regular_utf8(big_path)

    def test_validate_envelope_handles_non_string_keys_without_type_error(self) -> None:
        bad_env: dict[Any, Any] = {1: "bad", "extra": "y"}
        errs = conformance.validate_envelope(bad_env)
        self.assertIn("envelope:non_string_key", errs)
        self.assertIn("unexpected:extra", errs)

    def test_mapping_context_and_resolve_selected_enforce_category_and_iterable_types(
        self,
    ) -> None:
        ctx = conformance.MappingContext(mapping_id="test-map")
        with self.assertRaises(ValueError):
            ctx.numbered_alias("bad_lowercase", "secret")
        with self.assertRaises(ValueError):
            ctx.numbered_alias("UUID", "")
        with self.assertRaises(ValueError):
            ctx.user_alias("")

        anon = conformance.Anonymizer(ctx)
        masked = anon.anonymize("peer=10.1.2.3")
        with self.assertRaises(TypeError):
            anon.resolve_selected(masked, "[IP-PRIVATE-1]")
        with self.assertRaises(TypeError):
            anon.resolve_selected(masked, [123])  # type: ignore[list-item]


if __name__ == "__main__":
    unittest.main()
