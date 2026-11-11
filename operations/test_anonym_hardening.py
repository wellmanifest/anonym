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

    def test_huge_int_lone_surrogates_symlink_ancestors_and_unsafe_usernames(self) -> None:
        import os

        for bad_json in (
            '{"x": ' + ("9" * 400) + "}",
            '{"x": -' + ("9" * 400) + "}",
            '{"x": "\\ud800"}',
            '{"\\udfff": 1}',
            '{"x": "\ud800"}',
        ):
            with self.subTest(sample=bad_json[:32]), self.assertRaises(ValueError):
                conformance.strict_loads(bad_json)

        ctx = conformance.MappingContext(mapping_id="valid-map", primary_user="alice")
        env = conformance.Anonymizer(ctx).envelope("hello")
        env_surrogate = dict(env, payload="bad\ud800text")
        self.assertIn("payload:invalid_utf8", conformance.validate_envelope(env_surrogate))
        env_huge_count = dict(env, aliasCounts={"USER": 10**400})
        self.assertIn(
            "aliasCounts:invalid_count:USER", conformance.validate_envelope(env_huge_count)
        )
        with self.assertRaises(ValueError):
            conformance.render_preview("line\ud800bad")

        for bad_user in ("", " ", "alice/bob", "alice\\bob", "alice\nbob", "alice:bob"):
            with self.subTest(user=bad_user):
                with self.assertRaises(ValueError):
                    conformance.MappingContext(mapping_id="m1", primary_user=bad_user)
                with self.assertRaises(ValueError):
                    ctx.user_alias(bad_user)

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            real_dir = root / "real_sub"
            real_dir.mkdir()
            env_file = real_dir / "envelope.json"
            env_file.write_text(json.dumps(env), encoding="utf-8")
            sym_dir = root / "sym_sub"
            sym_dir.symlink_to(real_dir)

            with self.assertRaises(OSError):
                conformance.read_regular_utf8(sym_dir / "envelope.json")

            old_cwd = Path.cwd()
            try:
                os.chdir(root)
                with self.assertRaises(OSError):
                    conformance.read_regular_utf8(Path("sym_sub/envelope.json"))
            finally:
                os.chdir(old_cwd)

            for bad_max in (True, False, 0, -1):
                with self.subTest(max_bytes=bad_max), self.assertRaises(ValueError):
                    conformance.read_regular_utf8(env_file, max_bytes=bad_max)  # type: ignore[arg-type]

        self.assertIsNone(conformance.MAPPING_ID_RE.match("map-1\n"))
        self.assertIsNone(conformance.CATEGORY_RE.match("USER\n"))
        self.assertIsNone(conformance.SHA256_RE.match("a" * 64 + "\n"))

    def test_modular_bounds_relative_symlink_traversal_5000_digits_and_bracketed_home_paths(
        self,
    ) -> None:
        import os

        ops_dir = Path(__file__).resolve().parent
        for name in ("anonym_io.py", "conformance.py", "test_anonym_hardening.py"):
            lines = (ops_dir / name).read_text(encoding="utf-8").splitlines()
            self.assertLess(len(lines), 500, f"{name} exceeded 500 lines: {len(lines)}")

        with self.assertRaises(ValueError):
            conformance.strict_loads('{"x": ' + ("9" * 5000) + "}")

        ctx = conformance.MappingContext(mapping_id="bracket-map", primary_user="primary")
        anon = conformance.Anonymizer(ctx)
        hp = "/" + "home/"
        bracketed = f"[{hp}alice] [{hp}primary/.ssh] {hp}alice/file[1].txt"
        masked = anon.anonymize(bracketed)
        self.assertEqual(
            masked,
            f"[{hp}[USER-2]] [{hp}[USER]/.ssh] {hp}[USER-2]/file[1].txt",
        )
        self.assertEqual(anon.anonymize(masked), masked)

        for bad_user in ("[USER-2]", "alice[1]", "bob]2", "sur\ud800user"):
            with self.subTest(user=bad_user):
                with self.assertRaises(ValueError):
                    conformance.MappingContext(mapping_id="m2", primary_user=bad_user)
                with self.assertRaises(ValueError):
                    ctx.user_alias(bad_user)

        for bad_call in (
            lambda: anon.anonymize("bad\ud800text"),
            lambda: anon.resolve_selected("bad\ud800text", set()),
            lambda: ctx.numbered_alias("UUID", "bad\ud800orig"),
        ):
            with self.assertRaises(ValueError):
                bad_call()

        env = anon.envelope(masked)
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            real_sub = root / "real_sub"
            real_sub.mkdir()
            env_file = root / "envelope.json"
            env_file.write_text(json.dumps(env), encoding="utf-8")
            sym_sub = root / "sym_sub"
            sym_sub.symlink_to(real_sub)

            old_cwd = Path.cwd()
            try:
                os.chdir(root)
                with self.assertRaises(OSError):
                    conformance.read_regular_utf8("sym_sub/../envelope.json")
            finally:
                os.chdir(old_cwd)


if __name__ == "__main__":
    unittest.main()
