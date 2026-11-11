"""Bounded regular-file/stdin UTF-8 I/O and strict JSON parsing for wellmanifest.anonym."""

from __future__ import annotations

import hashlib
import json
import math
import os
import stat
import sys
from pathlib import Path
from typing import Any

MAX_FILE_BYTES = 4 * 1024 * 1024
MAX_JSON_DEPTH = 64


def _unique_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    obj: dict[str, Any] = {}
    for key, value in pairs:
        if key in obj:
            raise ValueError(f"duplicate JSON key: {key}")
        obj[key] = value
    return obj


def _reject_json_constant(token: str) -> Any:
    raise ValueError(f"non-finite JSON constant {token!r} is forbidden")


def _parse_finite_float(token: str) -> float:
    parsed = float(token)
    if not math.isfinite(parsed):
        raise ValueError(f"non-finite JSON number {token!r} is forbidden")
    return parsed


def _parse_finite_int(token: str) -> int:
    digits = token[1:] if token.startswith("-") else token
    if len(digits) > 309:
        raise ValueError("JSON integer magnitude exceeds finite range")
    parsed = int(token)
    try:
        ok = math.isfinite(float(parsed))
    except OverflowError:
        ok = False
    if not ok:
        raise ValueError("JSON integer magnitude exceeds finite range")
    return parsed


def _check_utf8_str(value: str) -> None:
    try:
        value.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise ValueError("lone UTF-16 surrogate in string is forbidden") from exc


def _sha256(payload: str) -> str:
    _check_utf8_str(payload)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _validate_json_tree(root: Any, max_depth: int = MAX_JSON_DEPTH) -> None:
    if type(max_depth) is not int or max_depth < 1:
        raise ValueError("max_depth must be a positive integer")
    stack: list[tuple[Any, int]] = [(root, 0)]
    while stack:
        current, depth = stack.pop()
        if depth > max_depth:
            raise ValueError(f"JSON nesting depth exceeds maximum ({max_depth})")
        if isinstance(current, dict):
            for key, child in current.items():
                if not isinstance(key, str):
                    raise ValueError("JSON object keys must be strings")
                _check_utf8_str(key)
                stack.append((child, depth + 1))
        elif isinstance(current, list):
            for child in current:
                stack.append((child, depth + 1))
        elif isinstance(current, str):
            _check_utf8_str(current)
        elif type(current) is int:
            try:
                ok = math.isfinite(float(current))
            except OverflowError:
                ok = False
            if not ok:
                raise ValueError("JSON integer magnitude exceeds finite range")
        elif isinstance(current, float) and not math.isfinite(current):
            raise ValueError("non-finite float value is forbidden")


def read_regular_utf8(path: str | Path, max_bytes: int = MAX_FILE_BYTES) -> str:
    if type(max_bytes) is not int or max_bytes < 1:
        raise ValueError("max_bytes must be a positive integer")
    raw_path = os.fspath(path)
    path_obj = Path(raw_path)
    if not path_obj.is_absolute():
        cur = Path()
        for part in path_obj.parts[:-1]:
            cur = cur / part
            if part not in {".", ".."} and cur.is_symlink():
                raise OSError(f"refusing symlink ancestor: {cur}")
    abs_path = Path(os.path.abspath(raw_path))
    if any(anc.is_symlink() for anc in abs_path.parents if len(anc.parts) > 2):
        raise OSError(f"refusing symlink ancestor: {path_obj}")
    lst = os.lstat(path_obj)
    if stat.S_ISLNK(lst.st_mode):
        raise OSError(f"refusing symlink file: {path_obj}")
    if not stat.S_ISREG(lst.st_mode):
        raise OSError(f"refusing non-regular file: {path_obj}")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    fd = os.open(path_obj, flags)
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise OSError(f"refusing non-regular file: {path_obj}")
        if (st.st_dev, st.st_ino) != (lst.st_dev, lst.st_ino):
            raise OSError(f"file inode changed during open: {path_obj}")
        if st.st_size > max_bytes:
            raise ValueError(f"file exceeds {max_bytes} bytes: {path_obj}")
        chunks = bytearray()
        while True:
            chunk = os.read(fd, min(65536, max_bytes + 1 - len(chunks)))
            if not chunk:
                break
            chunks.extend(chunk)
            if len(chunks) > max_bytes:
                raise ValueError(f"file exceeds {max_bytes} bytes: {path_obj}")
    finally:
        os.close(fd)
    return bytes(chunks).decode("utf-8")


def strict_loads(raw: str) -> Any:
    """Parse JSON while rejecting duplicate keys, non-finite numbers, and deep nesting."""
    if not isinstance(raw, str):
        raise TypeError("JSON payload must be a string")
    _check_utf8_str(raw)
    if len(raw.encode("utf-8")) > MAX_FILE_BYTES:
        raise ValueError(f"JSON payload exceeds {MAX_FILE_BYTES} bytes")
    try:
        parsed = json.loads(
            raw,
            object_pairs_hook=_unique_pairs,
            parse_constant=_reject_json_constant,
            parse_float=_parse_finite_float,
            parse_int=_parse_finite_int,
        )
    except RecursionError as exc:
        raise ValueError("JSON nesting depth exceeds maximum") from exc
    _validate_json_tree(parsed)
    return parsed


def read_json_input(path: str) -> Any:
    if path == "-":
        buf = getattr(sys.stdin, "buffer", None)
        if buf is not None:
            raw_bytes = buf.read(MAX_FILE_BYTES + 1)
            if len(raw_bytes) > MAX_FILE_BYTES:
                raise ValueError(f"stdin exceeds {MAX_FILE_BYTES} bytes")
            raw = raw_bytes.decode("utf-8")
        else:
            raw = sys.stdin.read(MAX_FILE_BYTES + 1)
            _check_utf8_str(raw)
            if len(raw.encode("utf-8")) > MAX_FILE_BYTES:
                raise ValueError(f"stdin exceeds {MAX_FILE_BYTES} bytes")
    else:
        raw = read_regular_utf8(Path(path))
    return strict_loads(raw)
