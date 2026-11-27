from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

HASH_RE = re.compile(r"^sha256:[0-9a-f]{64}$")


class ProofcaskError(Exception):
    """Base error with a stable, machine-readable code."""

    code = "PROOFCASK_ERROR"

    def __init__(self, message: str, code: str | None = None, details: Any = None):
        super().__init__(message)
        self.message = message
        if code:
            self.code = code
        self.details = details

    def __str__(self) -> str:
        return f"[{self.code}] {self.message}"

    def to_json(self) -> dict[str, Any]:
        out: dict[str, Any] = {"code": self.code, "message": self.message}
        if self.details is not None:
            out["details"] = self.details
        return out


class CanonicalizationError(ProofcaskError):
    code = "CANONICAL_JSON_ERROR"


class ManifestError(ProofcaskError):
    code = "MANIFEST_INVALID"


class ProofVerificationError(ProofcaskError):
    code = "PROOF_INVALID"


def _canonical_validate(value: Any) -> Any:
    if value is None or isinstance(value, (str, bool, int)):
        return value
    if isinstance(value, float):
        raise CanonicalizationError(
            "floating-point numbers are not canonical in ProofCask v1; use integer/string encoding",
            code="CANONICAL_FLOAT_UNSUPPORTED",
            details={"value": value},
        )
    if isinstance(value, dict):
        out: dict[str, Any] = {}
        for key, item in value.items():
            if not isinstance(key, str):
                raise CanonicalizationError(
                    "canonical JSON object keys must be strings",
                    code="CANONICAL_NON_STRING_KEY",
                    details={"key_type": type(key).__name__},
                )
            out[key] = _canonical_validate(item)
        return out
    if isinstance(value, (list, tuple)):
        return [_canonical_validate(item) for item in value]
    raise CanonicalizationError(
        f"value of type {type(value).__name__} is not JSON-canonicalizable",
        code="CANONICAL_UNSUPPORTED_TYPE",
    )


def canonical_text(value: Any) -> str:
    """Return deterministic compact UTF-8 JSON text used by domain hashes/signatures."""
    value = _canonical_validate(value)
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    )


def canonical_bytes(value: Any) -> bytes:
    return canonical_text(value).encode("utf-8")


def pretty_json_bytes(value: Any) -> bytes:
    """Human-readable command output; object keys stay sorted and arrays stay in chosen canonical order."""
    return (json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode("utf-8")


def _no_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key, value in pairs:
        if key in out:
            raise ProofcaskError(
                f"duplicate JSON object key: {key!r}",
                code="JSON_DUPLICATE_KEY",
                details={"key": key},
            )
        out[key] = value
    return out


def read_json_file(path: str | Path) -> Any:
    p = Path(path)
    try:
        raw = p.read_bytes()
    except OSError as exc:
        raise ProofcaskError(f"cannot read JSON file {p}: {exc}", code="INPUT_READ_ERROR") from exc
    try:
        # utf-8-sig also accepts ordinary UTF-8 and a Windows Notepad BOM.
        text = raw.decode("utf-8-sig")
        return json.loads(text, object_pairs_hook=_no_duplicate_keys, parse_constant=_reject_constant)
    except ProofcaskError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ProofcaskError(f"invalid UTF-8 JSON in {p}: {exc}", code="INPUT_JSON_INVALID") from exc


def _reject_constant(value: str) -> None:
    raise CanonicalizationError(
        f"non-canonical JSON constant {value}",
        code="CANONICAL_CONSTANT_UNSUPPORTED",
    )


def write_json_file(path: str | Path, value: Any) -> None:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_bytes(pretty_json_bytes(value))


def is_hash(value: Any) -> bool:
    return isinstance(value, str) and bool(HASH_RE.match(value))


def require_hash(value: Any, what: str) -> str:
    if not is_hash(value):
        raise ProofVerificationError(
            f"{what} must be sha256: followed by 64 lowercase hexadecimal digits",
            code="HASH_FORMAT_INVALID",
            details={"field": what, "value": value},
        )
    return value
