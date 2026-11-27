from __future__ import annotations

import hashlib
import hmac
import os
from pathlib import Path
from typing import Any

from . import SCHEMA_MAPPING_BUNDLE
from .util import ProofcaskError, canonical_bytes, read_json_file

MAPPING_DOMAIN = b"proofcask:mapping-record:v1\n"


def mapping_signing_bytes(record: dict[str, Any]) -> bytes:
    base = {k: v for k, v in record.items() if k != "signature"}
    return MAPPING_DOMAIN + canonical_bytes(base)


def sign_mapping_record(record: dict[str, Any], key: bytes) -> dict[str, Any]:
    out = dict(record)
    sig = hmac.new(key, mapping_signing_bytes(out), hashlib.sha256).hexdigest()
    out["signature"] = "hmac-sha256:" + sig
    return out


def verify_record_signature(record: dict[str, Any], key: bytes) -> bool:
    sig = record.get("signature")
    if not isinstance(sig, str) or not sig.startswith("hmac-sha256:"):
        return False
    supplied = sig.split(":", 1)[1]
    expected = hmac.new(key, mapping_signing_bytes(record), hashlib.sha256).hexdigest()
    return hmac.compare_digest(supplied, expected)


def decode_key_text(text: str) -> bytes:
    stripped = text.strip()
    try:
        if len(stripped) == 64 and all(c in "0123456789abcdefABCDEF" for c in stripped):
            return bytes.fromhex(stripped)
    except ValueError:
        pass
    return stripped.encode("utf-8")


def resolve_map_key(
    bundle_path: str | Path | None,
    bundle: dict[str, Any] | None,
    cli_key: str | bytes | None = None,
) -> bytes | None:
    if isinstance(cli_key, bytes):
        return cli_key
    if isinstance(cli_key, str) and cli_key:
        p = Path(cli_key)
        if p.exists() and p.is_file():
            return decode_key_text(p.read_text(encoding="utf-8"))
        return decode_key_text(cli_key)
    env_key = os.environ.get("PROOFCASK_MAP_KEY")
    if env_key:
        p = Path(env_key)
        if p.exists() and p.is_file():
            return decode_key_text(p.read_text(encoding="utf-8"))
        return decode_key_text(env_key)
    if bundle and bundle.get("map_key"):
        return decode_key_text(str(bundle["map_key"]))
    if bundle and bundle.get("key_file") and bundle_path is not None:
        key_path = Path(bundle_path).parent / str(bundle["key_file"])
        if key_path.exists():
            return decode_key_text(key_path.read_text(encoding="utf-8"))
    return None


class MappingBook:
    def __init__(self, raw: dict[str, Any], source: Path | None, key: bytes | None):
        if raw.get("schema") != SCHEMA_MAPPING_BUNDLE:
            raise ProofcaskError(
                f"expected schema {SCHEMA_MAPPING_BUNDLE}",
                code="MAP_SCHEMA_INVALID",
                details={"schema": raw.get("schema")},
            )
        self.raw = raw
        self.source = source
        self.key = key
        self.key_id = raw.get("key_id")
        self.key_available = key is not None
        records = raw.get("records")
        if not isinstance(records, list):
            raise ProofcaskError("mapping bundle records must be a list", code="MAP_INVALID")
        self.records: list[dict[str, Any]] = []
        for record in records:
            if not isinstance(record, dict):
                raise ProofcaskError("mapping record must be object", code="MAP_RECORD_INVALID")
            if not record.get("record_id") or not record.get("op"):
                raise ProofcaskError("mapping record requires record_id and op", code="MAP_RECORD_INVALID")
            self.records.append(record)
        self.records.sort(key=lambda r: (str(r.get("signed_at", "")), str(r.get("record_id", ""))))
        self.signature_status: dict[str, str] = {}
        for record in self.records:
            rid = str(record["record_id"])
            if key is None:
                self.signature_status[rid] = "key_unavailable"
            elif verify_record_signature(record, key):
                self.signature_status[rid] = "valid"
            else:
                self.signature_status[rid] = "invalid_signature"
        self.revoked_by: dict[str, dict[str, Any]] = {}
        for record in self.records:
            if record.get("op") != "revoke":
                continue
            if self.signature_status.get(str(record["record_id"])) != "valid":
                continue
            target = record.get("target_record_id")
            if target:
                self.revoked_by[str(target)] = record

    @classmethod
    def load(cls, path: str | Path, cli_key: str | bytes | None = None) -> "MappingBook":
        p = Path(path)
        raw = read_json_file(p)
        key = resolve_map_key(p, raw, cli_key)
        return cls(raw, p, key)

    def verification(self, record: dict[str, Any] | None) -> dict[str, Any] | None:
        if record is None:
            return None
        rid = str(record["record_id"])
        sig_status = self.signature_status.get(rid, "unknown")
        revoker = self.revoked_by.get(rid)
        revoked = revoker is not None
        usable = record.get("op") == "rename" and sig_status == "valid" and not revoked
        if sig_status != "valid":
            reason = "mapping_signature_invalid" if sig_status == "invalid_signature" else "mapping_key_unavailable"
        elif revoked:
            reason = "rename_mapping_revoked"
        elif record.get("op") != "rename":
            reason = "mapping_not_rename"
        else:
            reason = "valid_rename_mapping"
        out = {
            "signature_status": sig_status,
            "revoked": revoked,
            "usable": usable,
            "reason_code": reason,
        }
        if revoker is not None:
            out["revocation_record_id"] = revoker.get("record_id")
        return out

    def applicable_rename(self, leaf_id: str, old_path: str, new_path: str) -> dict[str, Any] | None:
        exact: list[dict[str, Any]] = []
        for record in self.records:
            if record.get("op") != "rename" or record.get("leaf_id") != leaf_id:
                continue
            if record.get("old_path") == old_path and record.get("new_path") == new_path:
                exact.append(record)
        if exact:
            # Canonical record order leaves the latest signed statement last.
            return exact[-1]
        related = [r for r in self.records if r.get("op") == "rename" and r.get("leaf_id") == leaf_id]
        if related:
            record = related[-1]
            receipt = {
                "record": record,
                "verification": self.verification(record),
                "path_match": False,
                "reason_code": "mapping_does_not_match_observed_paths",
            }
            return receipt  # type: ignore[return-value]
        return None

    def candidate_paths(self, leaf_id: str, side: str) -> list[str]:
        """Return claimed paths for gap detection, including unusable/revoked records."""
        field = "old_path" if side == "old" else "new_path"
        out: list[str] = []
        for record in self.records:
            if record.get("op") == "rename" and record.get("leaf_id") == leaf_id:
                value = record.get(field)
                if isinstance(value, str):
                    out.append(value)
        return sorted(set(out))

    def receipt_for(self, record_or_receipt: dict[str, Any] | None) -> dict[str, Any] | None:
        if record_or_receipt is None:
            return None
        if "record" in record_or_receipt and "verification" in record_or_receipt:
            return record_or_receipt
        return {
            "record": record_or_receipt,
            "verification": self.verification(record_or_receipt),
            "path_match": True,
        }
