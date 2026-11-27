from __future__ import annotations

from pathlib import Path
from typing import Any

from . import SCHEMA_INCLUDE, SCHEMA_REFERENCE
from .manifest_core import build_manifest, payload_digest
from .mapping import sign_mapping_record
from .util import write_json_file

FIXTURE_KEY = b"proofcask-fixture-hmac-key-v1"

REPORT_BYTES = "quarterly-report-bytes-v1\n".encode("utf-8")
META_BYTES = "same-bytes-different-metadata-v1\n".encode("utf-8")
TWIN_BYTES = "identical-twin-payload-v1\n".encode("utf-8")


def _old_files() -> list[dict[str, Any]]:
    return [
        {"path": "shared/welcome.txt", "leaf_id": "L-SHARED-1", "payload": "shared welcome\n", "metadata": {"custodian": "archive-bot", "title": "Shared welcome"}},
        {"path": "shared/policy.txt", "leaf_id": "L-SHARED-2", "payload": "shared policy\n", "metadata": {"custodian": "archive-bot", "title": "Shared policy"}},
        {"path": "stable/note.txt", "leaf_id": "L-STABLE", "payload": "stable note\n", "metadata": {"custodian": "clerk-a"}},
        {"path": "old-only/vanished.txt", "leaf_id": "L-ONLY-OLD", "payload": "old only exhibit\n", "metadata": {"custodian": "clerk-a"}},
        {"path": "reports/quarterly.txt", "leaf_id": "L-REPORT", "payload": REPORT_BYTES, "metadata": {"title": "Quarterly report", "series": "Q4"}},
        {"path": "copies/quarterly-copy.txt", "leaf_id": "L-REPORT-COPY", "payload": REPORT_BYTES, "metadata": {"title": "Quarterly report working copy", "copy": True}},
        {"path": "intake/corrected.txt", "leaf_id": "L-CORRECTED", "payload": "corrected exhibit bytes\n", "metadata": {"workflow": "correction-demo"}},
        {"path": "intake/revoked.txt", "leaf_id": "L-REVOKED", "payload": "revoked mapping exhibit\n", "metadata": {"workflow": "revocation-demo"}},
        {"path": "intake/unmapped.txt", "leaf_id": "L-UNMAPPED", "payload": "unmapped rename exhibit\n", "metadata": {"workflow": "missing-map-demo"}},
        {"path": "gap/2024/index.txt", "leaf_id": "L-GAP", "payload": "gap leaf preserved by OLD\n", "metadata": {"page": "2024/index"}},
        {"path": "metadata/same-bytes.txt", "leaf_id": "L-META", "payload": META_BYTES, "metadata": {"custodian": "alice", "label": "original"}},
        {"path": "changes/changed.txt", "leaf_id": "L-CHANGED", "payload": "old payload that will change\n", "metadata": {"custodian": "alice"}},
        {"path": "twins/twin-a.txt", "leaf_id": "L-TWIN-A", "payload": TWIN_BYTES, "metadata": {"accession": "A-100"}},
        {"path": "twins/twin-b.txt", "leaf_id": "L-TWIN-B", "payload": TWIN_BYTES, "metadata": {"accession": "B-200"}},
    ]


def _new_files() -> list[dict[str, Any]]:
    return [
        {"path": "shared/welcome.txt", "leaf_id": "L-SHARED-1", "payload": "shared welcome\n", "metadata": {"custodian": "archive-bot", "title": "Shared welcome"}},
        {"path": "shared/policy.txt", "leaf_id": "L-SHARED-2", "payload": "shared policy\n", "metadata": {"custodian": "archive-bot", "title": "Shared policy"}},
        {"path": "stable/note.txt", "leaf_id": "L-STABLE", "payload": "stable note\n", "metadata": {"custodian": "clerk-a"}},
        {"path": "archive/quarterly-renamed.txt", "leaf_id": "L-REPORT", "payload": REPORT_BYTES, "metadata": {"title": "Quarterly report", "series": "Q4"}},
        {"path": "copies/quarterly-copy.txt", "leaf_id": "L-REPORT-COPY", "payload": REPORT_BYTES, "metadata": {"title": "Quarterly report working copy", "copy": True}},
        {"path": "curated/correct-name.txt", "leaf_id": "L-CORRECTED", "payload": "corrected exhibit bytes\n", "metadata": {"workflow": "correction-demo"}},
        {"path": "curated/revoked-target.txt", "leaf_id": "L-REVOKED", "payload": "revoked mapping exhibit\n", "metadata": {"workflow": "revocation-demo"}},
        {"path": "curated/unmapped.txt", "leaf_id": "L-UNMAPPED", "payload": "unmapped rename exhibit\n", "metadata": {"workflow": "missing-map-demo"}},
        {"path": "gap/2024/index.txt", "leaf_id": "L-GAP", "payload": "gap leaf preserved by OLD\n", "metadata": {"page": "2024/index"}},
        {"path": "metadata/same-bytes.txt", "leaf_id": "L-META", "payload": META_BYTES, "metadata": {"custodian": "bob", "label": "corrected metadata"}},
        {"path": "changes/changed.txt", "leaf_id": "L-CHANGED", "payload": "new payload after sealed change\n", "metadata": {"custodian": "alice"}},
        {"path": "twins/twin-a.txt", "leaf_id": "L-TWIN-A", "payload": TWIN_BYTES, "metadata": {"accession": "A-100"}},
        {"path": "twins/twin-b.txt", "leaf_id": "L-TWIN-B", "payload": TWIN_BYTES, "metadata": {"accession": "B-200"}},
        {"path": "new-only/fresh.txt", "leaf_id": "L-ONLY-NEW", "payload": "fresh exhibit\n", "metadata": {"custodian": "clerk-b"}},
        # Same leaf ID and same committed leaf at two positions: duplicate exhibit conflict.
        {"path": "duplicates/first.txt", "leaf_id": "L-DUP", "payload": "duplicated exhibit bytes\n", "metadata": {"dedup_demo": True}},
        {"path": "duplicates/second.txt", "leaf_id": "L-DUP", "payload": "duplicated exhibit bytes\n", "metadata": {"dedup_demo": True}},
    ]


def _mapping_records(key: bytes) -> list[dict[str, Any]]:
    unsigned = [
        {
            "record_id": "MAP-REPORT-RENAME",
            "op": "rename",
            "leaf_id": "L-REPORT",
            "old_path": "reports/quarterly.txt",
            "new_path": "archive/quarterly-renamed.txt",
            "signed_by": "clerk@proofcask.example",
            "signed_at": "2026-11-20T09:00:00Z",
        },
        {
            "record_id": "MAP-CORRECT-V1-WRONG",
            "op": "rename",
            "leaf_id": "L-CORRECTED",
            "old_path": "intake/corrected.txt",
            "new_path": "curated/wrong-name.txt",
            "signed_by": "clerk@proofcask.example",
            "signed_at": "2026-11-20T09:05:00Z",
        },
        {
            "record_id": "MAP-CORRECT-V1-REVOKE",
            "op": "revoke",
            "target_record_id": "MAP-CORRECT-V1-WRONG",
            "reason": "correction: wrong destination selected",
            "signed_by": "supervisor@proofcask.example",
            "signed_at": "2026-11-20T10:05:00Z",
        },
        {
            "record_id": "MAP-CORRECT-V2-RIGHT",
            "op": "rename",
            "leaf_id": "L-CORRECTED",
            "old_path": "intake/corrected.txt",
            "new_path": "curated/correct-name.txt",
            "supersedes": "MAP-CORRECT-V1-WRONG",
            "signed_by": "supervisor@proofcask.example",
            "signed_at": "2026-11-20T10:10:00Z",
        },
        {
            "record_id": "MAP-REVOKED-RENAME",
            "op": "rename",
            "leaf_id": "L-REVOKED",
            "old_path": "intake/revoked.txt",
            "new_path": "curated/revoked-target.txt",
            "signed_by": "clerk@proofcask.example",
            "signed_at": "2026-11-21T09:00:00Z",
        },
        {
            "record_id": "MAP-REVOKED-CORRECTION",
            "op": "revoke",
            "target_record_id": "MAP-REVOKED-RENAME",
            "reason": "later correction withdraws this path mapping",
            "signed_by": "supervisor@proofcask.example",
            "signed_at": "2026-11-22T09:00:00Z",
        },
    ]
    return [sign_mapping_record(r, key) for r in unsigned]


def build_synthetic_bundle(target_dir: str | Path) -> dict[str, Path | bytes]:
    root = Path(target_dir)
    payload_dir = root / "payloads"
    payload_dir.mkdir(parents=True, exist_ok=True)

    old, old_info = build_manifest("BATCH-OLD-SYNTHETIC", _old_files(), sealed_at="2026-11-27T08:00:00Z")
    new, new_info = build_manifest("BATCH-NEW-SYNTHETIC", _new_files(), sealed_at="2026-11-27T09:00:00Z")

    # Deliberate missing intermediate page in NEW: gap/2024 is referenced by gap but absent.
    gap_hash = new_info["path_hashes"]["gap/2024"]
    omitted_node = new["nodes"][gap_hash]
    del new["nodes"][gap_hash]
    safe_hash = gap_hash.replace(":", "_")
    missing_page_path = root / "missing-pages" / f"{safe_hash}.json"
    missing_page_path.parent.mkdir(parents=True, exist_ok=True)
    # Save the omitted page out-of-band to simulate a page that was not supplied to reconcile.
    # Reconciliation and capsule verification never read this directory.
    write_json_file(
        missing_page_path,
        {
            "note": "Out-of-band copy of a page absent from new_manifest.json; proofcask does not read it.",
            "hash": gap_hash,
            "node": omitted_node,
        },
    )

    old_path = root / "old_manifest.json"
    new_path = root / "new_manifest.json"
    map_path = root / "mappings.json"
    key_path = root / "mapping.key"
    ref_path = root / "reference.json"
    include_path = root / "include.json"

    write_json_file(old_path, old)
    write_json_file(new_path, new)
    key_path.write_text(FIXTURE_KEY.decode("utf-8") + "\n", encoding="utf-8")
    mapping_bundle = {
        "schema": SCHEMA_REFERENCE.replace("reference", "mapping-bundle"),
        "bundle_id": "MAP-BUNDLE-SYNTHETIC",
        "key_id": "fixture-hmac-key",
        "key_file": "mapping.key",
        "records": _mapping_records(FIXTURE_KEY),
    }
    # Use exact mapping schema constant.
    from . import SCHEMA_MAPPING_BUNDLE

    mapping_bundle["schema"] = SCHEMA_MAPPING_BUNDLE
    write_json_file(map_path, mapping_bundle)

    include = {
        "schema": SCHEMA_INCLUDE,
        "include": ["L-REPORT", "L-REPORT-COPY", "L-SHARED-1", "L-GAP"],
    }
    write_json_file(include_path, include)
    reference = {
        "schema": SCHEMA_REFERENCE,
        "label": "proofcask-synthetic-fixture",
        "old_manifest": "old_manifest.json",
        "new_manifest": "new_manifest.json",
        "map": "mappings.json",
        "map_key": "mapping.key",
        "include": "include.json",
    }
    write_json_file(ref_path, reference)

    # Write payload bytes for optional independent payload verification.
    seen_digests: set[str] = set()
    for files in (_old_files(), _new_files()):
        for item in files:
            payload = item.get("payload", b"")
            if isinstance(payload, str):
                payload = payload.encode("utf-8")
            payload_bytes = bytes(payload)
            (payload_dir / f"{item['leaf_id']}.bin").write_bytes(payload_bytes)
            digest_hex = payload_digest(payload_bytes).split(":", 1)[1]
            if digest_hex not in seen_digests:
                (payload_dir / f"{digest_hex}.bin").write_bytes(payload_bytes)
                seen_digests.add(digest_hex)

    return {
        "root": root,
        "old": old_path,
        "new": new_path,
        "map": map_path,
        "key": key_path,
        "key_bytes": FIXTURE_KEY,
        "reference": ref_path,
        "include": include_path,
        "payload_dir": payload_dir,
        "missing_page": missing_page_path,
    }


def _build_omitted_page(new_manifest_after_delete: dict[str, Any], gap_hash: str) -> dict[str, Any]:
    # The node was deleted; callers wanting its content should construct before deletion.
    # This placeholder keeps the missing-pages folder explicit without affecting verification.
    return {
        "note": "This file represents an unavailable audit page. It is intentionally not read by reconcile.",
        "missing_node_hash": gap_hash,
    }
