from __future__ import annotations

from pathlib import Path
from typing import Any

from . import SCHEMA_CAPSULE, SCHEMA_INCLUDE, SCHEMA_RECONCILE, SCHEMA_REFERENCE
from .manifest_core import branch_hash, leaf_hash, verify_proof
from .mapping import MappingBook, verify_record_signature
from .reconcile import reconcile_files
from .util import ProofcaskError, is_hash, read_json_file, require_hash

CATEGORY_KEYS = ("equivalent", "added", "missing", "conflicting", "indeterminate")


def parse_include(spec: str | list[str]) -> list[str]:
    if isinstance(spec, list):
        values = [str(x) for x in spec]
    else:
        p = Path(spec)
        if spec.startswith("@"):
            p = Path(spec[1:])
        if p.exists() and p.is_file():
            raw = read_json_file(p) if p.suffix.lower() == ".json" else None
            if raw is None:
                values = []
                for line in p.read_text(encoding="utf-8-sig").splitlines():
                    line = line.strip()
                    if line and not line.startswith("#"):
                        values.append(line)
            elif isinstance(raw, list):
                values = [str(x.get("leaf_id", x) if isinstance(x, dict) else x) for x in raw]
            elif isinstance(raw, dict):
                items = raw.get("include") or raw.get("items") or raw.get("leaf_ids")
                if not isinstance(items, list):
                    raise ProofcaskError(
                        "include JSON must be a list or contain include/items/leaf_ids",
                        code="INCLUDE_SPEC_INVALID",
                    )
                values = [str(x.get("leaf_id", x) if isinstance(x, dict) else x) for x in items]
            else:
                raise ProofcaskError("include JSON must be list/object", code="INCLUDE_SPEC_INVALID")
        else:
            values = [part.strip() for part in str(spec).split(",") if part.strip()]
    out: list[str] = []
    for value in values:
        if value and value not in out:
            out.append(value)
    if not out:
        raise ProofcaskError("at least one INCLUDE exhibit ID is required", code="INCLUDE_EMPTY")
    return out


def _resolve_ref_path(value: str | None, base: Path) -> Path | None:
    if value is None:
        return None
    p = Path(value)
    if p.exists():
        return p
    q = base / p
    if q.exists():
        return q
    name_q = base / p.name
    if name_q.exists():
        return name_q
    return p


def load_reference(ref_path: str | Path, cli_map_key: str | bytes | None = None) -> dict[str, Any]:
    p = Path(ref_path)
    raw = read_json_file(p)
    base = p.parent
    if not isinstance(raw, dict):
        raise ProofcaskError("REF must be a JSON object", code="REF_INVALID")

    fields: dict[str, Any] = raw
    if raw.get("schema") == SCHEMA_RECONCILE:
        hint = (raw.get("source_ref") or {}).get("reference_hint") or raw.get("source_ref") or {}
        fields = hint
    elif raw.get("schema") not in (SCHEMA_REFERENCE, None):
        # Tolerate small user-written reference objects with old/new/map fields.
        fields = raw

    old_value = fields.get("old_manifest") or fields.get("old") or fields.get("OLD")
    new_value = fields.get("new_manifest") or fields.get("new") or fields.get("NEW")
    map_value = fields.get("map") or fields.get("mapping") or fields.get("map_bundle") or fields.get("MAP")
    if not old_value or not new_value or not map_value:
        raise ProofcaskError(
            "REF must identify old_manifest, new_manifest and map",
            code="REF_INVALID",
            details={"keys": sorted(raw.keys())},
        )
    old_p = _resolve_ref_path(str(old_value), base)
    new_p = _resolve_ref_path(str(new_value), base)
    map_p = _resolve_ref_path(str(map_value), base)
    assert old_p and new_p and map_p

    key_arg: str | bytes | None = cli_map_key
    ref_key = fields.get("map_key") or fields.get("key_file")
    if key_arg is None and ref_key:
        key_path = _resolve_ref_path(str(ref_key), base)
        key_arg = str(key_path) if key_path is not None else str(ref_key)

    return {
        "path": p,
        "label": raw.get("label") or fields.get("label") or str(p),
        "old": old_p,
        "new": new_p,
        "map": map_p,
        "map_key": key_arg,
        "raw": raw,
    }


def target_key(target: dict[str, Any]) -> tuple[str, str, str, str]:
    return (
        str(target.get("kind", "")),
        str(target.get("leaf_id") or ""),
        "\u0000".join(target.get("path") or []),
        str(target.get("target_hash", "")),
    )


def _target_from_proof(proof: dict[str, Any]) -> dict[str, Any]:
    return {
        "kind": proof["subject_kind"],
        "leaf_id": proof.get("leaf_id"),
        "payload_digest": proof.get("payload_digest"),
        "path": proof["path"],
        "target_hash": proof["target_hash"],
        "leaf": proof.get("target"),
    }


def _add_proof_to_pool(proof: dict[str, Any], pool: dict[str, dict[str, Any]]) -> None:
    # Creation performs a full standalone verification before compressing ancestors.
    verify_proof(proof)
    for step in proof["steps"]:
        children = [{"name": s["name"], "hash": s["hash"]} for s in step["siblings"]]
        children.append({"name": step["name"], "hash": step["child"]})
        children = sorted(children, key=lambda c: c["name"])
        node = {"kind": "branch", "children": children}
        computed = branch_hash(children)
        if computed != step["parent"]:
            raise ProofcaskError(
                "internal error: reconstructed pooled node hash does not match proof parent",
                code="POOL_BUILD_ERROR",
            )
        pool[step["parent"]] = node


def _extract_proofs(item: dict[str, Any]) -> list[tuple[str, dict[str, Any]]]:
    ev = item.get("evidence") or {}
    out: list[tuple[str, dict[str, Any]]] = []
    for side in ("old", "new"):
        direct = ev.get(side)
        if isinstance(direct, dict) and direct.get("format"):
            out.append((side, direct))
        for key in (f"{side}_all", f"{side}_gap"):
            value = ev.get(key)
            if isinstance(value, dict) and value.get("format"):
                out.append((side, value))
            elif isinstance(value, list):
                for proof in value:
                    if isinstance(proof, dict) and proof.get("format"):
                        out.append((side, proof))
    return out


def create_capsule(
    include: str | list[str],
    ref: str | Path | dict[str, Any],
    cli_map_key: str | bytes | None = None,
) -> dict[str, Any]:
    requested = parse_include(include) if not isinstance(include, list) else include
    if isinstance(ref, dict):
        ref_info = ref
        report = ref_info.get("report")
        if report is None:
            raise ProofcaskError("in-memory REF dict must contain report", code="REF_INVALID")
        label = ref_info.get("label", "in-memory-reference")
        roots = report["roots"]
        key_arg = cli_map_key
    else:
        info = load_reference(ref, cli_map_key)
        label = info["label"]
        report = reconcile_files(info["old"], info["new"], info["map"], info["map_key"])
        roots = report["roots"]
        key_arg = info["map_key"]

    if requested == ["ALL"]:
        requested = sorted(
            {
                item.get("leaf_id")
                for key in CATEGORY_KEYS
                for item in report.get(key, [])
                if item.get("leaf_id")
            }
        )

    pool: dict[str, dict[str, Any]] = {}
    side_targets: dict[str, dict[tuple[Any, ...], dict[str, Any]]] = {
        "old": {},
        "new": {},
    }
    mapping_receipts: dict[str, dict[str, Any]] = {}
    requested_set = set(requested)

    for category in CATEGORY_KEYS:
        for item in report.get(category, []):
            leaf_id = item.get("leaf_id")
            # Capsule proofs cover (a) explicitly requested exhibits and
            # (b) actual root deltas. Unchanged same-commitment equivalents are
            # omitted unless requested; their shared ancestors stay bound by roots.
            is_delta = category != "equivalent" or item.get("reason_code") == "verified_rename"
            if leaf_id not in requested_set and not is_delta:
                continue
            for side, proof in _extract_proofs(item):
                _add_proof_to_pool(proof, pool)
                target = _target_from_proof(proof)
                side_targets[side][target_key(target)] = target
            mapping = (item.get("evidence") or {}).get("mapping")
            if mapping and mapping.get("record"):
                rid = str(mapping["record"].get("record_id"))
                mapping_receipts[rid] = mapping

    included = sorted(requested_set)
    available_ids = {
        t.get("leaf_id")
        for side in ("old", "new")
        for t in side_targets[side].values()
        if t.get("leaf_id")
    }
    missing_includes = [leaf_id for leaf_id in included if leaf_id not in available_ids]
    if missing_includes:
        raise ProofcaskError(
            "INCLUDE IDs were not found in either sealed root",
            code="INCLUDE_NOT_FOUND",
            details={"missing": missing_includes, "available": sorted(x for x in available_ids if x)},
        )

    delta_entries: list[dict[str, Any]] = []
    for category in CATEGORY_KEYS:
        for item in report.get(category, []):
            mapping = (item.get("evidence") or {}).get("mapping") or {}
            delta_entries.append(
                {
                    "classification": item["classification"],
                    "reason_code": item["reason_code"],
                    "leaf_id": item.get("leaf_id"),
                    "old_path": item.get("old_path"),
                    "new_path": item.get("new_path"),
                    "message": item.get("message"),
                    "differences": item.get("differences") or {},
                    "mapping_record_id": (mapping.get("record") or {}).get("record_id"),
                }
            )
    delta_entries.sort(
        key=lambda e: (
            e.get("leaf_id") or "~",
            e.get("classification") or "",
            e.get("reason_code") or "",
            e.get("old_path") or "",
            e.get("new_path") or "",
        )
    )

    capsule: dict[str, Any] = {
        "schema": SCHEMA_CAPSULE,
        "ok": True,
        "reference": label,
        "roots": roots,
        "included": included,
        "proofs": {
            "old": {
                "root": roots["old"],
                "targets": [side_targets["old"][k] for k in sorted(side_targets["old"])],
            },
            "new": {
                "root": roots["new"],
                "targets": [side_targets["new"][k] for k in sorted(side_targets["new"])],
            },
        },
        "node_pool": [{"hash": h, "node": pool[h]} for h in sorted(pool)],
        "mapping_receipts": [mapping_receipts[k] for k in sorted(mapping_receipts)],
        "delta": {"summary": report["summary"], "entries": delta_entries},
        "shared_subtrees": report.get("observations", {}).get("shared_subtrees", []),
        "canonicalization": {
            "json": "UTF-8, object keys sorted, compact separators for hashes",
            "leaf_domain": "proofcask:leaf:v1",
            "branch_domain": "proofcask:branch:v1",
            "target_order": "kind, leaf_id, path, target_hash",
            "node_pool_order": "node hash ascending",
        },
    }
    return capsule


def _verify_pool_target(
    target: Any,
    pool: dict[str, dict[str, Any]],
    root: str,
) -> dict[str, Any]:
    if not isinstance(target, dict):
        raise ProofcaskError("target must be object", code="TARGET_MALFORMED")
    kind = target.get("kind")
    if kind not in ("leaf", "missing_node"):
        raise ProofcaskError("target kind invalid", code="TARGET_MALFORMED")
    path = target.get("path")
    if not isinstance(path, list) or not all(isinstance(x, str) for x in path) or not path:
        raise ProofcaskError("target path must be non-empty string list", code="TARGET_MALFORMED")
    target_hash_value = require_hash(target.get("target_hash"), "target.target_hash")

    if kind == "leaf":
        leaf = target.get("leaf")
        if not isinstance(leaf, dict):
            raise ProofcaskError("leaf target must include leaf", code="TARGET_MALFORMED")
        if target.get("leaf_id") != leaf.get("leaf_id"):
            raise ProofcaskError(
                "target leaf_id does not match committed leaf",
                code="LEAF_ID_MISMATCH",
                details={"target_leaf_id": target.get("leaf_id"), "leaf_leaf_id": leaf.get("leaf_id")},
            )
        if target.get("payload_digest") != leaf.get("payload_digest"):
            raise ProofcaskError(
                "target payload_digest does not match committed leaf",
                code="PAYLOAD_DIGEST_MISMATCH",
                details={"target_digest": target.get("payload_digest"), "leaf_digest": leaf.get("payload_digest")},
            )
        if leaf_hash(leaf) != target_hash_value:
            raise ProofcaskError(
                "leaf hash does not match target_hash",
                code="TARGET_HASH_MISMATCH",
                details={"claimed": target_hash_value, "computed": leaf_hash(leaf)},
            )

    current = root
    for i, name in enumerate(path):
        node = pool.get(current)
        if node is None:
            raise ProofcaskError(
                "required shared branch node is absent from capsule pool",
                code="SHARED_NODE_MISSING",
                details={"node_hash": current, "path_index": i},
            )
        child_hash_value = None
        for child in node.get("children", []):
            if child.get("name") == name:
                child_hash_value = child.get("hash")
                break
        if child_hash_value is None:
            raise ProofcaskError(
                "target path position is not committed by pooled branch node",
                code="TREE_POSITION_MISMATCH",
                details={"component": name, "path_index": i, "node_hash": current},
            )
        if i == len(path) - 1:
            if child_hash_value != target_hash_value:
                raise ProofcaskError(
                    "final tree position points at a different target hash",
                    code="TREE_POSITION_MISMATCH",
                    details={"claimed_target": target_hash_value, "committed_child": child_hash_value},
                )
        else:
            current = child_hash_value
            if current not in pool:
                raise ProofcaskError(
                    "intermediate path node is absent from capsule pool",
                    code="SHARED_NODE_MISSING",
                    details={"node_hash": current, "path_index": i},
                )
    return {
        "ok": True,
        "kind": kind,
        "leaf_id": target.get("leaf_id"),
        "path": path,
        "target_hash": target_hash_value,
    }


def verify_capsule(
    capsule: Any,
    map_key: str | bytes | None = None,
    payload_dir: str | Path | None = None,
) -> dict[str, Any]:
    errors: list[dict[str, Any]] = []
    verified: list[dict[str, Any]] = []
    map_errors: list[dict[str, Any]] = []

    if not isinstance(capsule, dict) or capsule.get("schema") != SCHEMA_CAPSULE:
        return {
            "ok": False,
            "errors": [
                ProofcaskError(
                    f"expected capsule schema {SCHEMA_CAPSULE}",
                    code="CAPSULE_SCHEMA_INVALID",
                ).to_json()
            ],
            "verified_targets": [],
        }

    roots = capsule.get("roots") or {}
    try:
        old_root = require_hash(roots.get("old"), "roots.old")
        new_root = require_hash(roots.get("new"), "roots.new")
    except ProofcaskError as exc:
        return {"ok": False, "errors": [exc.to_json()], "verified_targets": []}

    raw_pool = capsule.get("node_pool")
    pool: dict[str, dict[str, Any]] = {}
    if not isinstance(raw_pool, list):
        errors.append(ProofcaskError("node_pool must be a list", code="CAPSULE_POOL_INVALID").to_json())
    else:
        hashes = [entry.get("hash") if isinstance(entry, dict) else None for entry in raw_pool]
        if hashes != sorted(h for h in hashes if isinstance(h, str)):
            errors.append(
                ProofcaskError(
                    "node_pool is not in canonical hash order",
                    code="CAPSULE_ORDER_INVALID",
                ).to_json()
            )
        for entry in raw_pool:
            try:
                if not isinstance(entry, dict):
                    raise ProofcaskError("pool entry must be object", code="CAPSULE_POOL_INVALID")
                h = require_hash(entry.get("hash"), "pool entry hash")
                if h in pool:
                    raise ProofcaskError("duplicate node pool hash", code="CAPSULE_POOL_DUPLICATE")
                from .manifest_core import validate_node

                node = validate_node(h, entry.get("node"))
                pool[h] = node
            except ProofcaskError as exc:
                errors.append(exc.to_json())

    for side, root in (("old", old_root), ("new", new_root)):
        side_proof = (capsule.get("proofs") or {}).get(side)
        if not isinstance(side_proof, dict):
            errors.append(ProofcaskError(f"missing proofs.{side}", code="CAPSULE_SIDE_MISSING").to_json())
            continue
        if side_proof.get("root") != root:
            errors.append(ProofcaskError(f"proofs.{side}.root mismatch", code="ROOT_MISMATCH").to_json())
        targets = side_proof.get("targets")
        if not isinstance(targets, list):
            errors.append(ProofcaskError(f"proofs.{side}.targets must be list", code="CAPSULE_TARGETS_INVALID").to_json())
            continue
        keys = []
        for pos, target in enumerate(targets):
            try:
                keys.append(target_key(target))
            except Exception:
                keys.append(("", "", "", ""))
        if keys != sorted(keys):
            errors.append(
                ProofcaskError(
                    f"proofs.{side}.targets are not in canonical order",
                    code="PROOF_ORDER_INVALID",
                    details={"side": side},
                ).to_json()
            )
        for target in targets:
            try:
                info = _verify_pool_target(target, pool, root)
                info["side"] = side
                verified.append(info)
            except ProofcaskError as exc:
                details = exc.details or {}
                details.update({"side": side})
                exc.details = details
                errors.append(exc.to_json())

    included = capsule.get("included")
    available_included = {v.get("leaf_id") for v in verified if v.get("leaf_id")}
    if not isinstance(included, list):
        errors.append(ProofcaskError("included must be a list", code="INCLUDE_INVALID").to_json())
    else:
        if included != sorted(included):
            errors.append(ProofcaskError("included is not canonical sorted order", code="CAPSULE_ORDER_INVALID").to_json())
        for leaf_id in included:
            if leaf_id not in available_included:
                errors.append(
                    ProofcaskError(
                        "included exhibit does not have a verified leaf target",
                        code="INCLUDE_WITHOUT_PROOF",
                        details={"leaf_id": leaf_id},
                    ).to_json()
                )

    mapping_status = "not_checked"
    receipts = capsule.get("mapping_receipts") or []
    if map_key is not None:
        mapping_status = "checked"
        key = map_key if isinstance(map_key, bytes) else str(map_key).encode("utf-8")
        for receipt in receipts if isinstance(receipts, list) else []:
            record = receipt.get("record") if isinstance(receipt, dict) else None
            if not isinstance(record, dict) or not verify_record_signature(record, key):
                map_errors.append(
                    ProofcaskError(
                        "mapping receipt signature failed independent verification",
                        code="MAP_SIGNATURE_INVALID",
                        details={"record_id": (record or {}).get("record_id")},
                    ).to_json()
                )
        errors.extend(map_errors)
    elif receipts:
        mapping_status = "key_unavailable"

    payload_checked = 0
    payload_errors: list[dict[str, Any]] = []
    if payload_dir is not None:
        pdir = Path(payload_dir)
        for info in verified:
            leaf_id = info.get("leaf_id")
            if not leaf_id:
                continue
            target = next(
                (
                    t
                    for side in ("old", "new")
                    for t in ((capsule.get("proofs") or {}).get(side, {}) or {}).get("targets", [])
                    if isinstance(t, dict) and t.get("leaf_id") == leaf_id
                ),
                None,
            )
            if target is None:
                continue
            digest = target.get("payload_digest", "")
            hex_digest = digest.split(":", 1)[1] if isinstance(digest, str) and ":" in digest else ""
            candidates = [
                pdir / hex_digest,
                pdir / f"{hex_digest}.bin",
                pdir / f"{leaf_id}.bin",
                pdir / f"{leaf_id}.payload",
                pdir / f"{leaf_id}.txt",
            ]
            path = next((p for p in candidates if p.exists() and p.is_file()), None)
            if path is None:
                payload_errors.append(
                    ProofcaskError(
                        "payload directory supplied but exhibit bytes were not found",
                        code="PAYLOAD_FILE_MISSING",
                        details={"leaf_id": leaf_id},
                    ).to_json()
                )
                continue
            import hashlib

            actual = "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()
            if actual != digest:
                payload_errors.append(
                    ProofcaskError(
                        "exhibit payload bytes do not match committed digest",
                        code="PAYLOAD_DIGEST_MISMATCH",
                        details={"leaf_id": leaf_id, "file": str(path), "expected": digest, "actual": actual},
                    ).to_json()
                )
            else:
                payload_checked += 1
        errors.extend(payload_errors)

    return {
        "ok": not errors,
        "schema": capsule.get("schema"),
        "reference": capsule.get("reference"),
        "roots": roots,
        "verified_target_count": len(verified),
        "verified_targets": verified,
        "included": included if isinstance(included, list) else [],
        "mapping_verification": {"status": mapping_status, "errors": map_errors},
        "payload_verification": {"checked": payload_checked, "errors": payload_errors},
        "errors": errors,
    }
