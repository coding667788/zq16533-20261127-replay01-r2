from __future__ import annotations

from pathlib import Path
from typing import Any

from . import SCHEMA_RECONCILE
from .manifest_core import Manifest, index_manifest, prove_path
from .mapping import MappingBook
from .util import ProofcaskError, canonical_bytes


def _metadata_keys(old: dict[str, Any], new: dict[str, Any]) -> list[str]:
    keys = set(old) | set(new)
    changed: list[str] = []
    for key in sorted(keys):
        if canonical_bytes(old.get(key)) != canonical_bytes(new.get(key)):
            changed.append(key)
    return changed


def _item(
    classification: str,
    reason_code: str,
    *,
    leaf_id: str | None = None,
    old_path: str | None = None,
    new_path: str | None = None,
    old_proof: dict[str, Any] | None = None,
    new_proof: dict[str, Any] | None = None,
    mapping: dict[str, Any] | None = None,
    extra_evidence: dict[str, Any] | None = None,
    differences: dict[str, Any] | None = None,
    message: str | None = None,
) -> dict[str, Any]:
    evidence: dict[str, Any] = {
        "old": old_proof,
        "new": new_proof,
        "mapping": mapping,
    }
    if extra_evidence:
        evidence.update(extra_evidence)
    return {
        "classification": classification,
        "reason_code": reason_code,
        "message": message or reason_code.replace("_", " "),
        "leaf_id": leaf_id,
        "old_path": old_path,
        "new_path": new_path,
        "differences": differences or {},
        "evidence": evidence,
    }


def _gap_for_candidates(manifest: Manifest, paths: list[str]) -> dict[str, Any] | None:
    for candidate in paths:
        try:
            proof = prove_path(manifest, candidate)
        except ProofcaskError:
            continue
        if proof.get("subject_kind") == "missing_node":
            return proof
    return None


def _descendant_hashes(root_hash: str, nodes: dict[str, dict[str, Any]]) -> set[str]:
    seen: set[str] = set()
    stack = [root_hash]
    while stack:
        h = stack.pop()
        if h in seen:
            continue
        seen.add(h)
        node = nodes.get(h)
        if node and node.get("kind") == "branch":
            stack.extend(c["hash"] for c in node["children"])
    return seen


def _shared_subtrees(old_idx: dict[str, Any], new_idx: dict[str, Any]) -> list[dict[str, Any]]:
    old_m: Manifest = old_idx["manifest"]
    new_m: Manifest = new_idx["manifest"]
    shared = sorted(h for h in set(old_m.nodes) & set(new_m.nodes) if old_m.nodes[h].get("kind") == "branch")
    maximal: list[str] = []
    shared_set = set(shared)
    for h in shared:
        covered_by_other = False
        for other in shared:
            if other == h:
                continue
            # Only descend when other is actually a present shared node.
            if h in _descendant_hashes(other, old_m.nodes):
                covered_by_other = True
                break
        if not covered_by_other:
            maximal.append(h)
    out = []
    for h in sorted(maximal):
        out.append(
            {
                "node_hash": h,
                "old_paths": sorted(set(old_idx["node_paths"].get(h, []))),
                "new_paths": sorted(set(new_idx["node_paths"].get(h, []))),
                "legal_shared_subtree": True,
            }
        )
    return out


def reconcile_manifests(
    old_manifest: Manifest | dict[str, Any],
    new_manifest: Manifest | dict[str, Any],
    book: MappingBook,
    *,
    source_ref: dict[str, Any] | None = None,
) -> dict[str, Any]:
    old_m = old_manifest if isinstance(old_manifest, Manifest) else Manifest(old_manifest)
    new_m = new_manifest if isinstance(new_manifest, Manifest) else Manifest(new_manifest)
    old_idx = index_manifest(old_m)
    new_idx = index_manifest(new_m)

    equivalent: list[dict[str, Any]] = []
    added: list[dict[str, Any]] = []
    missing: list[dict[str, Any]] = []
    conflicting: list[dict[str, Any]] = []
    indeterminate: list[dict[str, Any]] = []

    all_ids = sorted(set(old_idx["by_leaf_id"]) | set(new_idx["by_leaf_id"]))

    for leaf_id in all_ids:
        old_occs = old_idx["by_leaf_id"].get(leaf_id, [])
        new_occs = new_idx["by_leaf_id"].get(leaf_id, [])

        if len(old_occs) > 1 or len(new_occs) > 1:
            conflicting.append(
                _item(
                    "conflicting",
                    "duplicate_exhibit",
                    leaf_id=leaf_id,
                    old_path=old_occs[0]["path_string"] if old_occs else None,
                    new_path=new_occs[0]["path_string"] if new_occs else None,
                    old_proof=old_occs[0]["proof"] if old_occs else None,
                    new_proof=new_occs[0]["proof"] if new_occs else None,
                    extra_evidence={
                        "old_all": [o["proof"] for o in old_occs],
                        "new_all": [o["proof"] for o in new_occs],
                        "old_paths": [o["path_string"] for o in old_occs],
                        "new_paths": [o["path_string"] for o in new_occs],
                    },
                    message="stable leaf_id occurs more than once in a sealed batch",
                )
            )
            continue

        if len(old_occs) == 1 and len(new_occs) == 1:
            old_o = old_occs[0]
            new_o = new_occs[0]
            old_leaf = old_o["leaf"]
            new_leaf = new_o["leaf"]
            payload_equal = old_leaf["payload_digest"] == new_leaf["payload_digest"]
            metadata_equal = canonical_bytes(old_leaf["metadata"]) == canonical_bytes(new_leaf["metadata"])
            changed_keys = [] if metadata_equal else _metadata_keys(old_leaf["metadata"], new_leaf["metadata"])
            differences = {
                "payload_digest_equal": payload_equal,
                "metadata_equal": metadata_equal,
                "old_payload_digest": old_leaf["payload_digest"],
                "new_payload_digest": new_leaf["payload_digest"],
                "changed_metadata_keys": changed_keys,
                "leaf_commitment_equal": old_o["node_hash"] == new_o["node_hash"],
            }
            same_path = old_o["path_string"] == new_o["path_string"]
            mapping_receipt = None
            if not same_path:
                mapping_result = book.applicable_rename(leaf_id, old_o["path_string"], new_o["path_string"])
                mapping_receipt = book.receipt_for(mapping_result)

            if not payload_equal or not metadata_equal:
                if not payload_equal and metadata_equal:
                    reason = "payload_digest_mismatch"
                elif payload_equal and not metadata_equal:
                    reason = "metadata_mismatch"
                else:
                    reason = "payload_and_metadata_mismatch"
                conflicting.append(
                    _item(
                        "conflicting",
                        reason,
                        leaf_id=leaf_id,
                        old_path=old_o["path_string"],
                        new_path=new_o["path_string"],
                        old_proof=old_o["proof"],
                        new_proof=new_o["proof"],
                        mapping=mapping_receipt,
                        differences=differences,
                        message="same stable leaf_id but sealed content/metadata differ",
                    )
                )
                continue

            if same_path:
                equivalent.append(
                    _item(
                        "equivalent",
                        "same_leaf_commitment",
                        leaf_id=leaf_id,
                        old_path=old_o["path_string"],
                        new_path=new_o["path_string"],
                        old_proof=old_o["proof"],
                        new_proof=new_o["proof"],
                        differences=differences,
                        message="leaf ID, payload digest, metadata, path and root proof agree",
                    )
                )
                continue

            verification = (mapping_receipt or {}).get("verification") or {}
            if verification.get("usable"):
                equivalent.append(
                    _item(
                        "equivalent",
                        "verified_rename",
                        leaf_id=leaf_id,
                        old_path=old_o["path_string"],
                        new_path=new_o["path_string"],
                        old_proof=old_o["proof"],
                        new_proof=new_o["proof"],
                        mapping=mapping_receipt,
                        differences=differences,
                        message="signed, non-revoked mapping authorizes the path rename",
                    )
                )
            else:
                reason = verification.get("reason_code") or "rename_mapping_missing"
                if mapping_receipt is None:
                    reason = "rename_mapping_missing"
                indeterminate.append(
                    _item(
                        "indeterminate",
                        reason,
                        leaf_id=leaf_id,
                        old_path=old_o["path_string"],
                        new_path=new_o["path_string"],
                        old_proof=old_o["proof"],
                        new_proof=new_o["proof"],
                        mapping=mapping_receipt,
                        differences=differences,
                        message="leaf bytes agree, but the path rename lacks currently verifiable authorization",
                    )
                )
            continue

        # Exactly one available occurrence. Before saying added/missing, check whether
        # the other side has a committed reference to an absent intermediate page.
        if len(new_occs) == 1 and len(old_occs) == 0:
            new_o = new_occs[0]
            candidates = [new_o["path_string"], *book.candidate_paths(leaf_id, "old")]
            gap_proof = _gap_for_candidates(old_m, candidates)
            if gap_proof is not None:
                indeterminate.append(
                    _item(
                        "indeterminate",
                        "missing_intermediate_node",
                        leaf_id=leaf_id,
                        new_path=new_o["path_string"],
                        new_proof=new_o["proof"],
                        extra_evidence={"old_gap": gap_proof},
                        message="OLD root commits a reference to a page absent from the supplied manifest",
                    )
                )
            else:
                added.append(
                    _item(
                        "added",
                        "leaf_id_absent_from_old",
                        leaf_id=leaf_id,
                        new_path=new_o["path_string"],
                        new_proof=new_o["proof"],
                        message="stable leaf ID has a verifiable NEW proof and no OLD occurrence/gap",
                    )
                )
            continue

        if len(old_occs) == 1 and len(new_occs) == 0:
            old_o = old_occs[0]
            candidates = [old_o["path_string"], *book.candidate_paths(leaf_id, "new")]
            gap_proof = _gap_for_candidates(new_m, candidates)
            if gap_proof is not None:
                indeterminate.append(
                    _item(
                        "indeterminate",
                        "missing_intermediate_node",
                        leaf_id=leaf_id,
                        old_path=old_o["path_string"],
                        old_proof=old_o["proof"],
                        extra_evidence={"new_gap": gap_proof},
                        message="NEW root commits a reference to a page absent from the supplied manifest",
                    )
                )
            else:
                missing.append(
                    _item(
                        "missing",
                        "leaf_id_absent_from_new",
                        leaf_id=leaf_id,
                        old_path=old_o["path_string"],
                        old_proof=old_o["proof"],
                        message="stable leaf ID has a verifiable OLD proof and no NEW occurrence/gap",
                    )
                )

    # Gaps that cannot be tied to a known leaf ID still receive their own review path.
    tied_gap_hashes: set[tuple[str, str]] = set()
    for item in indeterminate:
        ev = item["evidence"]
        for side, key in (("old", "old_gap"), ("new", "new_gap")):
            proof = ev.get(key)
            if proof:
                tied_gap_hashes.add((side, proof["target_hash"]))
    gap_items: list[dict[str, Any]] = []
    for side, idx in (("old", old_idx), ("new", new_idx)):
        for gap in idx["gaps"]:
            if (side, gap["hash"]) in tied_gap_hashes:
                continue
            proof = gap["proof"]
            gap_items.append(
                _item(
                    "indeterminate",
                    "missing_intermediate_node",
                    leaf_id=None,
                    old_path=gap["path_string"] if side == "old" else None,
                    new_path=gap["path_string"] if side == "new" else None,
                    extra_evidence={f"{side}_gap": proof},
                    message=f"{side.upper()} manifest is missing intermediate node {gap['hash']}",
                )
            )
    indeterminate.extend(gap_items)

    for bucket in (equivalent, added, missing, conflicting, indeterminate):
        bucket.sort(key=lambda x: (x.get("leaf_id") or "~", x.get("reason_code") or "", x.get("old_path") or "", x.get("new_path") or ""))

    # Identical payload digests under different stable leaf IDs are legal exhibits.
    digest_to_ids: dict[str, set[str]] = {}
    for idx in (old_idx, new_idx):
        for occ in idx["occurrences"]:
            digest_to_ids.setdefault(occ["leaf"]["payload_digest"], set()).add(occ["leaf_id"])
    shared_payload_groups = [
        {"payload_digest": digest, "leaf_ids": sorted(ids), "distinct_exhibits": True}
        for digest, ids in sorted(digest_to_ids.items())
        if len(ids) > 1
    ]

    report: dict[str, Any] = {
        "schema": SCHEMA_RECONCILE,
        "ok": True,
        "roots": {"old": old_m.root, "new": new_m.root},
        "source_ref": source_ref or {},
        "summary": {
            "equivalent": len(equivalent),
            "added": len(added),
            "missing": len(missing),
            "conflicting": len(conflicting),
            "indeterminate": len(indeterminate),
            "old_tree_gaps": len(old_idx["gaps"]),
            "new_tree_gaps": len(new_idx["gaps"]),
        },
        "equivalent": equivalent,
        "added": added,
        "missing": missing,
        "conflicting": conflicting,
        "indeterminate": indeterminate,
        "tree_gaps": {"old": old_idx["gaps"], "new": new_idx["gaps"]},
        "observations": {
            "legal_same_digest_exhibits": shared_payload_groups,
            "shared_subtrees": _shared_subtrees(old_idx, new_idx),
            "mapping_key_available": book.key_available,
            "mapping_key_id": book.key_id,
        },
    }
    return report


def reconcile_files(
    old_path: str | Path,
    new_path: str | Path,
    map_path: str | Path,
    map_key: str | bytes | None = None,
) -> dict[str, Any]:
    old_p = Path(old_path)
    new_p = Path(new_path)
    map_p = Path(map_path)
    old_m = Manifest.load(old_p)
    new_m = Manifest.load(new_p)
    book = MappingBook.load(map_p, map_key)
    source_ref = {
        "old_manifest": str(old_p),
        "new_manifest": str(new_p),
        "map": str(map_p),
        "reference_hint": {
            "schema": "proofcask.reference/v1",
            "old_manifest": str(old_p),
            "new_manifest": str(new_p),
            "map": str(map_p),
        },
    }
    if book.key_id:
        source_ref["reference_hint"]["key_id"] = book.key_id
    return reconcile_manifests(old_m, new_m, book, source_ref=source_ref)
