from __future__ import annotations

import hashlib
from pathlib import Path, PurePosixPath
from typing import Any, Iterable

from . import PROOF_FORMAT, SCHEMA_MANIFEST
from .util import (
    ManifestError,
    ProofVerificationError,
    canonical_bytes,
    is_hash,
    read_json_file,
    require_hash,
)

LEAF_DOMAIN = b"proofcask:leaf:v1\n"
BRANCH_DOMAIN = b"proofcask:branch:v1\n"
PAYLOAD_PREFIX = "sha256:"


def payload_digest(payload: bytes) -> str:
    return PAYLOAD_PREFIX + hashlib.sha256(payload).hexdigest()


def domain_hash(domain: bytes, obj: Any) -> str:
    h = hashlib.sha256()
    h.update(domain)
    h.update(canonical_bytes(obj))
    return PAYLOAD_PREFIX + h.hexdigest()


def make_leaf(leaf_id: str, digest: str, metadata: dict[str, Any] | None = None) -> dict[str, Any]:
    if not isinstance(leaf_id, str) or not leaf_id:
        raise ManifestError("leaf_id must be a non-empty string", code="LEAF_ID_INVALID")
    if not is_hash(digest):
        raise ManifestError("payload digest must be a sha256 hash", code="DIGEST_INVALID")
    if metadata is None:
        metadata = {}
    if not isinstance(metadata, dict):
        raise ManifestError("leaf metadata must be an object", code="METADATA_INVALID")
    return {
        "kind": "leaf",
        "leaf_id": leaf_id,
        "payload_digest": digest,
        "metadata": metadata,
    }


def leaf_hash(leaf: dict[str, Any]) -> str:
    return domain_hash(LEAF_DOMAIN, leaf)


def branch_hash(children: list[dict[str, str]]) -> str:
    return domain_hash(BRANCH_DOMAIN, {"kind": "branch", "children": children})


def normalize_path(path: str | Iterable[str]) -> tuple[str, ...]:
    if isinstance(path, str):
        raw_parts = path.replace("\\", "/").split("/")
    else:
        raw_parts = list(path)
    parts: list[str] = []
    for part in raw_parts:
        if not isinstance(part, str):
            raise ManifestError("path components must be strings", code="PATH_INVALID")
        if part in ("", ".", "..") or "/" in part or "\\" in part:
            raise ManifestError(
                "logical tree paths must be relative slash paths without '.', '..', or empty components",
                code="PATH_INVALID",
                details={"path": path},
            )
        if any(ord(ch) < 32 for ch in part):
            raise ManifestError("path components may not contain control characters", code="PATH_INVALID")
        parts.append(part)
    if not parts:
        raise ManifestError("path must not be empty", code="PATH_INVALID")
    return tuple(parts)


def path_string(parts: Iterable[str]) -> str:
    return "/".join(parts)


def _validate_child_entry(child: Any) -> dict[str, str]:
    if not isinstance(child, dict) or set(child) != {"name", "hash"}:
        raise ManifestError(
            "branch child must be exactly {name, hash}",
            code="BRANCH_CHILD_INVALID",
            details={"child": child},
        )
    name = child["name"]
    normalize_path((name,))
    require_hash(child["hash"], "branch child hash")
    return {"name": name, "hash": child["hash"]}


def validate_node(node_hash_value: str, node: Any) -> dict[str, Any]:
    require_hash(node_hash_value, "node map key")
    if not isinstance(node, dict) or "kind" not in node:
        raise ManifestError("node must be an object with kind", code="NODE_INVALID")
    kind = node["kind"]
    if kind == "leaf":
        if set(node) != {"kind", "leaf_id", "payload_digest", "metadata"}:
            raise ManifestError(
                "leaf node must contain exactly kind, leaf_id, payload_digest, metadata",
                code="LEAF_SCHEMA_INVALID",
                details={"hash": node_hash_value, "keys": sorted(node)},
            )
        if not isinstance(node["leaf_id"], str) or not node["leaf_id"]:
            raise ManifestError("leaf_id must be non-empty string", code="LEAF_ID_INVALID")
        require_hash(node["payload_digest"], "leaf payload_digest")
        if not isinstance(node["metadata"], dict):
            raise ManifestError("leaf metadata must be object", code="METADATA_INVALID")
        expected = leaf_hash(node)
    elif kind == "branch":
        if set(node) != {"kind", "children"}:
            raise ManifestError(
                "branch node must contain exactly kind and children",
                code="BRANCH_SCHEMA_INVALID",
                details={"hash": node_hash_value, "keys": sorted(node)},
            )
        if not isinstance(node["children"], list):
            raise ManifestError("branch children must be a list", code="BRANCH_CHILDREN_INVALID")
        children = [_validate_child_entry(c) for c in node["children"]]
        names = [c["name"] for c in children]
        if len(names) != len(set(names)):
            raise ManifestError("branch has duplicate child names", code="BRANCH_DUPLICATE_NAME")
        if names != sorted(names):
            raise ManifestError(
                "branch children are not in canonical UTF-8 name order",
                code="BRANCH_ORDER_INVALID",
                details={"names": names},
            )
        expected = branch_hash(children)
    else:
        raise ManifestError(f"unknown node kind {kind!r}", code="NODE_KIND_UNKNOWN")
    if expected != node_hash_value:
        raise ManifestError(
            "node map key/hash does not match domain-separated canonical preimage",
            code="NODE_HASH_MISMATCH",
            details={"claimed": node_hash_value, "computed": expected},
        )
    return node


class Manifest:
    def __init__(self, data: dict[str, Any], source: str | Path | None = None):
        if not isinstance(data, dict) or data.get("schema") != SCHEMA_MANIFEST:
            raise ManifestError(
                f"expected schema {SCHEMA_MANIFEST}",
                code="MANIFEST_SCHEMA_INVALID",
                details={"schema": None if not isinstance(data, dict) else data.get("schema")},
            )
        self.data = data
        self.source = str(source) if source is not None else None
        self.batch_id = data.get("batch_id")
        self.root = require_hash(data.get("root"), "manifest root")
        raw_nodes = data.get("nodes")
        if not isinstance(raw_nodes, dict):
            raise ManifestError("manifest nodes must be an object", code="MANIFEST_NODES_INVALID")
        self.nodes: dict[str, dict[str, Any]] = {}
        for node_id, node in raw_nodes.items():
            self.nodes[node_id] = validate_node(node_id, node)
        if self.root not in self.nodes:
            raise ManifestError(
                "manifest root page is missing",
                code="ROOT_NODE_MISSING",
                details={"root": self.root},
            )

    @classmethod
    def load(cls, path: str | Path) -> "Manifest":
        p = Path(path)
        return cls(read_json_file(p), source=p)

    def child(self, node_hash_value: str, name: str) -> str | None:
        node = self.nodes.get(node_hash_value)
        if node is None or node["kind"] != "branch":
            return None
        for child in node["children"]:
            if child["name"] == name:
                return child["hash"]
        return None


def build_manifest(
    batch_id: str,
    files: Iterable[dict[str, Any]],
    *,
    sealed_at: str | None = None,
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Build a content-addressed manifest.

    Each file entry: path, leaf_id, and either payload bytes/text or payload_digest.
    Returns (manifest, build_info); build_info maps slash paths to node hashes.
    """
    tree: dict[str, Any] = {}
    nodes: dict[str, dict[str, Any]] = {}
    path_hashes: dict[str, str] = {}

    for item in files:
        path = normalize_path(item["path"])
        cursor = tree
        for part in path[:-1]:
            nxt = cursor.setdefault(part, {})
            if not isinstance(nxt, dict):
                raise ManifestError("path prefix is not a directory", code="PATH_CONFLICT", details={"path": path})
            cursor = nxt
        name = path[-1]
        if name in cursor:
            raise ManifestError("duplicate tree path", code="DUPLICATE_PATH", details={"path": path})
        if "payload_digest" in item:
            digest = item["payload_digest"]
        else:
            payload = item.get("payload", b"")
            if isinstance(payload, str):
                payload = payload.encode("utf-8")
            if not isinstance(payload, (bytes, bytearray)):
                raise ManifestError("payload must be bytes or text", code="PAYLOAD_INVALID")
            digest = payload_digest(bytes(payload))
        leaf = make_leaf(item["leaf_id"], digest, item.get("metadata") or {})
        cursor[name] = leaf

    def build_dir(directory: dict[str, Any], logical: tuple[str, ...]) -> str:
        children: list[dict[str, str]] = []
        for name in sorted(directory):
            value = directory[name]
            child_path = logical + (name,)
            if isinstance(value, dict) and value.get("kind") == "leaf":
                node_hash_value = leaf_hash(value)
                nodes[node_hash_value] = value
                path_hashes[path_string(child_path)] = node_hash_value
            else:
                node_hash_value = build_dir(value, child_path)
                path_hashes[path_string(child_path)] = node_hash_value
            children.append({"name": name, "hash": node_hash_value})
        node = {"kind": "branch", "children": children}
        h = branch_hash(children)
        nodes[h] = node
        return h

    root = build_dir(tree, ())
    manifest: dict[str, Any] = {
        "schema": SCHEMA_MANIFEST,
        "batch_id": batch_id,
        "root": root,
        "nodes": nodes,
    }
    if sealed_at is not None:
        manifest["sealed_at"] = sealed_at
    return manifest, {"path_hashes": path_hashes}


def _step(parent_hash: str, parent: dict[str, Any], name: str, child_hash_value: str) -> dict[str, Any]:
    siblings = [
        {"name": c["name"], "hash": c["hash"]}
        for c in parent["children"]
        if c["name"] != name
    ]
    return {
        "child": child_hash_value,
        "name": name,
        "siblings": siblings,
        "parent": parent_hash,
    }


def prove_path(manifest: Manifest | dict[str, Any], path: str | Iterable[str]) -> dict[str, Any]:
    """Create a leaf or missing-node proof.

    A missing intermediate page is not an exception: the returned proof commits the
    expected absent hash inside its nearest available parent. A name absent from an
    available parent raises PATH_NOT_FOUND.
    """
    m = manifest if isinstance(manifest, Manifest) else Manifest(manifest)
    parts = normalize_path(path)
    current = m.root
    root_to_subject_steps: list[dict[str, Any]] = []

    for i, name in enumerate(parts):
        parent = m.nodes.get(current)
        if parent is None:
            # The current hash was an absent child discovered by the previous iteration.
            raise ProofVerificationError(
                "cannot continue proof through missing intermediate node",
                code="MISSING_INTERMEDIATE_NODE",
                details={"missing_hash": current, "remaining_path": list(parts[i:])},
            )
        if parent["kind"] != "branch":
            raise ProofVerificationError(
                "path traversal reached a leaf before all path components were consumed",
                code="TREE_POSITION_INVALID",
                details={"path": list(parts), "at": name},
            )
        child_hash_value = None
        for child in parent["children"]:
            if child["name"] == name:
                child_hash_value = child["hash"]
                break
        if child_hash_value is None:
            raise ProofVerificationError(
                "path component is absent from available branch node",
                code="PATH_NOT_FOUND",
                details={"path": list(parts), "component": name, "parent": current},
            )
        root_to_subject_steps.append(_step(current, parent, name, child_hash_value))
        is_last = i == len(parts) - 1
        child_node = m.nodes.get(child_hash_value)
        if child_node is None:
            missing_path = parts[: i + 1]
            return {
                "format": PROOF_FORMAT,
                "root": m.root,
                "subject_kind": "missing_node",
                "leaf_id": None,
                "payload_digest": None,
                "path": list(missing_path),
                "target_hash": child_hash_value,
                "target": None,
                "steps": list(reversed(root_to_subject_steps)),
            }
        if is_last:
            if child_node["kind"] != "leaf":
                raise ProofVerificationError(
                    "path resolves to a branch node, not a leaf",
                    code="PATH_NOT_LEAF",
                    details={"path": list(parts), "hash": child_hash_value},
                )
            return {
                "format": PROOF_FORMAT,
                "root": m.root,
                "subject_kind": "leaf",
                "leaf_id": child_node["leaf_id"],
                "payload_digest": child_node["payload_digest"],
                "path": list(parts),
                "target_hash": child_hash_value,
                "target": child_node,
                "steps": list(reversed(root_to_subject_steps)),
            }
        if child_node["kind"] != "branch":
            raise ProofVerificationError(
                "non-final path component resolves to a leaf",
                code="TREE_POSITION_INVALID",
                details={"path": list(parts), "component": name},
            )
        current = child_hash_value

    raise ProofVerificationError("empty path cannot be proven", code="PATH_INVALID")


def index_manifest(manifest: Manifest | dict[str, Any]) -> dict[str, Any]:
    m = manifest if isinstance(manifest, Manifest) else Manifest(manifest)
    occurrences: list[dict[str, Any]] = []
    gaps: list[dict[str, Any]] = []
    node_paths: dict[str, list[str]] = {}

    def walk(node_hash_value: str, logical_path: tuple[str, ...], active: tuple[str, ...]) -> None:
        path_text = path_string(logical_path) if logical_path else ""
        node_paths.setdefault(node_hash_value, []).append(path_text)
        node = m.nodes.get(node_hash_value)
        if node is None:
            proof = prove_path(m, logical_path)
            gaps.append({"path": list(logical_path), "path_string": path_text, "hash": node_hash_value, "proof": proof})
            return
        if node["kind"] == "leaf":
            proof = prove_path(m, logical_path)
            occurrences.append(
                {
                    "leaf_id": node["leaf_id"],
                    "path": list(logical_path),
                    "path_string": path_text,
                    "node_hash": node_hash_value,
                    "leaf": node,
                    "proof": proof,
                }
            )
            return
        if node_hash_value in active:
            raise ManifestError(
                "cycle detected in content-addressed tree",
                code="TREE_CYCLE",
                details={"hash": node_hash_value, "path": list(logical_path)},
            )
        for child in node["children"]:
            name = child["name"]
            child_path = logical_path + (name,)
            child_hash_value = child["hash"]
            node_paths.setdefault(child_hash_value, []).append(path_string(child_path))
            if child_hash_value not in m.nodes:
                proof = prove_path(m, child_path)
                gaps.append(
                    {
                        "path": list(child_path),
                        "path_string": path_string(child_path),
                        "hash": child_hash_value,
                        "proof": proof,
                    }
                )
            else:
                walk(child_hash_value, child_path, active + (node_hash_value,))

    walk(m.root, (), ())
    occurrences.sort(key=lambda o: (o["leaf_id"], o["path_string"], o["node_hash"]))
    gaps.sort(key=lambda g: (g["path_string"], g["hash"]))
    by_id: dict[str, list[dict[str, Any]]] = {}
    for occ in occurrences:
        by_id.setdefault(occ["leaf_id"], []).append(occ)
    return {
        "manifest": m,
        "occurrences": occurrences,
        "by_leaf_id": by_id,
        "gaps": gaps,
        "node_paths": node_paths,
    }


def _validate_sibling_list(siblings: Any) -> list[dict[str, str]]:
    if not isinstance(siblings, list):
        raise ProofVerificationError("proof step siblings must be a list", code="PROOF_MALFORMED")
    out = [_validate_child_entry(s) for s in siblings]
    names = [s["name"] for s in out]
    if names != sorted(names):
        raise ProofVerificationError(
            "proof siblings are not in canonical name order",
            code="PROOF_ORDER_INVALID",
            details={"names": names},
        )
    if len(names) != len(set(names)):
        raise ProofVerificationError("proof siblings contain duplicate names", code="PROOF_MALFORMED")
    return out


def verify_proof(proof: Any, expected_root: str | None = None) -> dict[str, Any]:
    """Independently verify a minimal path proof. Raises ProofVerificationError with a distinct code."""
    if not isinstance(proof, dict):
        raise ProofVerificationError("proof must be a JSON object", code="PROOF_MALFORMED")
    if proof.get("format") != PROOF_FORMAT:
        raise ProofVerificationError(
            f"proof format must be {PROOF_FORMAT}",
            code="PROOF_FORMAT_INVALID",
            details={"format": proof.get("format")},
        )
    root = require_hash(proof.get("root"), "proof.root")
    if expected_root is not None and root != expected_root:
        raise ProofVerificationError(
            "proof root does not match expected sealed root",
            code="ROOT_MISMATCH",
            details={"proof_root": root, "expected_root": expected_root},
        )
    kind = proof.get("subject_kind")
    if kind not in ("leaf", "missing_node"):
        raise ProofVerificationError("subject_kind must be leaf or missing_node", code="PROOF_MALFORMED")
    path = proof.get("path")
    if not isinstance(path, list) or not all(isinstance(x, str) for x in path):
        raise ProofVerificationError("proof.path must be a list of strings", code="PROOF_MALFORMED")
    path_parts = normalize_path(path)
    target_hash_value = require_hash(proof.get("target_hash"), "proof.target_hash")

    target = proof.get("target")
    if kind == "leaf":
        if not isinstance(target, dict):
            raise ProofVerificationError("leaf proof must include target leaf", code="PROOF_MALFORMED")
        if proof.get("leaf_id") != target.get("leaf_id"):
            raise ProofVerificationError(
                "proof leaf_id does not match committed leaf.leaf_id",
                code="LEAF_ID_MISMATCH",
                details={"proof_leaf_id": proof.get("leaf_id"), "target_leaf_id": target.get("leaf_id")},
            )
        if proof.get("payload_digest") != target.get("payload_digest"):
            raise ProofVerificationError(
                "proof payload_digest does not match committed leaf.payload_digest",
                code="PAYLOAD_DIGEST_MISMATCH",
                details={
                    "proof_digest": proof.get("payload_digest"),
                    "leaf_digest": target.get("payload_digest"),
                },
            )
        require_hash(target.get("payload_digest"), "target.payload_digest")
        computed_target = leaf_hash(target)
        if computed_target != target_hash_value:
            raise ProofVerificationError(
                "target leaf hash does not match proof target_hash",
                code="TARGET_HASH_MISMATCH",
                details={"claimed": target_hash_value, "computed": computed_target},
            )
    else:
        if target is not None:
            raise ProofVerificationError("missing_node proof target must be null", code="PROOF_MALFORMED")
        if proof.get("leaf_id") is not None or proof.get("payload_digest") is not None:
            raise ProofVerificationError("missing_node proof must not claim leaf identity", code="PROOF_MALFORMED")

    steps = proof.get("steps")
    if not isinstance(steps, list):
        raise ProofVerificationError("proof.steps must be a list", code="PROOF_MALFORMED")
    if len(steps) != len(path_parts):
        raise ProofVerificationError(
            "proof step count does not match path depth",
            code="PROOF_SHAPE_INVALID",
            details={"steps": len(steps), "path_depth": len(path_parts)},
        )

    current = target_hash_value
    reversed_path = list(reversed(path_parts))
    step_children = [s.get("child") if isinstance(s, dict) else None for s in steps]

    for i, step in enumerate(steps):
        if not isinstance(step, dict):
            raise ProofVerificationError("proof step must be object", code="PROOF_MALFORMED", details={"index": i})
        child = require_hash(step.get("child"), f"steps[{i}].child")
        name = step.get("name")
        if not isinstance(name, str):
            raise ProofVerificationError("proof step name must be string", code="PROOF_MALFORMED")
        parent = require_hash(step.get("parent"), f"steps[{i}].parent")

        if child != current:
            if current in step_children:
                raise ProofVerificationError(
                    f"proof steps are out of canonical leaf-to-root order at step {i}",
                    code="PROOF_ORDER_INVALID",
                    details={"index": i, "expected_child": current, "actual_child": child},
                )
            raise ProofVerificationError(
                "proof hash chain is broken",
                code="PROOF_CHAIN_BROKEN",
                details={"index": i, "expected_child": current, "actual_child": child},
            )

        expected_name = reversed_path[i]
        if name != expected_name:
            raise ProofVerificationError(
                "proof tree position/name does not match claimed path",
                code="TREE_POSITION_MISMATCH",
                details={"index": i, "expected_name": expected_name, "actual_name": name},
            )

        siblings = _validate_sibling_list(step.get("siblings"))
        if any(s["name"] == name for s in siblings):
            raise ProofVerificationError(
                "proof target name also appears among siblings",
                code="TREE_POSITION_MISMATCH",
                details={"name": name},
            )
        merged = siblings + [{"name": name, "hash": current}]
        merged = sorted(merged, key=lambda c: c["name"])
        computed_parent = branch_hash(merged)
        if computed_parent != parent:
            raise ProofVerificationError(
                "recomputed parent node does not match proof step parent",
                code="PARENT_HASH_MISMATCH",
                details={"index": i, "claimed_parent": parent, "computed_parent": computed_parent},
            )
        current = parent

    if current != root:
        raise ProofVerificationError(
            "proof ends at a different root",
            code="ROOT_MISMATCH",
            details={"computed_root": current, "expected_root": root},
        )
    return {
        "ok": True,
        "root": root,
        "subject_kind": kind,
        "leaf_id": proof.get("leaf_id"),
        "target_hash": target_hash_value,
        "steps": len(steps),
    }
