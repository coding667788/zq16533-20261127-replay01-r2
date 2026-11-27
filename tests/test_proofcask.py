from __future__ import annotations

import copy
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from proofcask.capsule import create_capsule, verify_capsule  # noqa: E402
from proofcask.fixtures_builder import FIXTURE_KEY, build_synthetic_bundle  # noqa: E402
from proofcask.manifest_core import Manifest, verify_proof  # noqa: E402
from proofcask.mapping import MappingBook  # noqa: E402
from proofcask.reconcile import reconcile_manifests, reconcile_files  # noqa: E402
from proofcask.util import ProofcaskError, ProofVerificationError, read_json_file  # noqa: E402


class SyntheticRepoTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls._temp = tempfile.TemporaryDirectory(prefix="proofcask-test-")
        cls.paths = build_synthetic_bundle(cls._temp.name)
        cls.report = reconcile_files(cls.paths["old"], cls.paths["new"], cls.paths["map"], FIXTURE_KEY)
        cls.capsule = create_capsule(
            str(cls.paths["include"]),
            str(cls.paths["reference"]),
            FIXTURE_KEY,
        )
        cls.verification = verify_capsule(
            cls.capsule,
            FIXTURE_KEY,
            cls.paths["payload_dir"],
        )

    @classmethod
    def tearDownClass(cls) -> None:
        cls._temp.cleanup()

    def find_item(self, leaf_id: str):
        for category in ("equivalent", "added", "missing", "conflicting", "indeterminate"):
            for item in self.report[category]:
                if item.get("leaf_id") == leaf_id:
                    return category, item
        self.fail(f"leaf {leaf_id} not found")

    def test_reconcile_covers_all_required_classes(self) -> None:
        summary = self.report["summary"]
        self.assertEqual(summary["equivalent"], 8)
        self.assertEqual(summary["added"], 1)
        self.assertEqual(summary["missing"], 1)
        self.assertEqual(summary["conflicting"], 3)
        self.assertEqual(summary["indeterminate"], 3)
        self.assertEqual(summary["new_tree_gaps"], 1)

        category, report_item = self.find_item("L-ONLY-NEW")
        self.assertEqual(category, "added")
        self.assertEqual(report_item["reason_code"], "leaf_id_absent_from_old")

        category, report_item = self.find_item("L-ONLY-OLD")
        self.assertEqual(category, "missing")

        category, report_item = self.find_item("L-DUP")
        self.assertEqual(category, "conflicting")
        self.assertEqual(report_item["reason_code"], "duplicate_exhibit")
        self.assertEqual(len(report_item["evidence"]["new_all"]), 2)

        category, report_item = self.find_item("L-META")
        self.assertEqual(category, "conflicting")
        self.assertEqual(report_item["reason_code"], "metadata_mismatch")
        self.assertTrue(report_item["differences"]["payload_digest_equal"])
        self.assertIn("custodian", report_item["differences"]["changed_metadata_keys"])

        category, report_item = self.find_item("L-CHANGED")
        self.assertEqual(category, "conflicting")
        self.assertEqual(report_item["reason_code"], "payload_digest_mismatch")

        category, report_item = self.find_item("L-GAP")
        self.assertEqual(category, "indeterminate")
        self.assertEqual(report_item["reason_code"], "missing_intermediate_node")
        self.assertEqual(report_item["evidence"]["new_gap"]["subject_kind"], "missing_node")

        category, report_item = self.find_item("L-REVOKED")
        self.assertEqual(category, "indeterminate")
        self.assertEqual(report_item["reason_code"], "rename_mapping_revoked")

        category, report_item = self.find_item("L-UNMAPPED")
        self.assertEqual(category, "indeterminate")
        self.assertEqual(report_item["reason_code"], "rename_mapping_missing")

    def test_signed_rename_and_correction_are_equivalent(self) -> None:
        category, item = self.find_item("L-REPORT")
        self.assertEqual(category, "equivalent")
        self.assertEqual(item["reason_code"], "verified_rename")
        self.assertEqual(item["old_path"], "reports/quarterly.txt")
        self.assertEqual(item["new_path"], "archive/quarterly-renamed.txt")
        self.assertTrue(item["evidence"]["mapping"]["verification"]["usable"])

        category, item = self.find_item("L-CORRECTED")
        self.assertEqual(category, "equivalent")
        self.assertEqual(item["reason_code"], "verified_rename")
        self.assertEqual(item["new_path"], "curated/correct-name.txt")

    def test_same_digest_other_leaf_is_not_identity(self) -> None:
        category, report_item = self.find_item("L-REPORT-COPY")
        self.assertEqual(category, "equivalent")
        self.assertEqual(report_item["old_path"], report_item["new_path"])

        groups = self.report["observations"]["legal_same_digest_exhibits"]
        report_group = next(g for g in groups if {"L-REPORT", "L-REPORT-COPY"} <= set(g["leaf_ids"]))
        self.assertTrue(report_group["distinct_exhibits"])
        self.assertEqual(len(report_group["leaf_ids"]), 2)

        _, renamed = self.find_item("L-REPORT")
        new_proof = renamed["evidence"]["new"]
        self.assertEqual(new_proof["leaf_id"], "L-REPORT")
        self.assertEqual(new_proof["path"], ["archive", "quarterly-renamed.txt"])

    def test_legal_shared_subtree_is_reported(self) -> None:
        shared = self.report["observations"]["shared_subtrees"]
        self.assertTrue(shared)
        paths = shared[0]["old_paths"]
        self.assertIn("shared", paths)
        self.assertEqual(shared[0]["old_paths"], shared[0]["new_paths"])

    def test_every_reconcile_proof_independently_verifies(self) -> None:
        checked = 0
        for category in ("equivalent", "added", "missing", "conflicting", "indeterminate"):
            for item in self.report[category]:
                ev = item["evidence"]
                for side, root in (("old", self.report["roots"]["old"]), ("new", self.report["roots"]["new"])):
                    for key in (side, f"{side}_gap"):
                        proof = ev.get(key)
                        if isinstance(proof, dict):
                            result = verify_proof(proof, root)
                            self.assertTrue(result["ok"])
                            checked += 1
                    for proof in ev.get(f"{side}_all", []):
                        result = verify_proof(proof, root)
                        self.assertTrue(result["ok"])
                        checked += 1
        self.assertGreaterEqual(checked, 25)

    def test_capsule_verifies_and_uses_canonical_order(self) -> None:
        self.assertTrue(self.verification["ok"], msg=json.dumps(self.verification["errors"], indent=2))
        self.assertEqual(self.capsule["included"], sorted(self.capsule["included"]))
        self.assertEqual(
            self.capsule["node_pool"],
            sorted(self.capsule["node_pool"], key=lambda e: e["hash"]),
        )
        for side in ("old", "new"):
            targets = self.capsule["proofs"][side]["targets"]
            keys = [
                (t["kind"], t.get("leaf_id") or "", "\u0000".join(t["path"]), t["target_hash"])
                for t in targets
            ]
            self.assertEqual(keys, sorted(keys))
        self.assertTrue(any(s["old_paths"] and s["new_paths"] for s in self.capsule["shared_subtrees"]))
        self.assertEqual(self.verification["mapping_verification"]["status"], "checked")
        self.assertEqual(self.verification["payload_verification"]["errors"], [])

    def test_mutation_distinctions_on_standalone_proof(self) -> None:
        _, item = self.find_item("L-REPORT")
        original = item["evidence"]["new"]

        mutations = {
            "proof_order": lambda p: p["steps"].reverse(),
            "tree_position": lambda p: p["path"].__setitem__(0, "tampered-position"),
            "leaf_id": lambda p: p.__setitem__("leaf_id", "L-MUTATED-ID"),
            "digest": lambda p: p.__setitem__("payload_digest", "sha256:" + "0" * 64),
        }
        expected = {
            "proof_order": "PROOF_ORDER_INVALID",
            "tree_position": "TREE_POSITION_MISMATCH",
            "leaf_id": "LEAF_ID_MISMATCH",
            "digest": "PAYLOAD_DIGEST_MISMATCH",
        }
        for name, mutate in mutations.items():
            with self.subTest(mutation=name):
                mutated = copy.deepcopy(original)
                mutate(mutated)
                with self.assertRaises(ProofVerificationError) as ctx:
                    verify_proof(mutated, self.report["roots"]["new"])
                self.assertEqual(ctx.exception.code, expected[name])
                self.assertIn(expected[name], str(ctx.exception))

    def test_capsule_mutations_are_detected(self) -> None:
        # Reorder canonical target list.
        mutated = copy.deepcopy(self.capsule)
        targets = mutated["proofs"]["new"]["targets"]
        self.assertGreaterEqual(len(targets), 2)
        targets[0], targets[1] = targets[1], targets[0]
        result = verify_capsule(mutated, FIXTURE_KEY)
        self.assertFalse(result["ok"])
        self.assertIn("PROOF_ORDER_INVALID", [e["code"] for e in result["errors"]])

        # Leaf ID mutation.
        mutated = copy.deepcopy(self.capsule)
        target = next(t for t in mutated["proofs"]["new"]["targets"] if t["kind"] == "leaf")
        target["leaf_id"] = "L-MUTATED-CAPSULE-ID"
        result = verify_capsule(mutated, FIXTURE_KEY)
        self.assertIn("LEAF_ID_MISMATCH", [e["code"] for e in result["errors"]])

        # Digest mutation.
        mutated = copy.deepcopy(self.capsule)
        target = next(t for t in mutated["proofs"]["new"]["targets"] if t["kind"] == "leaf")
        target["payload_digest"] = "sha256:" + "0" * 64
        result = verify_capsule(mutated, FIXTURE_KEY)
        self.assertIn("PAYLOAD_DIGEST_MISMATCH", [e["code"] for e in result["errors"]])

        # Tree position mutation is caught by pooled path traversal.
        from proofcask.capsule import _verify_pool_target

        pool = {entry["hash"]: entry["node"] for entry in self.capsule["node_pool"]}
        target = copy.deepcopy(next(t for t in self.capsule["proofs"]["new"]["targets"] if t["kind"] == "leaf"))
        target["path"][0] = "zzz-position-mutation"
        with self.assertRaises(ProofcaskError) as ctx:
            _verify_pool_target(target, pool, self.capsule["roots"]["new"])
        self.assertEqual(ctx.exception.code, "TREE_POSITION_MISMATCH")

    def test_unincluded_objects_are_bound_by_root(self) -> None:
        _, item = self.find_item("L-STABLE")
        proof = copy.deepcopy(item["evidence"]["new"])
        root_step = proof["steps"][-1]
        self.assertTrue(root_step["siblings"])
        root_step["siblings"][0]["hash"] = "sha256:" + "0" * 64
        with self.assertRaises(ProofVerificationError) as ctx:
            verify_proof(proof, self.report["roots"]["new"])
        self.assertEqual(ctx.exception.code, "PARENT_HASH_MISMATCH")

        mutated = copy.deepcopy(self.capsule)
        pool_entry = next(
            entry
            for entry in mutated["node_pool"]
            if entry["node"]["kind"] == "branch" and len(entry["node"]["children"]) >= 2
        )
        pool_entry["node"]["children"][0]["hash"] = "sha256:" + "1" * 64
        result = verify_capsule(mutated, FIXTURE_KEY)
        self.assertIn("NODE_HASH_MISMATCH", [e["code"] for e in result["errors"]])

    def test_invalid_mapping_signature_is_not_trusted(self) -> None:
        raw = read_json_file(self.paths["map"])
        raw["records"][0]["signature"] = raw["records"][0]["signature"] + "tampered"
        old_m = Manifest.load(self.paths["old"])
        new_m = Manifest.load(self.paths["new"])
        book = MappingBook(raw, self.paths["map"], FIXTURE_KEY)
        report = reconcile_manifests(old_m, new_m, book)
        item = next(x for x in report["indeterminate"] if x.get("leaf_id") == "L-REPORT")
        self.assertEqual(item["reason_code"], "mapping_signature_invalid")

    def test_cli_outputs_utf8_json(self) -> None:
        cmd = [
            sys.executable,
            "-m",
            "proofcask",
            "reconcile",
            str(self.paths["old"]),
            str(self.paths["new"]),
            str(self.paths["map"]),
        ]
        proc = subprocess.run(cmd, cwd=ROOT, capture_output=True, timeout=30)
        self.assertEqual(proc.returncode, 0, msg=proc.stderr.decode("utf-8", "replace"))
        data = json.loads(proc.stdout.decode("utf-8"))
        self.assertTrue(data["ok"])
        self.assertEqual(data["summary"]["conflicting"], 3)

        capsule_out = self.paths["root"] / "cli-capsule.json"
        verify_out = self.paths["root"] / "cli-verify.json"
        cmd = [
            sys.executable,
            "-m",
            "proofcask",
            "capsule",
            str(self.paths["include"]),
            str(self.paths["reference"]),
            "--out",
            str(capsule_out),
        ]
        proc = subprocess.run(cmd, cwd=ROOT, capture_output=True, timeout=30)
        self.assertEqual(proc.returncode, 0, msg=proc.stderr.decode("utf-8", "replace"))

        cmd = [
            sys.executable,
            "-m",
            "proofcask",
            "verify",
            str(capsule_out),
            "--map-key",
            str(self.paths["key"]),
            "--payload-dir",
            str(self.paths["payload_dir"]),
            "--out",
            str(verify_out),
        ]
        proc = subprocess.run(cmd, cwd=ROOT, capture_output=True, timeout=30)
        self.assertEqual(proc.returncode, 0, msg=proc.stderr.decode("utf-8", "replace"))
        result = json.loads(verify_out.read_text(encoding="utf-8"))
        self.assertTrue(result["ok"], msg=result.get("errors"))


if __name__ == "__main__":
    unittest.main(verbosity=2)
