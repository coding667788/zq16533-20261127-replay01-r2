from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Any

from .capsule import create_capsule, verify_capsule
from .reconcile import reconcile_files
from .util import ProofcaskError, pretty_json_bytes


def _print_json(value: Any, out: str | Path | None = None) -> int:
    data = pretty_json_bytes(value)
    if out:
        Path(out).write_bytes(data)
    sys.stdout.buffer.write(data)
    sys.stdout.buffer.flush()
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="proofcask",
        description="Offline reconciliation and compact proof capsules for sealed audit manifests.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    rec = sub.add_parser("reconcile", help="reconcile OLD NEW MAP and emit JSON report")
    rec.add_argument("old", metavar="OLD")
    rec.add_argument("new", metavar="NEW")
    rec.add_argument("map", metavar="MAP")
    rec.add_argument("--map-key", help="HMAC key text or key file; defaults to MAP key_file/PROOFCASK_MAP_KEY")
    rec.add_argument("--out", help="also write UTF-8 JSON to this path")

    cap = sub.add_parser("capsule", help="create a compact shared-node capsule for INCLUDE and REF")
    cap.add_argument("include", metavar="INCLUDE", help="comma-separated leaf IDs, @file, include JSON/TXT, or ALL")
    cap.add_argument("ref", metavar="REF", help="reference JSON or a proofcask reconcile report")
    cap.add_argument("--map-key", help="override mapping HMAC key text/file")
    cap.add_argument("--out", help="also write UTF-8 JSON to this path")

    ver = sub.add_parser("verify", help="independently verify a capsule JSON file")
    ver.add_argument("capsule", metavar="CAPSULE")
    ver.add_argument("--map-key", help="mapping HMAC key text or key file")
    ver.add_argument("--payload-dir", help="optional directory containing <leaf_id>.bin exhibit bytes")
    ver.add_argument("--out", help="also write UTF-8 JSON result to this path")
    return parser


def main(argv: list[str] | None = None) -> int:
    # Windows consoles may default to a legacy code page; force UTF-8 for machine output.
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8")  # type: ignore[attr-defined]
        except Exception:
            pass

    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        if args.command == "reconcile":
            report = reconcile_files(args.old, args.new, args.map, args.map_key)
            return _print_json(report, args.out)
        if args.command == "capsule":
            capsule = create_capsule(args.include, args.ref, args.map_key)
            return _print_json(capsule, args.out)
        if args.command == "verify":
            from .mapping import resolve_map_key
            from .util import read_json_file

            capsule = read_json_file(args.capsule)
            map_key = resolve_map_key(None, None, args.map_key)
            result = verify_capsule(capsule, map_key, args.payload_dir)
            rc = _print_json(result, args.out)
            return 0 if result.get("ok") else 1
        parser.error(f"unknown command {args.command}")
        return 2
    except ProofcaskError as exc:
        error_obj = {"ok": False, "error": exc.to_json()}
        sys.stdout.buffer.write(pretty_json_bytes(error_obj))
        return 2
    except BrokenPipeError:
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
