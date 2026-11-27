from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from proofcask.fixtures_builder import build_synthetic_bundle  # noqa: E402


def main() -> int:
    fixtures = ROOT / "fixtures"
    paths = build_synthetic_bundle(fixtures)
    print(f"fixtures written to {paths['root']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
