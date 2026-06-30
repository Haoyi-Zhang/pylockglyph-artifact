#!/usr/bin/env python3
"""Audit benchmark-scope boundaries for proxy baselines and benchmark role."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from pylockglyph.quality import audit_benchmark_scope_contract


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, default=ROOT / "evidence" / "benchmark_scope_contract_summary.json")
    args = parser.parse_args()
    summary = audit_benchmark_scope_contract(ROOT, args.output)
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0 if summary["status"] == "pass" else 1


if __name__ == "__main__":
    raise SystemExit(main())
