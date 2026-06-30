#!/usr/bin/env python3
"""Hash the complete research package and record the replay envelope."""
from __future__ import annotations
import argparse
import json
import sys
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
REPOSITORY = ROOT.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
from pylockglyph.audit import write_replay_manifest

def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--elapsed", type=float, required=True)
    parser.add_argument("--manifest", type=Path, default=ROOT / "evidence" / "replay_manifest.csv")
    parser.add_argument("--summary", type=Path, default=ROOT / "evidence" / "replay_summary.json")
    args = parser.parse_args()
    summary = write_replay_manifest(REPOSITORY, args.manifest, args.summary, args.elapsed)
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0 if summary["status"] == "pass" else 1

if __name__ == "__main__":
    raise SystemExit(main())
