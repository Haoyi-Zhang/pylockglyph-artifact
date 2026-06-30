#!/usr/bin/env python3
"""Evaluate one manifest/lockfile pair without changing the benchmark."""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from pylockglyph.certificate import PROFILES, decide
from pylockglyph.model import CorpusSubject, MANAGERS
from pylockglyph.parsers import parse_subject


def _common_base(manifest: Path, lockfile: Path) -> Path:
    common = Path(os.path.commonpath([str(manifest), str(lockfile)]))
    return common if common.is_dir() else common.parent


def _relative(path: Path, base: Path) -> str:
    try:
        return path.relative_to(base).as_posix()
    except ValueError as exc:
        raise SystemExit(f"{path} is not under {base}") from exc


def main() -> int:
    parser = argparse.ArgumentParser(description="Evaluate one Python manifest/lockfile pair.")
    parser.add_argument("--manager", choices=MANAGERS, required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--lockfile", type=Path, required=True)
    parser.add_argument("--subject-id", default="local_pair")
    args = parser.parse_args()

    manifest = args.manifest.resolve(strict=True)
    lockfile = args.lockfile.resolve(strict=True)
    base = _common_base(manifest, lockfile)
    subject = CorpusSubject(
        subject_id=args.subject_id,
        manager_family=args.manager,
        repository="local",
        commit="local",
        manifest_path=_relative(manifest, base),
        lockfile_path=_relative(lockfile, base),
        local_path=".",
        license_status="not_checked",
    )
    parsed = parse_subject(base, subject)
    decisions = {profile: decide(parsed, profile).as_dict() for profile in PROFILES}
    payload = {
        "status": "pass" if parsed.parser_status == "parsed" else "fail",
        "subject_id": subject.subject_id,
        "manager_family": args.manager,
        "parser_status": parsed.parser_status,
        "package_records": len(parsed.packages),
        "evidence": parsed.evidence.as_dict(),
        "decisions": decisions,
        "errors": list(parsed.errors),
    }
    print(json.dumps(payload, indent=2, sort_keys=True))
    return 0 if parsed.parser_status == "parsed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
