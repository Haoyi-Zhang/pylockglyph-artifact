"""Corpus loading and byte-level provenance checks."""
from __future__ import annotations

import json
from pathlib import Path
from collections import Counter

from .io import read_csv, sha256_file
from .model import CorpusSubject, MANAGERS


def load_subjects(artifact_root: Path) -> tuple[CorpusSubject, ...]:
    rows = read_csv(artifact_root / "data" / "corpus" / "ledger.csv")
    subjects = []
    for row in rows:
        subjects.append(CorpusSubject(
            subject_id=row["subject_id"],
            manager_family=row["manager_family"],
            repository=row["repository"],
            commit=row["commit"],
            manifest_path=row["manifest_path"],
            lockfile_path=row["lockfile_path"],
            local_path=row["local_path"],
            license_status=row["license_status"],
            manager_project=row.get("manager_project", "false").lower() == "true",
        ))
    return tuple(subjects)


def manager_counts(subjects: tuple[CorpusSubject, ...]) -> dict[str, int]:
    counts = Counter(subject.manager_family for subject in subjects)
    return {manager: counts.get(manager, 0) for manager in MANAGERS}


def audit_capsule(artifact_root: Path, subjects: tuple[CorpusSubject, ...]) -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    for subject in subjects:
        directory = subject.directory(artifact_root)
        acquisition_path = directory / "acquisition.json"
        problems: list[str] = []
        try:
            acquisition = json.loads(acquisition_path.read_text(encoding="utf-8"))
        except Exception as exc:  # exact failure is retained for the audit row
            acquisition = {}
            problems.append(f"acquisition:{type(exc).__name__}")
        manifest = directory / subject.manifest_path
        lockfile = directory / subject.lockfile_path
        licenses = sorted(p for p in directory.iterdir() if p.is_file() and p.name.lower().startswith(("license", "copying"))) if directory.exists() else []
        if not manifest.is_file(): problems.append("manifest_missing")
        if not lockfile.is_file(): problems.append("lockfile_missing")
        if not licenses: problems.append("license_missing")
        if acquisition.get("repository") != subject.repository: problems.append("repository_mismatch")
        if acquisition.get("commit") != subject.commit: problems.append("commit_mismatch")
        if manifest.is_file() and acquisition.get("manifest_sha256") != sha256_file(manifest): problems.append("manifest_digest_mismatch")
        if lockfile.is_file() and acquisition.get("lockfile_sha256") != sha256_file(lockfile): problems.append("lockfile_digest_mismatch")
        recorded_licenses = {item.get("path"): item.get("sha256") for item in acquisition.get("license_files", []) if isinstance(item, dict)}
        for license_path in licenses:
            if recorded_licenses.get(license_path.name) != sha256_file(license_path):
                problems.append(f"license_digest_mismatch:{license_path.name}")
        rows.append({
            "subject_id": subject.subject_id,
            "manager_family": subject.manager_family,
            "repository": subject.repository,
            "commit": subject.commit,
            "manifest_sha256": sha256_file(manifest) if manifest.is_file() else "",
            "lockfile_sha256": sha256_file(lockfile) if lockfile.is_file() else "",
            "license_files": ";".join(p.name for p in licenses),
            "status": "pass" if not problems else "fail",
            "problems": ";".join(problems),
        })
    return rows
