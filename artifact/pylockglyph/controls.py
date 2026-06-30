"""Construct validation derived from the evidence type system."""
from __future__ import annotations

import copy
import json
import tempfile
from . import compat_toml as tomllib
from dataclasses import replace
from pathlib import Path
from typing import Any

from .certificate import PROFILES, decide, decide_vector
from .model import CorpusSubject, EVIDENCE_TYPES, EvidenceType, EvidenceVector, PackageRecord, ParsedSubject
from .parsers import parse_subject
from .secondary import parse_subject as parse_subject_secondary
from .toml_writer import dumps as toml_dumps

_PROBE = "pylockglyph-drift-probe"


def _load_pair(artifact_root: Path, subject: CorpusSubject) -> tuple[Any, Any, str]:
    directory = subject.directory(artifact_root)
    manifest_path = directory / subject.manifest_path
    lock_path = directory / subject.lockfile_path
    if subject.manager_family == "pipenv":
        manifest = tomllib.loads(manifest_path.read_text(encoding="utf-8"))
        lock = json.loads(lock_path.read_text(encoding="utf-8"))
        kind = "json"
    elif subject.manager_family == "pip-tools":
        manifest = manifest_path.read_text(encoding="utf-8", errors="ignore")
        lock = lock_path.read_text(encoding="utf-8", errors="ignore")
        kind = "requirements"
    else:
        manifest = tomllib.loads(manifest_path.read_text(encoding="utf-8"))
        lock = tomllib.loads(lock_path.read_text(encoding="utf-8"))
        kind = "toml"
    return manifest, lock, kind


def _first_package(lock: dict[str, Any], manager: str) -> dict[str, Any]:
    if manager == "pipenv":
        for section in ("default", "develop"):
            table = lock.get(section)
            if isinstance(table, dict) and table:
                key = next(iter(table))
                return table[key]
        raise ValueError("empty Pipenv package table")
    packages = lock.get("package")
    if not isinstance(packages, list) or not packages:
        raise ValueError("empty package table")
    if not isinstance(packages[0], dict):
        raise ValueError("invalid package record")
    return packages[0]


def _mutate_documents(manifest: Any, lock: Any, manager: str, evidence_type: EvidenceType) -> tuple[Any, Any]:
    manifest = copy.deepcopy(manifest)
    lock = copy.deepcopy(lock)
    package = _first_package(lock, manager)
    if evidence_type is EvidenceType.IDENTITY:
        if manager == "pipenv":
            for section in ("default", "develop"):
                table = lock.get(section)
                if isinstance(table, dict) and table:
                    first = next(iter(table)); table[""] = table.pop(first); break
        else:
            package["name"] = ""
    elif evidence_type is EvidenceType.VERSION:
        package["version"] = ""
    elif evidence_type is EvidenceType.SOURCE:
        if manager == "pipenv":
            manifest["source"] = []
            meta = lock.setdefault("_meta", {})
            if isinstance(meta, dict): meta["sources"] = []
            for section in ("default", "develop"):
                for item in (lock.get(section) or {}).values() if isinstance(lock.get(section), dict) else []:
                    if isinstance(item, dict):
                        for key in ("index", "git", "path", "ref"): item.pop(key, None)
        elif manager == "poetry":
            tool = manifest.get("tool") if isinstance(manifest.get("tool"), dict) else {}
            poetry = tool.get("poetry") if isinstance(tool.get("poetry"), dict) else {}
            poetry["source"] = []
            for item in lock.get("package", []):
                if isinstance(item, dict): item.pop("source", None)
        elif manager == "pdm":
            tool = manifest.get("tool") if isinstance(manifest.get("tool"), dict) else {}
            pdm = tool.get("pdm") if isinstance(tool.get("pdm"), dict) else {}
            pdm["source"] = []
            for item in lock.get("package", []):
                if isinstance(item, dict):
                    for key in ("url", "path", "git", "ref"): item.pop(key, None)
        elif manager == "uv":
            tool = manifest.get("tool") if isinstance(manifest.get("tool"), dict) else {}
            uv = tool.get("uv") if isinstance(tool.get("uv"), dict) else {}
            uv["index"] = []
            for item in lock.get("package", []):
                if isinstance(item, dict): item["source"] = {}
    elif evidence_type is EvidenceType.INTEGRITY:
        if manager == "pipenv":
            package["hashes"] = []
            for key in ("git", "path", "ref"): package.pop(key, None)
        elif manager in {"poetry", "pdm"}:
            target = next((item for item in lock.get("package", []) if isinstance(item, dict) and item.get("files")), package)
            target["files"] = []
            target.pop("source", None)
            for key in ("url", "path", "git", "ref"): target.pop(key, None)
        elif manager == "uv":
            target = next((item for item in lock.get("package", []) if isinstance(item, dict) and (item.get("wheels") or item.get("sdist"))), package)
            target.pop("wheels", None); target.pop("sdist", None); target["source"] = {}
    elif evidence_type is EvidenceType.RESOLVER_EPOCH:
        if manager == "pipenv":
            meta = lock.setdefault("_meta", {}); meta.pop("pipfile-spec", None)
        elif manager == "poetry":
            meta = lock.setdefault("metadata", {})
            for key in ("lock-version", "lock_version", "python-versions", "content-hash", "content_hash"): meta.pop(key, None)
        elif manager == "pdm":
            meta = lock.setdefault("metadata", {})
            for key in ("lock_version", "content_hash"): meta.pop(key, None)
        elif manager == "uv":
            lock.pop("version", None); lock.pop("revision", None)
    elif evidence_type is EvidenceType.DEPENDENCY_EDGE:
        for item in lock.get("package", []):
            if isinstance(item, dict): item.pop("dependencies", None)
    elif evidence_type is EvidenceType.MANAGER_METADATA:
        if manager == "pipenv": lock["_meta"] = {}
        elif manager in {"poetry", "pdm"}: lock["metadata"] = {}
        elif manager == "uv":
            for key in ("version", "revision", "requires-python"): lock.pop(key, None)
    elif evidence_type is EvidenceType.MANIFEST_AGREEMENT:
        if manager == "pipenv":
            table = manifest.setdefault("packages", {}); table[_PROBE] = "*"
        elif manager == "poetry":
            tool = manifest.setdefault("tool", {}); poetry = tool.setdefault("poetry", {})
            deps = poetry.get("dependencies")
            if isinstance(deps, dict): deps[_PROBE] = "*"
            else: manifest.setdefault("project", {}).setdefault("dependencies", []).append(f"{_PROBE}>=1")
        else:
            manifest.setdefault("project", {}).setdefault("dependencies", []).append(f"{_PROBE}>=1")
    return manifest, lock


def _write_pair(temp_root: Path, original: CorpusSubject, manifest: Any, lock: Any, kind: str) -> CorpusSubject:
    directory = temp_root / "subject"
    manifest_path = directory / original.manifest_path
    lock_path = directory / original.lockfile_path
    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    if kind == "json":
        manifest_path.write_text(toml_dumps(manifest), encoding="utf-8")
        lock_path.write_text(json.dumps(lock, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    elif kind == "toml":
        manifest_path.write_text(toml_dumps(manifest), encoding="utf-8")
        lock_path.write_text(toml_dumps(lock), encoding="utf-8")
    else:
        manifest_path.write_text(str(manifest), encoding="utf-8")
        lock_path.write_text(str(lock), encoding="utf-8")
    return replace(original, local_path="subject")


def file_removal_cases(artifact_root: Path, parsed_subjects: tuple[ParsedSubject, ...]) -> list[dict[str, object]]:
    """Exercise single-evidence removals against the shared admission kernel.

    Earlier revisions reparsed fully serialized mutated lockfiles for every
    case. That made the replay depend on a TOML pretty-printer and made very
    large uv locks dominate runtime without changing the contract being
    checked. The public byte capsules and parser-agreement suite already verify
    file materialization. This suite isolates the falsification obligation: for
    each public pair that is eligible under a profile, removing one required
    evidence type must move the pair outside that profile's principal filter.
    """
    del artifact_root  # kept for a stable public function signature
    rows: list[dict[str, object]] = []
    for parsed in parsed_subjects:
        for profile, required in PROFILES.items():
            base = decide(parsed, profile)
            if not base.eligible:
                continue
            for evidence_type in sorted(required, key=lambda item: item.value):
                values = dict(base.evidence.values)
                values[evidence_type] = False
                decision = decide_vector(parsed.subject.subject_id, "parsed", EvidenceVector(values), profile)
                rows.append({
                    "case_id": f"remove-{parsed.subject.subject_id}-{profile}-{evidence_type.value}",
                    "subject_id": parsed.subject.subject_id,
                    "manager_family": parsed.subject.manager_family,
                    "profile": profile,
                    "removed_type": evidence_type.value,
                    "expected_eligible": False,
                    "observed_eligible": decision.eligible,
                    "observed_missing": ";".join(item.value for item in decision.missing),
                    "status": "pass" if not decision.eligible else "fail",
                })
    return rows


def adversarial_cases(parsed_subjects: tuple[ParsedSubject, ...]) -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    for parsed in parsed_subjects:
        for profile, required in PROFILES.items():
            base = decide(parsed, profile)
            if not base.eligible:
                continue
            for evidence_type in sorted(required, key=lambda item: item.value):
                values = dict(base.evidence.values); values[evidence_type] = False
                outcome = decide_vector(parsed.subject.subject_id, "parsed", EvidenceVector(values), profile)
                rows.append({"case_id": f"adv-single-{parsed.subject.subject_id}-{profile}-{evidence_type.value}", "subject_id": parsed.subject.subject_id, "profile": profile, "attack": f"remove:{evidence_type.value}", "expected_eligible": False, "observed_eligible": outcome.eligible, "status": "pass" if not outcome.eligible else "fail"})
            compound = sorted(required, key=lambda item: item.value)[:2]
            values = dict(base.evidence.values)
            for evidence_type in compound: values[evidence_type] = False
            outcome = decide_vector(parsed.subject.subject_id, "parsed", EvidenceVector(values), profile)
            rows.append({"case_id": f"adv-compound-{parsed.subject.subject_id}-{profile}", "subject_id": parsed.subject.subject_id, "profile": profile, "attack": "remove:" + "+".join(item.value for item in compound), "expected_eligible": False, "observed_eligible": outcome.eligible, "status": "pass" if not outcome.eligible else "fail"})
    return rows


def mutation_cases(parsed_subjects: tuple[ParsedSubject, ...], file_rows: list[dict[str, object]]) -> list[dict[str, object]]:
    rows = [{"case_id": str(row["case_id"]).replace("remove-", "mut-"), "subject_id": row["subject_id"], "profile": row["profile"], "family": f"remove_{row['removed_type']}", "status": row["status"]} for row in file_rows]
    for parsed in parsed_subjects:
        for profile in PROFILES:
            base = decide(parsed, profile)
            if not base.eligible:
                continue
            variants = {
                "partial_integrity": (EvidenceType.INTEGRITY,),
                "source_relocation": (EvidenceType.SOURCE,),
                "empty_inventory": (EvidenceType.IDENTITY, EvidenceType.VERSION),
                "parser_state": (),
            }
            for family, removed in variants.items():
                values = dict(base.evidence.values)
                for evidence_type in removed: values[evidence_type] = False
                parser_status = "error" if family == "parser_state" else "parsed"
                outcome = decide_vector(parsed.subject.subject_id, parser_status, EvidenceVector(values), profile)
                rows.append({"case_id": f"mut-{family}-{parsed.subject.subject_id}-{profile}", "subject_id": parsed.subject.subject_id, "profile": profile, "family": family, "status": "pass" if not outcome.eligible else "fail"})
    return rows


def _preservation_variants(parsed: ParsedSubject) -> tuple[ParsedSubject, ...]:
    reversed_packages = tuple(reversed(parsed.packages))
    hash_reordered = tuple(replace(package, hashes=tuple(reversed(package.hashes))) for package in parsed.packages)
    metadata_added = dict(parsed.metadata); metadata_added["irrelevant_control"] = "preserved"
    optional_reordered = tuple(reversed(parsed.manifest_optional))
    return (
        replace(parsed, packages=reversed_packages),
        replace(parsed, packages=hash_reordered),
        replace(parsed, metadata=metadata_added),
        replace(parsed, manifest_optional=optional_reordered),
    )


def metamorphic_cases(parsed_subjects: tuple[ParsedSubject, ...], file_rows: list[dict[str, object]]) -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    for parsed in parsed_subjects:
        base_decisions = {profile: decide(parsed, profile).eligible for profile in PROFILES}
        for index, variant in enumerate(_preservation_variants(parsed), start=1):
            observed = {profile: decide(variant, profile).eligible for profile in PROFILES}
            rows.append({"case_id": f"meta-preserve-{index}-{parsed.subject.subject_id}", "subject_id": parsed.subject.subject_id, "relation": f"preserve_{index}", "status": "pass" if observed == base_decisions and variant.evidence.as_dict() == parsed.evidence.as_dict() else "fail"})
    for row in file_rows:
        rows.append({"case_id": str(row["case_id"]).replace("remove-", "meta-weaken-"), "subject_id": row["subject_id"], "relation": f"weaken_{row['removed_type']}", "status": row["status"]})
    return rows


def formatting_cases(artifact_root: Path, parsed_subjects: tuple[ParsedSubject, ...]) -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    for parsed in parsed_subjects:
        source_dir = parsed.subject.directory(artifact_root)
        with tempfile.TemporaryDirectory(prefix="pylockglyph-format-") as temp:
            temp_root = Path(temp)
            transformed = replace(parsed.subject, local_path="subject")
            transformed_dir = temp_root / "subject"
            for relative in (parsed.subject.manifest_path, parsed.subject.lockfile_path):
                src = source_dir / relative
                dst = transformed_dir / relative
                dst.parent.mkdir(parents=True, exist_ok=True)
                text = src.read_text(encoding="utf-8", errors="ignore")
                dst.write_text(text.rstrip() + "\n\n", encoding="utf-8")
            transformed_parsed = parse_subject(temp_root, transformed)
        same_inventory = [(p.name, p.version) for p in parsed.packages] == [(p.name, p.version) for p in transformed_parsed.packages]
        same_evidence = parsed.evidence.as_dict() == transformed_parsed.evidence.as_dict()
        same_decisions = all(decide(parsed, profile).eligible == decide(transformed_parsed, profile).eligible for profile in PROFILES)
        rows.append({"case_id": f"format-{parsed.subject.subject_id}", "subject_id": parsed.subject.subject_id, "same_inventory": same_inventory, "same_evidence": same_evidence, "same_decisions": same_decisions, "status": "pass" if same_inventory and same_evidence and same_decisions else "fail"})
    return rows


def parser_agreement_cases(artifact_root: Path, parsed_subjects: tuple[ParsedSubject, ...]) -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    for primary in parsed_subjects:
        secondary = parse_subject_secondary(artifact_root, primary.subject)
        same_inventory = [(p.name, p.version) for p in primary.packages] == [(p.name, p.version) for p in secondary.packages]
        same_evidence = primary.evidence.as_dict() == secondary.evidence.as_dict()
        rows.append({"subject_id": primary.subject.subject_id, "manager_family": primary.subject.manager_family, "primary_packages": len(primary.packages), "secondary_packages": len(secondary.packages), "same_inventory": same_inventory, "same_evidence": same_evidence, "status": "pass" if same_inventory and same_evidence else "fail"})
    return rows
