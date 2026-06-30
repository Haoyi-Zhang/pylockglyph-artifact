"""Independent parser implementation used for differential validation."""
from __future__ import annotations

import json
import re
from . import compat_toml as tomllib
from pathlib import Path
from typing import Any

from .io import normalize_name
from .model import CorpusSubject, PackageRecord, ParsedSubject

_NAME = re.compile(r"^\s*([A-Za-z0-9_.-]+)")
_PIN = re.compile(r"^\s*([A-Za-z0-9_.-]+)(?:\[[^\]]+\])?==([^\s\\]+)")
_SHA = re.compile(r"sha256:[0-9a-fA-F]{64}")


def _dep(value: object) -> str:
    match = _NAME.match(str(value or ""))
    return normalize_name(match.group(1)) if match else ""


def _dep_set(value: Any) -> tuple[str, ...]:
    if isinstance(value, dict):
        return tuple(sorted({normalize_name(str(key)) for key in value}))
    if isinstance(value, list):
        result = set()
        for item in value:
            if isinstance(item, dict):
                if item.get("name"):
                    result.add(normalize_name(str(item["name"])))
            else:
                name = _dep(item)
                if name:
                    result.add(name)
        return tuple(sorted(result))
    return ()


def _hashes(value: Any) -> tuple[str, ...]:
    if isinstance(value, str):
        return tuple(sorted(set(_SHA.findall(value))))
    if isinstance(value, list):
        joined = " ".join(str(item.get("hash", "")) if isinstance(item, dict) else str(item) for item in value)
        return tuple(sorted(set(_SHA.findall(joined))))
    return ()


def _source(source: Any) -> tuple[str, bool, bool]:
    if not isinstance(source, dict):
        return "", False, False
    anchor = str(source.get("registry") or source.get("url") or source.get("index") or source.get("path") or source.get("directory") or source.get("editable") or source.get("virtual") or source.get("git") or source.get("vcs") or source.get("reference") or source.get("resolved_reference") or "")
    local = any(source.get(key) for key in ("path", "directory", "editable", "virtual"))
    resolved = str(source.get("resolved_reference") or source.get("reference") or source.get("rev") or "")
    pinned = bool(re.fullmatch(r"[0-9a-fA-F]{7,40}", resolved))
    return anchor, pinned, bool(local)


def _manifest(subject: CorpusSubject, path: Path) -> tuple[tuple[str, ...], tuple[str, ...], bool]:
    if subject.manager_family == "pip-tools":
        names = []
        for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
            line = line.strip()
            if line and not line.startswith(("#", "-")):
                name = _dep(line)
                if name:
                    names.append(name)
        return tuple(sorted(set(names))), (), False
    doc = tomllib.loads(path.read_text(encoding="utf-8"))
    if subject.manager_family == "pipenv":
        default = tuple(sorted(normalize_name(str(key)) for key in (doc.get("packages") or {}))) if isinstance(doc.get("packages"), dict) else ()
        optional = tuple(sorted(normalize_name(str(key)) for key in (doc.get("dev-packages") or {}))) if isinstance(doc.get("dev-packages"), dict) else ()
        sources = doc.get("source")
        return default, optional, isinstance(sources, list) and any(isinstance(item, dict) and item.get("url") for item in sources)
    project = doc.get("project") if isinstance(doc.get("project"), dict) else {}
    tool = doc.get("tool") if isinstance(doc.get("tool"), dict) else {}
    default = {_dep(item) for item in project.get("dependencies", []) if _dep(item)} if isinstance(project.get("dependencies"), list) else set()
    optional = set()
    for values in (project.get("optional-dependencies") or {}).values() if isinstance(project.get("optional-dependencies"), dict) else []:
        if isinstance(values, list):
            optional.update(_dep(item) for item in values if _dep(item))
    for values in (doc.get("dependency-groups") or {}).values() if isinstance(doc.get("dependency-groups"), dict) else []:
        if isinstance(values, list):
            optional.update(_dep(item) for item in values if _dep(item))
    explicit = False
    if subject.manager_family == "poetry":
        poetry = tool.get("poetry") if isinstance(tool.get("poetry"), dict) else {}
        if isinstance(poetry.get("dependencies"), dict):
            default.update(normalize_name(str(key)) for key in poetry["dependencies"] if str(key).lower() != "python")
        for group in (poetry.get("group") or {}).values() if isinstance(poetry.get("group"), dict) else []:
            if isinstance(group, dict) and isinstance(group.get("dependencies"), dict):
                optional.update(normalize_name(str(key)) for key in group["dependencies"] if str(key).lower() != "python")
        sources = poetry.get("source")
        explicit = isinstance(sources, list) and any(isinstance(item, dict) and item.get("url") for item in sources)
    elif subject.manager_family == "pdm":
        pdm = tool.get("pdm") if isinstance(tool.get("pdm"), dict) else {}
        if isinstance(pdm.get("dependencies"), dict):
            default.update(normalize_name(str(key)) for key in pdm["dependencies"])
        sources = pdm.get("source")
        explicit = isinstance(sources, list) and any(isinstance(item, dict) and item.get("url") for item in sources)
    elif subject.manager_family == "uv":
        uv = tool.get("uv") if isinstance(tool.get("uv"), dict) else {}
        indexes = uv.get("index")
        explicit = isinstance(indexes, list) and any(isinstance(item, dict) and item.get("url") for item in indexes)
    return tuple(sorted(default)), tuple(sorted(optional)), explicit


def parse_subject(artifact_root: Path, subject: CorpusSubject) -> ParsedSubject:
    directory = subject.directory(artifact_root)
    manifest_path = directory / subject.manifest_path
    lock_path = directory / subject.lockfile_path
    try:
        default, optional, manifest_source = _manifest(subject, manifest_path)
        packages: list[PackageRecord] = []
        lock_source = False
        epoch = False
        manager_metadata = False
        metadata: dict[str, Any] = {}
        if subject.manager_family == "pipenv":
            doc = json.loads(lock_path.read_text(encoding="utf-8"))
            meta = doc.get("_meta") if isinstance(doc.get("_meta"), dict) else {}
            sources = meta.get("sources") if isinstance(meta.get("sources"), list) else []
            lock_source = any(isinstance(item, dict) and item.get("url") for item in sources)
            for group in ("default", "develop"):
                for name, item in (doc.get(group) or {}).items() if isinstance(doc.get(group), dict) else []:
                    if not isinstance(item, dict):
                        continue
                    anchor = str(item.get("index") or item.get("git") or item.get("path") or "")
                    packages.append(PackageRecord(normalize_name(str(name)), str(item.get("version", "")).lstrip("="), _hashes(item.get("hashes")), anchor, (), (group,), str(item.get("markers") or ""), bool(item.get("ref") and re.fullmatch(r"[0-9a-fA-F]{7,40}", str(item.get("ref")))), bool(item.get("path"))))
                    lock_source = lock_source or bool(anchor)
            epoch = bool(meta.get("pipfile-spec")); manager_metadata = bool(meta.get("pipfile-spec") or meta.get("hash") or sources); metadata = meta
        elif subject.manager_family == "pip-tools":
            name = version = ""; hashes: list[str] = []; header: list[str] = []
            def flush() -> None:
                nonlocal name, version, hashes
                if name: packages.append(PackageRecord(normalize_name(name), version, tuple(sorted(set(hashes)))))
                name = version = ""; hashes = []
            for raw in lock_path.read_text(encoding="utf-8", errors="ignore").splitlines():
                if raw.startswith("#") and len(header) < 20: header.append(raw)
                match = _PIN.match(raw)
                if match:
                    flush(); name, version = match.group(1), match.group(2).rstrip("\\"); hashes.extend(_SHA.findall(raw))
                elif name:
                    hashes.extend(_SHA.findall(raw))
            flush(); generated = any("pip-compile" in item.lower() or "autogenerated" in item.lower() for item in header)
            epoch = generated; manager_metadata = generated; metadata = {"generated": generated}; lock_source = False
        else:
            doc = tomllib.loads(lock_path.read_text(encoding="utf-8"))
            for item in doc.get("package", []) if isinstance(doc.get("package"), list) else []:
                if not isinstance(item, dict): continue
                anchor, pinned, local = _source(item.get("source") if subject.manager_family in {"poetry", "uv"} else item)
                lock_source = lock_source or bool(anchor)
                hashes = _hashes(item.get("files"))
                if subject.manager_family == "uv":
                    combined = []
                    if isinstance(item.get("sdist"), dict): combined.append(str(item["sdist"].get("hash", "")))
                    if isinstance(item.get("wheels"), list): combined.extend(str(w.get("hash", "")) for w in item["wheels"] if isinstance(w, dict))
                    hashes = _hashes(combined)
                packages.append(PackageRecord(normalize_name(str(item.get("name", ""))), str(item.get("version", "")), hashes, anchor, _dep_set(item.get("dependencies")), (), str(item.get("marker") or ""), pinned, local))
            if subject.manager_family == "poetry":
                meta = doc.get("metadata") if isinstance(doc.get("metadata"), dict) else {}
                epoch = bool(meta.get("lock-version") or meta.get("lock_version") or meta.get("python-versions") or meta.get("content-hash")); manager_metadata = bool(meta.get("lock-version") or meta.get("lock_version") or meta.get("content-hash") or meta.get("content_hash")); metadata = meta
            elif subject.manager_family == "pdm":
                meta = doc.get("metadata") if isinstance(doc.get("metadata"), dict) else {}
                epoch = bool(meta.get("lock_version") or meta.get("content_hash")); manager_metadata = bool(meta.get("lock_version") or meta.get("content_hash") or meta.get("groups") or meta.get("strategy")); metadata = meta
            else:
                epoch = bool(doc.get("version") or doc.get("revision")); manager_metadata = bool(doc.get("version") or doc.get("revision") or doc.get("requires-python")); metadata = {key: doc.get(key) for key in ("version", "revision", "requires-python")}
        return ParsedSubject(subject, "parsed", tuple(packages), default, optional, bool(manifest_source or lock_source), epoch, manager_metadata, metadata)
    except Exception as exc:
        return ParsedSubject(subject, "error", errors=(f"{type(exc).__name__}: {exc}",))
