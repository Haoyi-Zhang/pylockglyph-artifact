"""Primary manager adapters for five Python lockfile families."""
from __future__ import annotations

import json
import re
from . import compat_toml as tomllib
from pathlib import Path
from typing import Any, Iterable

from .io import normalize_name
from .model import CorpusSubject, PackageRecord, ParsedSubject

_NAME_RE = re.compile(r"^\s*([A-Za-z0-9_.-]+)")
_PIN_RE = re.compile(r"^\s*([A-Za-z0-9_.-]+)(?:\[[^\]]+\])?==([^\s\\]+)")
_HASH_RE = re.compile(r"sha256:[0-9a-fA-F]{64}")
_VCS_PIN_RE = re.compile(r"(?:@|rev(?:ision)?[=:]|reference[=:])[^\s#]*[0-9a-fA-F]{7,40}")


def _read_toml(path: Path) -> dict[str, Any]:
    with path.open("rb") as handle:
        return tomllib.load(handle)


def _name(value: object) -> str:
    match = _NAME_RE.match(str(value or ""))
    return normalize_name(match.group(1)) if match else ""


def _dependencies(value: Any) -> tuple[str, ...]:
    found: list[str] = []
    if isinstance(value, dict):
        found.extend(normalize_name(str(key)) for key in value if str(key).strip())
    elif isinstance(value, list):
        for item in value:
            if isinstance(item, dict) and item.get("name"):
                found.append(normalize_name(str(item["name"])))
            else:
                dep = _name(item)
                if dep:
                    found.append(dep)
    elif isinstance(value, str):
        dep = _name(value)
        if dep:
            found.append(dep)
    return tuple(sorted(set(found)))


def _valid_hashes(value: Any) -> tuple[str, ...]:
    found: set[str] = set()
    if isinstance(value, list):
        for item in value:
            if isinstance(item, dict):
                hash_text = str(item.get("hash", ""))
            else:
                hash_text = str(item)
            found.update(_HASH_RE.findall(hash_text))
    elif isinstance(value, str):
        found.update(_HASH_RE.findall(value))
    return tuple(sorted(found))


def _source_properties(source: Any) -> tuple[str, bool, bool]:
    if not isinstance(source, dict):
        return "", False, False
    registry = str(source.get("registry") or source.get("url") or source.get("index") or "")
    path = str(source.get("path") or source.get("directory") or source.get("editable") or source.get("virtual") or "")
    git = str(source.get("git") or source.get("vcs") or "")
    resolved = str(source.get("resolved_reference") or "")
    reference = str(source.get("reference") or source.get("rev") or resolved or "")
    anchor = registry or path or git or reference
    local = bool(path)
    pinned = bool(resolved and re.fullmatch(r"[0-9a-fA-F]{7,40}", resolved)) or bool(reference and re.fullmatch(r"[0-9a-fA-F]{7,40}", reference)) or bool(_VCS_PIN_RE.search(" ".join((git, reference, resolved))))
    return anchor, pinned, local


def _manifest_pyproject(path: Path, manager: str) -> tuple[tuple[str, ...], tuple[str, ...], bool]:
    doc = _read_toml(path)
    project = doc.get("project") if isinstance(doc.get("project"), dict) else {}
    tool = doc.get("tool") if isinstance(doc.get("tool"), dict) else {}
    default: list[str] = []
    optional: list[str] = []
    if isinstance(project.get("dependencies"), list):
        default.extend(filter(None, (_name(item) for item in project["dependencies"])))
    optional_table = project.get("optional-dependencies")
    if isinstance(optional_table, dict):
        for values in optional_table.values():
            if isinstance(values, list):
                optional.extend(filter(None, (_name(item) for item in values)))
    groups = doc.get("dependency-groups")
    if isinstance(groups, dict):
        for values in groups.values():
            if isinstance(values, list):
                optional.extend(filter(None, (_name(item) for item in values)))
    explicit_source = False
    if manager == "poetry":
        poetry = tool.get("poetry") if isinstance(tool.get("poetry"), dict) else {}
        deps = poetry.get("dependencies") if isinstance(poetry.get("dependencies"), dict) else {}
        default.extend(normalize_name(str(key)) for key in deps if str(key).lower() != "python")
        group_table = poetry.get("group") if isinstance(poetry.get("group"), dict) else {}
        for group in group_table.values():
            if isinstance(group, dict) and isinstance(group.get("dependencies"), dict):
                optional.extend(normalize_name(str(key)) for key in group["dependencies"] if str(key).lower() != "python")
        sources = poetry.get("source")
        explicit_source = isinstance(sources, list) and any(isinstance(item, dict) and item.get("url") for item in sources)
    elif manager == "pdm":
        pdm = tool.get("pdm") if isinstance(tool.get("pdm"), dict) else {}
        deps = pdm.get("dependencies") if isinstance(pdm.get("dependencies"), dict) else {}
        default.extend(normalize_name(str(key)) for key in deps)
        sources = pdm.get("source")
        explicit_source = isinstance(sources, list) and any(isinstance(item, dict) and item.get("url") for item in sources)
    elif manager == "uv":
        uv = tool.get("uv") if isinstance(tool.get("uv"), dict) else {}
        indexes = uv.get("index")
        explicit_source = isinstance(indexes, list) and any(isinstance(item, dict) and item.get("url") for item in indexes)
    return tuple(sorted(set(default))), tuple(sorted(set(optional))), explicit_source


def _manifest_pipfile(path: Path) -> tuple[tuple[str, ...], tuple[str, ...], bool]:
    doc = _read_toml(path)
    default = tuple(sorted(normalize_name(str(key)) for key in (doc.get("packages") or {}) if str(key).strip())) if isinstance(doc.get("packages"), dict) else ()
    optional = tuple(sorted(normalize_name(str(key)) for key in (doc.get("dev-packages") or {}) if str(key).strip())) if isinstance(doc.get("dev-packages"), dict) else ()
    sources = doc.get("source")
    explicit = isinstance(sources, list) and any(isinstance(item, dict) and item.get("url") for item in sources)
    return default, optional, explicit


def _manifest_requirements(path: Path) -> tuple[tuple[str, ...], tuple[str, ...], bool]:
    default: list[str] = []
    for raw in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        line = raw.strip()
        if not line or line.startswith(("#", "-")):
            continue
        dep = _name(line)
        if dep:
            default.append(dep)
    return tuple(sorted(set(default))), (), False


def _parse_poetry(path: Path) -> tuple[tuple[PackageRecord, ...], bool, bool, bool, dict[str, Any]]:
    doc = _read_toml(path)
    packages: list[PackageRecord] = []
    package_source = False
    for item in doc.get("package", []) if isinstance(doc.get("package"), list) else []:
        if not isinstance(item, dict):
            continue
        source = item.get("source")
        anchor, pinned, local = _source_properties(source)
        package_source = package_source or bool(anchor)
        packages.append(PackageRecord(
            name=normalize_name(str(item.get("name", ""))),
            version=str(item.get("version", "")),
            hashes=_valid_hashes(item.get("files")),
            source_anchor=anchor,
            dependencies=_dependencies(item.get("dependencies")),
            groups=tuple(str(x) for x in item.get("groups", []) if str(x).strip()) if isinstance(item.get("groups"), list) else tuple([str(item.get("category"))]) if item.get("category") else (),
            marker=str(item.get("marker") or ""),
            pinned_source=pinned,
            local_source=local,
        ))
    metadata = doc.get("metadata") if isinstance(doc.get("metadata"), dict) else {}
    epoch = bool(metadata.get("lock-version") or metadata.get("lock_version") or metadata.get("python-versions") or metadata.get("content-hash"))
    manager_metadata = bool(metadata.get("lock-version") or metadata.get("lock_version") or metadata.get("content-hash") or metadata.get("content_hash"))
    return tuple(packages), package_source, epoch, manager_metadata, metadata


def _parse_pdm(path: Path) -> tuple[tuple[PackageRecord, ...], bool, bool, bool, dict[str, Any]]:
    doc = _read_toml(path)
    packages: list[PackageRecord] = []
    package_source = False
    for item in doc.get("package", []) if isinstance(doc.get("package"), list) else []:
        if not isinstance(item, dict):
            continue
        anchor, pinned, local = _source_properties(item)
        package_source = package_source or bool(anchor)
        packages.append(PackageRecord(
            name=normalize_name(str(item.get("name", ""))),
            version=str(item.get("version", "")),
            hashes=_valid_hashes(item.get("files")),
            source_anchor=anchor,
            dependencies=_dependencies(item.get("dependencies")),
            groups=tuple(str(x) for x in item.get("groups", []) if str(x).strip()) if isinstance(item.get("groups"), list) else (),
            marker=str(item.get("marker") or ""),
            pinned_source=pinned,
            local_source=local,
        ))
    metadata = doc.get("metadata") if isinstance(doc.get("metadata"), dict) else {}
    epoch = bool(metadata.get("lock_version") or metadata.get("content_hash"))
    manager_metadata = bool(metadata.get("lock_version") or metadata.get("content_hash") or metadata.get("groups") or metadata.get("strategy"))
    return tuple(packages), package_source, epoch, manager_metadata, metadata


def _parse_pipenv(path: Path) -> tuple[tuple[PackageRecord, ...], bool, bool, bool, dict[str, Any]]:
    doc = json.loads(path.read_text(encoding="utf-8"))
    meta = doc.get("_meta") if isinstance(doc.get("_meta"), dict) else {}
    sources = meta.get("sources") if isinstance(meta.get("sources"), list) else []
    explicit_source = any(isinstance(item, dict) and item.get("url") for item in sources)
    packages: list[PackageRecord] = []
    for section in ("default", "develop"):
        table = doc.get(section) if isinstance(doc.get(section), dict) else {}
        for name, item in table.items():
            if not isinstance(item, dict):
                continue
            source_anchor = str(item.get("index") or item.get("git") or item.get("path") or "")
            pinned = bool(item.get("ref") and re.fullmatch(r"[0-9a-fA-F]{7,40}", str(item.get("ref"))))
            local = bool(item.get("path"))
            packages.append(PackageRecord(
                name=normalize_name(str(name)),
                version=str(item.get("version", "")).lstrip("="),
                hashes=_valid_hashes(item.get("hashes")),
                source_anchor=source_anchor,
                dependencies=(),
                groups=(section,),
                marker=str(item.get("markers") or item.get("marker") or ""),
                pinned_source=pinned,
                local_source=local,
            ))
    epoch = bool(meta.get("pipfile-spec"))
    manager_metadata = bool(meta.get("pipfile-spec") or meta.get("hash") or sources)
    return tuple(packages), explicit_source or any(p.source_anchor for p in packages), epoch, manager_metadata, meta


def _parse_uv(path: Path) -> tuple[tuple[PackageRecord, ...], bool, bool, bool, dict[str, Any]]:
    doc = _read_toml(path)
    packages: list[PackageRecord] = []
    explicit_source = False
    for item in doc.get("package", []) if isinstance(doc.get("package"), list) else []:
        if not isinstance(item, dict):
            continue
        source = item.get("source")
        anchor, pinned, local = _source_properties(source)
        explicit_source = explicit_source or bool(anchor)
        hashes: set[str] = set()
        sdist = item.get("sdist")
        if isinstance(sdist, dict):
            hashes.update(_valid_hashes(str(sdist.get("hash", ""))))
        hashes.update(_valid_hashes(item.get("wheels")))
        packages.append(PackageRecord(
            name=normalize_name(str(item.get("name", ""))),
            version=str(item.get("version", "")),
            hashes=tuple(sorted(hashes)),
            source_anchor=anchor,
            dependencies=_dependencies(item.get("dependencies")),
            marker=";".join(str(x) for x in item.get("resolution-markers", []) if str(x).strip()) if isinstance(item.get("resolution-markers"), list) else "",
            pinned_source=pinned,
            local_source=local,
        ))
    epoch = bool(doc.get("version") or doc.get("revision"))
    manager_metadata = bool(doc.get("version") or doc.get("revision") or doc.get("requires-python"))
    return tuple(packages), explicit_source, epoch, manager_metadata, {k: doc.get(k) for k in ("version", "revision", "requires-python")}


def _parse_piptools(path: Path) -> tuple[tuple[PackageRecord, ...], bool, bool, bool, dict[str, Any]]:
    packages: list[PackageRecord] = []
    current_name = ""
    current_version = ""
    current_hashes: list[str] = []
    header: list[str] = []

    def flush() -> None:
        nonlocal current_name, current_version, current_hashes
        if current_name:
            packages.append(PackageRecord(name=normalize_name(current_name), version=current_version, hashes=tuple(sorted(set(current_hashes)))))
        current_name, current_version, current_hashes = "", "", []

    for raw in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        line = raw.rstrip()
        if line.startswith("#") and len(header) < 20:
            header.append(line)
        match = _PIN_RE.match(line)
        if match:
            flush()
            current_name, current_version = match.group(1), match.group(2).rstrip("\\")
            current_hashes.extend(_HASH_RE.findall(line))
        elif current_name:
            current_hashes.extend(_HASH_RE.findall(line))
    flush()
    generated = any("pip-compile" in line.lower() or "autogenerated" in line.lower() for line in header)
    return tuple(packages), False, generated, generated, {"header": "\n".join(header), "generated": generated}


def parse_subject(artifact_root: Path, subject: CorpusSubject) -> ParsedSubject:
    directory = subject.directory(artifact_root)
    manifest_path = directory / subject.manifest_path
    lockfile_path = directory / subject.lockfile_path
    try:
        if subject.manager_family == "pipenv":
            manifest_default, manifest_optional, manifest_source = _manifest_pipfile(manifest_path)
            packages, lock_source, epoch, metadata, raw = _parse_pipenv(lockfile_path)
        elif subject.manager_family in {"poetry", "pdm", "uv"}:
            manifest_default, manifest_optional, manifest_source = _manifest_pyproject(manifest_path, subject.manager_family)
            parser = {"poetry": _parse_poetry, "pdm": _parse_pdm, "uv": _parse_uv}[subject.manager_family]
            packages, lock_source, epoch, metadata, raw = parser(lockfile_path)
        elif subject.manager_family == "pip-tools":
            manifest_default, manifest_optional, manifest_source = _manifest_requirements(manifest_path)
            packages, lock_source, epoch, metadata, raw = _parse_piptools(lockfile_path)
        else:
            raise ValueError(f"unsupported manager family: {subject.manager_family}")
        return ParsedSubject(
            subject=subject,
            parser_status="parsed",
            packages=packages,
            manifest_default=manifest_default,
            manifest_optional=manifest_optional,
            explicit_source=bool(manifest_source or lock_source),
            resolver_epoch=epoch,
            manager_metadata=metadata,
            metadata=raw,
        )
    except Exception as exc:
        return ParsedSubject(subject=subject, parser_status="error", errors=(f"{type(exc).__name__}: {exc}",))


def parse_all(artifact_root: Path, subjects: Iterable[CorpusSubject]) -> tuple[ParsedSubject, ...]:
    return tuple(parse_subject(artifact_root, subject) for subject in subjects)
