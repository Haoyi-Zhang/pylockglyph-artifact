"""Typed domain model for profile-indexed lockfile admission."""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Mapping


class EvidenceType(str, Enum):
    IDENTITY = "identity"
    VERSION = "version"
    SOURCE = "source"
    INTEGRITY = "integrity"
    RESOLVER_EPOCH = "resolver_epoch"
    DEPENDENCY_EDGE = "dependency_edge"
    MANAGER_METADATA = "manager_metadata"
    MANIFEST_AGREEMENT = "manifest_agreement"


EVIDENCE_TYPES: tuple[EvidenceType, ...] = tuple(EvidenceType)
MANAGERS: tuple[str, ...] = ("pdm", "pip-tools", "pipenv", "poetry", "uv")


@dataclass(frozen=True)
class CorpusSubject:
    subject_id: str
    manager_family: str
    repository: str
    commit: str
    manifest_path: str
    lockfile_path: str
    local_path: str
    license_status: str
    manager_project: bool = False

    def directory(self, artifact_root: Path) -> Path:
        return artifact_root / self.local_path


@dataclass(frozen=True)
class PackageRecord:
    name: str
    version: str
    hashes: tuple[str, ...] = ()
    source_anchor: str = ""
    dependencies: tuple[str, ...] = ()
    groups: tuple[str, ...] = ()
    marker: str = ""
    pinned_source: bool = False
    local_source: bool = False

    @property
    def integrity_witness(self) -> bool:
        return bool(self.hashes) or self.pinned_source or self.local_source


@dataclass(frozen=True)
class EvidenceVector:
    values: Mapping[EvidenceType, bool]

    def has(self, evidence_type: EvidenceType) -> bool:
        return bool(self.values.get(evidence_type, False))

    def support(self) -> frozenset[EvidenceType]:
        return frozenset(t for t in EVIDENCE_TYPES if self.has(t))

    def missing(self, required: frozenset[EvidenceType]) -> tuple[EvidenceType, ...]:
        return tuple(t for t in EVIDENCE_TYPES if t in required and not self.has(t))

    def as_dict(self) -> dict[str, bool]:
        return {t.value: self.has(t) for t in EVIDENCE_TYPES}


@dataclass(frozen=True)
class ParsedSubject:
    subject: CorpusSubject
    parser_status: str
    packages: tuple[PackageRecord, ...] = ()
    manifest_default: tuple[str, ...] = ()
    manifest_optional: tuple[str, ...] = ()
    explicit_source: bool = False
    resolver_epoch: bool = False
    manager_metadata: bool = False
    metadata: Mapping[str, Any] = field(default_factory=dict)
    errors: tuple[str, ...] = ()

    @property
    def package_names(self) -> frozenset[str]:
        return frozenset(p.name for p in self.packages if p.name)

    @property
    def evidence(self) -> EvidenceVector:
        usable = self.parser_status == "parsed" and bool(self.packages)
        default = frozenset(self.manifest_default)
        return EvidenceVector({
            EvidenceType.IDENTITY: usable and all(bool(p.name) for p in self.packages),
            EvidenceType.VERSION: usable and all(bool(p.version) for p in self.packages),
            EvidenceType.SOURCE: usable and self.explicit_source,
            EvidenceType.INTEGRITY: usable and all(p.integrity_witness for p in self.packages),
            EvidenceType.RESOLVER_EPOCH: usable and self.resolver_epoch,
            EvidenceType.DEPENDENCY_EDGE: usable and any(bool(p.dependencies) for p in self.packages),
            EvidenceType.MANAGER_METADATA: usable and self.manager_metadata,
            EvidenceType.MANIFEST_AGREEMENT: usable and default.issubset(self.package_names),
        })


@dataclass(frozen=True)
class CertificateDecision:
    subject_id: str
    profile: str
    eligible: bool
    missing: tuple[EvidenceType, ...]
    evidence: EvidenceVector
    parser_status: str

    def as_dict(self) -> dict[str, object]:
        return {
            "subject_id": self.subject_id,
            "profile": self.profile,
            "eligible": self.eligible,
            "parser_status": self.parser_status,
            "missing": ";".join(t.value for t in self.missing),
            **self.evidence.as_dict(),
        }
