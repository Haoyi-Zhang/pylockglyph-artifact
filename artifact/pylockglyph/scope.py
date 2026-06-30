"""Claim-scope and boundary audits for the research package."""
from __future__ import annotations

import json
import re
from pathlib import Path

from .io import write_json


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="ignore")


def _sentences(text: str) -> list[str]:
    compact = re.sub(r"\s+", " ", text)
    return [item.strip() for item in re.split(r"(?<=[.!?])\s+", compact) if item.strip()]


def _strip_tex_commands(text: str) -> str:
    text = re.sub(r"%.*", "", text)
    text = re.sub(r"\\cite\w*\s*\{[^}]*\}", "", text)
    text = re.sub(r"\\ref\s*\{[^}]*\}", "", text)
    text = re.sub(r"\\label\s*\{[^}]*\}", "", text)
    text = re.sub(r"\\[a-zA-Z]+\*?(?:\[[^]]*\])?(?:\{([^{}]*)\})?", lambda m: m.group(1) or "", text)
    return text


BOUNDARY_TERMS = {
    "prevalence": re.compile(r"\bprevalence\b", re.IGNORECASE),
    "random_sample": re.compile(r"\b(random|probability) sample\b|\brepresentative sample\b", re.IGNORECASE),
    "manager_ranking": re.compile(r"\b(manager ranking|rank(?:ed|ing) managers?)\b", re.IGNORECASE),
    "population_inference": re.compile(r"\becosystem-wide\b|\bpopulation inference\b|\bgeneralize to the Python ecosystem\b", re.IGNORECASE),
    "accuracy_metrics": re.compile(r"\b(accuracy|precision|recall|F1|false positive|false negative|ROC|AUC)\b", re.IGNORECASE),
}

SAFE_BOUNDARY_MARKERS = re.compile(
    r"\b(not|no|without|avoid|avoids|outside|does not|do not|must not|cannot|rather than|benchmark-scoped|construct-validation|not used to|not interpreted as|is not a|prevents|preventing|keeps)\b",
    re.IGNORECASE,
)

PROCESS_TERMS = [
    "best" + " paper",
    "strong" + " accept",
    "major" + " revision",
    "weak" + " reject",
    "re" + "viewer",
    "meta-" + "re" + "view",
    "ga" + "te\\s*\\d+",
    "protocol" + "_blocked",
    "sub" + "mission",
    "fi" + "nal version",
    "pro" + "mpt",
    "chat" + "gpt",
    "L" + "LM",
    "large language" + " model",
    "AI" + "-generated",
    "ag" + "ent",
]
PROCESS_OR_AI = re.compile(r"\b(?:" + "|".join(PROCESS_TERMS) + r")\b", re.IGNORECASE)

ARTIFACT_TRACE = re.compile(
    r"\b(?:artifact/tool|pylockglyph/|def\s+\w+|function\s+\w+|script\s+\w+\.py|run_gate|Gate6)\b",
    re.IGNORECASE,
)

REQUIRED_SCOPE_PHRASES = [
    "not a random sample",
    "not used to estimate ecosystem prevalence",
    "consumer profile",
]
REQUIRED_SCOPE_PATTERNS = {
    "benchmark_scoped_construct_validation": re.compile(r"benchmark[- ]scoped construct[- ]validation", re.IGNORECASE),
    "not_manager_ranking": re.compile(r"not (?:a )?manager ranking|not (?:manager )?rankings|manager rankings?\b.*not", re.IGNORECASE),
}


def audit_claim_scope(repository_root: Path, output: Path | None = None) -> dict[str, object]:
    """Check that authored claims match the construct-validation design.

    The audit is intentionally textual and conservative. It does not decide the
    science; it guards against accidental population claims, process traces, and
    paper-as-implementation phrasing.
    """
    paper = repository_root / "paper"
    main_tex = _read(paper / "main.tex")
    supplement_tex = _read(paper / "supplement.tex") if (paper / "supplement.tex").is_file() else ""
    authored = _strip_tex_commands(main_tex + "\n" + supplement_tex)
    main_authored = _strip_tex_commands(main_tex)
    findings: list[dict[str, str]] = []

    process_hits = sorted(set(m.group(0) for m in PROCESS_OR_AI.finditer(authored)))
    if process_hits:
        findings.append({
            "severity": "P0",
            "check": "process_or_ai_trace",
            "detail": ", ".join(process_hits[:20]),
        })

    artifact_hits = sorted(set(m.group(0) for m in ARTIFACT_TRACE.finditer(main_authored)))
    if artifact_hits:
        findings.append({
            "severity": "P1",
            "check": "main_paper_implementation_trace",
            "detail": ", ".join(artifact_hits[:20]),
        })

    unsafe_sentences: list[str] = []
    for sentence in _sentences(authored):
        matched = [name for name, pattern in BOUNDARY_TERMS.items() if pattern.search(sentence)]
        if matched and not SAFE_BOUNDARY_MARKERS.search(sentence):
            unsafe_sentences.append("/".join(matched) + ": " + sentence[:220])
    if unsafe_sentences:
        findings.append({
            "severity": "P0",
            "check": "unbounded_empirical_claim",
            "detail": " | ".join(unsafe_sentences[:8]),
        })

    lower_authored = authored.lower()
    missing_phrases = [phrase for phrase in REQUIRED_SCOPE_PHRASES if phrase.lower() not in lower_authored]
    missing_phrases.extend(name for name, pattern in REQUIRED_SCOPE_PATTERNS.items() if not pattern.search(authored))
    if missing_phrases:
        findings.append({
            "severity": "P1",
            "check": "scope_statement",
            "detail": ", ".join(missing_phrases),
        })

    main_lower = main_authored.lower()
    for concept in ("principal filter", "typed non-substitution", "projection separation", "consumer profile", "rejected verdict"):
        if concept not in main_lower:
            findings.append({"severity": "P1", "check": "theory_visibility", "detail": concept})

    status = "pass" if not findings else "fail"
    summary: dict[str, object] = {
        "status": status,
        "findings": findings,
        "boundary_terms_checked": sorted(BOUNDARY_TERMS),
        "required_scope_phrases": REQUIRED_SCOPE_PHRASES + sorted(REQUIRED_SCOPE_PATTERNS),
    }
    if output is not None:
        write_json(output, summary)
    return summary
