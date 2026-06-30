#!/usr/bin/env python3
"""Render compact LaTeX tables and plot data from replay evidence."""
from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def rows(path: Path) -> list[dict[str, str]]:
    with path.open(newline="", encoding="utf-8") as handle:
        return list(csv.DictReader(handle))


def write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text.rstrip() + "\n", encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--evidence", type=Path, default=ROOT / "evidence")
    parser.add_argument("--paper", type=Path, default=ROOT.parent / "paper")
    args = parser.parse_args()
    evidence = args.evidence
    paper = args.paper

    manager = rows(evidence / "manager_profile_summary.csv")
    manager_lines = ["\\begin{tabular}{lrrr}", "\\toprule", "Manager & Pairs & Inventory & Graph \\\\", "\\midrule"]
    for row in manager:
        name = {"pdm": "PDM", "pip-tools": "pip-tools", "pipenv": "Pipenv", "poetry": "Poetry", "uv": "uv", "Total": "Total"}[row["manager_family"]]
        manager_lines.append(f"{name} & {row['pairs']} & {row['inventory_eligible']}/{row['pairs']} & {row['dependency_graph_eligible']}/{row['pairs']} \\\\")
    manager_lines += ["\\bottomrule", "\\end{tabular}"]
    write(paper / "tables" / "manager_profiles.tex", "\n".join(manager_lines))

    missing = rows(evidence / "missing_obligations.csv")
    missing_lines = ["\\begin{tabular}{lrrrr}", "\\toprule", "Manager & Source & Integrity & Edges & Drift \\\\", "\\midrule"]
    for row in missing:
        name = {"pdm": "PDM", "pip-tools": "pip-tools", "pipenv": "Pipenv", "poetry": "Poetry", "uv": "uv"}[row["manager_family"]]
        values = [row["source"], row["integrity"], row["dependency_edge"], row["manifest_agreement"]]
        marked = [f"\\textbf{{{value}}}" if value == "0" else value for value in values]
        missing_lines.append(f"{name} & {marked[0]} & {marked[1]} & {marked[2]} & {marked[3]} \\\\")
    missing_lines += ["\\bottomrule", "\\end{tabular}"]
    write(paper / "tables" / "missing_obligations.tex", "\n".join(missing_lines))

    controls = rows(evidence / "controlled_outcomes.csv")
    labels = {
        "file_removals": "Evidence removals",
        "adversarial_vectors": "Adversarial vectors",
        "metamorphic": "Metamorphic relations",
        "mutations": "Executable mutations",
        "formatting": "Formatting transformations",
        "parser_agreement": "Independent-parser comparisons",
    }
    control_lines = ["\\begin{tabular}{lrr}", "\\toprule", "Validation suite & Pass & Cases \\\\", "\\midrule"]
    for row in controls:
        pass_value = f"\\textbf{{{row['pass']}}}" if row["pass"] == row["cases"] else row["pass"]
        control_lines.append(f"{labels[row['suite']]} & {pass_value} & {row['cases']} \\\\")
    control_lines += ["\\bottomrule", "\\end{tabular}"]
    write(paper / "tables" / "controls.tex", "\n".join(control_lines))

    projections = rows(evidence / "projection_summary.csv")
    consumer_baselines = rows(evidence / "consumer_baseline_summary.csv")
    pretty = {
        "parser": "Parser",
        "inventory": "Name/version",
        "metadata": "Metadata",
        "integrity": "Integrity",
        "manifest_subset": "Manifest subset",
        "source_identity": "Source+identity",
        "resolver_metadata": "Resolver metadata",
        "sbom_minimal": "SBOM proxy",
        "vulnerability_graph": "Vuln graph proxy",
        "reproducible_lock": "Repro lock proxy",
    }

    projection_lines = ["\\begin{tabular}{lrr}", "\\toprule", "Projection & Accepts & Over-admits \\\\", "\\midrule"]
    coordinates = []
    figure_projections = {"parser", "inventory", "metadata", "integrity", "manifest_subset"}
    for row in projections:
        over = row["projection_over_admits"]
        over_marked = f"\\textbf{{{over}}}" if over == "0" else over
        projection_lines.append(f"{pretty[row['projection']]} & {row['projection_accepts']}/{row['decisions']} & {over_marked} \\\\")
        if row["projection"] in figure_projections:
            coordinates.append(f"({row['projection_over_admits']},{pretty[row['projection']]})")
    projection_lines += ["\\bottomrule", "\\end{tabular}"]
    write(paper / "tables" / "projections.tex", "\n".join(projection_lines))
    write(paper / "figures" / "projection_coordinates.tex", "\\addplot coordinates {" + " ".join(coordinates) + "};")

    focus = [
        row
        for row in consumer_baselines
        if row["projection"] in {"parser", "inventory", "sbom_minimal", "vulnerability_graph", "reproducible_lock"}
    ]
    consumer_names = {
        "sbom_inventory": "SBOM inventory",
        "vulnerability_matching": "Vulnerability matching",
        "reproducible_input": "Reproducible input",
        "full_dependency_graph": "Dependency graph",
    }
    baseline_lines = ["\\begin{tabular}{llrr}", "\\toprule", "Consumer & Baseline & Accepts & Over-admits \\\\", "\\midrule"]
    for row in focus:
        over = row["baseline_over_admits"]
        over_marked = f"\\textbf{{{over}}}" if over == "0" else over
        baseline_lines.append(
            f"{consumer_names[row['consumer']]} & {pretty[row['projection']]} & {row['baseline_accepts']}/{row['decisions']} & {over_marked} \\\\"
        )
    baseline_lines += ["\\bottomrule", "\\end{tabular}"]
    write(paper / "tables" / "consumer_baselines.tex", "\n".join(baseline_lines))

    summary = json.loads((evidence / "study_summary.json").read_text(encoding="utf-8"))
    tests = json.loads((evidence / "unit_test_summary.json").read_text(encoding="utf-8")) if (evidence / "unit_test_summary.json").is_file() else {"tests_run": 0}
    macros = [
        f"\\newcommand{{\\SubjectCount}}{{{summary['subjects']}}}",
        f"\\newcommand{{\\PackageCount}}{{{summary['package_records']:,}}}",
        f"\\newcommand{{\\InventoryEligible}}{{{summary['profiles']['inventory']}}}",
        f"\\newcommand{{\\GraphEligible}}{{{summary['profiles']['dependency_graph']}}}",
        f"\\newcommand{{\\ProjectionDecisions}}{{{summary['projection_decisions']}}}",
        f"\\newcommand{{\\ProjectionOver}}{{{summary['projection_over_admissions']}}}",
        f"\\newcommand{{\\ConsumerBaselineDecisions}}{{{summary['consumer_baseline_decisions']}}}",
        f"\\newcommand{{\\ConsumerBaselineOver}}{{{summary['consumer_baseline_over_admissions']}}}",
        f"\\newcommand{{\\ControlledCases}}{{{summary['controlled_cases']}}}",
        f"\\newcommand{{\\ProofDecisions}}{{{summary['proof_decisions']:,}}}",
        f"\\newcommand{{\\UnitTests}}{{{tests['tests_run']}}}",
    ]
    write(paper / "tables" / "macros.tex", "\n".join(macros))
    print(json.dumps({"status": "pass", "tables": 6, "figures": 1, "tests": tests["tests_run"]}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
