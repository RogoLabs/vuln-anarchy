#!/usr/bin/env python3
"""Build pre-computed index files: leaderboard.json, anarchy-map.json, stats.json, vector-analysis.json, and rejected-with-ghsa.csv."""

import csv
import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

DATA_DIR = Path(__file__).parent.parent / "docs" / "data"
INDEXES_DIR = DATA_DIR / "indexes"
LEADERBOARD_PATH = INDEXES_DIR / "leaderboard.json"
ANARCHY_MAP_PATH = INDEXES_DIR / "anarchy-map.json"
REJECTED_CSV_PATH = DATA_DIR / "rejected-with-ghsa.csv"
CONFLICTS_CSV_PATH = DATA_DIR / "conflicts.csv"

LEADERBOARD_SIZE = 100       # Non-rejected entries — always 100 shown when Hide Rejected is on
LEADERBOARD_REJECTED_CAP = 15  # Rejected CVEs shown when Hide Rejected is off

STATS_PATH = INDEXES_DIR / "stats.json"
VECTOR_ANALYSIS_PATH = INDEXES_DIR / "vector-analysis.json"

# CVSS v3 metric metadata: key → (full name, value severity order high→low)
CVSS_METRICS = {
    "AV": ("Attack Vector",         {"N": 3, "A": 2, "L": 1, "P": 0}),
    "AC": ("Attack Complexity",     {"L": 1, "H": 0}),
    "PR": ("Privileges Required",   {"N": 2, "L": 1, "H": 0}),
    "UI": ("User Interaction",      {"N": 1, "R": 0}),
    "S":  ("Scope",                 {"C": 1, "U": 0}),
    "C":  ("Confidentiality",       {"H": 2, "M": 1, "L": 0, "N": -1}),
    "I":  ("Integrity",             {"H": 2, "M": 1, "L": 0, "N": -1}),
    "A":  ("Availability",          {"H": 2, "M": 1, "L": 0, "N": -1}),
}


def _parse_cvss_vector(vector: str) -> dict:
    """Parse a CVSS v3 vector string into a {metric: value} dict."""
    if not vector:
        return {}
    return {k: v for part in vector.split("/")[1:] for k, v in [part.split(":", 1)] if ":" in part}


def build_vector_analysis(conflict_records: list) -> dict:
    """
    Compare NVD vs GitHub CVSS vectors for every conflict CVE (same version only).
    Returns a dict suitable for vector-analysis.json.
    """
    metric_total: dict[str, int] = {m: 0 for m in CVSS_METRICS}
    metric_disagree: dict[str, int] = {m: 0 for m in CVSS_METRICS}
    metric_nvd_higher: dict[str, int] = {m: 0 for m in CVSS_METRICS}
    metric_gh_higher: dict[str, int] = {m: 0 for m in CVSS_METRICS}
    transitions: dict[str, Counter] = {m: Counter() for m in CVSS_METRICS}
    comparable = 0

    for record in conflict_records:
        nvd_vec = record.get("sources", {}).get("nvd", {}).get("cvss_vector", "")
        gh_vec = record.get("sources", {}).get("github", {}).get("cvss_vector", "")
        if not nvd_vec or not gh_vec:
            continue
        if nvd_vec.split("/")[0] != gh_vec.split("/")[0]:
            continue  # skip cross-version comparisons
        comparable += 1
        nvd_m = _parse_cvss_vector(nvd_vec)
        gh_m = _parse_cvss_vector(gh_vec)
        for key, (_, severity) in CVSS_METRICS.items():
            nv, gv = nvd_m.get(key), gh_m.get(key)
            if nv is None or gv is None:
                continue
            metric_total[key] += 1
            if nv != gv:
                metric_disagree[key] += 1
                transitions[key][f"{nv}→{gv}"] += 1
                ns, gs = severity.get(nv, -99), severity.get(gv, -99)
                if ns > gs:
                    metric_nvd_higher[key] += 1
                elif gs > ns:
                    metric_gh_higher[key] += 1

    metrics_out = []
    for key, (name, _) in CVSS_METRICS.items():
        total = metric_total[key]
        disagree = metric_disagree[key]
        top = [{"transition": t, "count": c} for t, c in transitions[key].most_common(5)]
        metrics_out.append({
            "key": key,
            "name": name,
            "total": total,
            "disagree_count": disagree,
            "disagree_rate": round(disagree / total * 100, 1) if total else 0,
            "nvd_higher_count": metric_nvd_higher[key],
            "gh_higher_count": metric_gh_higher[key],
            "top_transitions": top,
        })

    # Sort by disagree_rate descending for the chart
    metrics_out.sort(key=lambda x: -x["disagree_rate"])

    return {
        "comparable_conflicts": comparable,
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "metrics": metrics_out,
    }


def leaderboard_sort_key(record: dict):
    """Sort by drift_score descending — no special-casing for rejected type."""
    return -record.get("drift_score", 0)


def _published_date(record: dict) -> str | None:
    """Return the CVE published date as YYYY-MM-DD, or None if unavailable."""
    raw = record.get("sources", {}).get("nvd", {}).get("published")
    if raw:
        return raw[:10]  # trim to date portion
    return None


def build_leaderboard_entry(record: dict):
    nvd = record.get("sources", {}).get("nvd", {})
    github = record.get("sources", {}).get("github", {})
    return {
        "cve_id": record["cve_id"],
        "drift_score": record.get("drift_score", 0),
        "drift_type": record.get("drift_type", "gap"),
        "cvss_variance": record.get("cvss_variance", 0),
        "source_count": record.get("source_count", 0),
        "assigning_cna": record.get("assigning_cna"),
        "nvd_score": nvd.get("cvss_score"),
        "nvd_cvss_version": nvd.get("cvss_version"),
        "nvd_status": nvd.get("status"),
        "github_score": github.get("cvss_score"),
        "github_cvss_version": github.get("cvss_version"),
        "published_date": _published_date(record),
    }


def build_anarchy_map_entry(record: dict):
    nvd = record.get("sources", {}).get("nvd", {})
    github = record.get("sources", {}).get("github", {})
    return {
        "cve_id": record["cve_id"],
        "nvd_score": nvd.get("cvss_score"),
        "github_score": github.get("cvss_score"),
        "cvss_variance": record.get("cvss_variance", 0),
        "assigning_cna": record.get("assigning_cna"),
        "published_date": _published_date(record),
    }


def main():
    cve_files = sorted(DATA_DIR.glob("**/CVE-*.json"))
    if not cve_files:
        print("No CVE files found. Run ingestion and drift scripts first.")
        return

    print(f"Building indexes from {len(cve_files)} CVE files...")

    all_records = []
    for path in cve_files:
        try:
            record = json.loads(path.read_text())
            if "drift_score" not in record:
                continue
            all_records.append(record)
        except Exception as e:
            print(f"  Error reading {path.name}: {e}")

    # Classify records by drift type (used throughout)
    conflict_records = [r for r in all_records if r.get("drift_type") == "conflict"]
    gap_records = [r for r in all_records if r.get("drift_type") == "gap"]
    rejected_scored = [r for r in all_records if r.get("drift_type") == "rejected" and r.get("drift_score", 0) > 0.5]

    # Leaderboard: cap rejected CVEs to avoid dominating; fill rest with conflict/gap
    sorted_all = sorted(all_records, key=leaderboard_sort_key)
    rejected = [r for r in sorted_all if r.get("drift_type") == "rejected"][:LEADERBOARD_REJECTED_CAP]
    others = [r for r in sorted_all if r.get("drift_type") != "rejected"][:LEADERBOARD_SIZE]
    mixed = sorted(rejected + others, key=leaderboard_sort_key)
    leaderboard = [build_leaderboard_entry(r) for r in mixed]

    INDEXES_DIR.mkdir(parents=True, exist_ok=True)
    LEADERBOARD_PATH.write_text(json.dumps(leaderboard, indent=2))
    print(f"Leaderboard written: {LEADERBOARD_PATH} ({len(leaderboard)} entries)")

    # Anarchy Map: conflict CVEs only (both NVD and GitHub have scores)
    anarchy_map = [build_anarchy_map_entry(r) for r in conflict_records]
    ANARCHY_MAP_PATH.write_text(json.dumps(anarchy_map, indent=2))
    print(f"Anarchy Map written: {ANARCHY_MAP_PATH} ({len(anarchy_map)} entries)")

    # Vector Analysis: per-metric CVSS disagreement breakdown
    vector_analysis = build_vector_analysis(conflict_records)
    VECTOR_ANALYSIS_PATH.write_text(json.dumps(vector_analysis, indent=2))
    print(f"Vector Analysis written: {VECTOR_ANALYSIS_PATH} ({vector_analysis['comparable_conflicts']} comparable conflicts)")

    # Rejected-with-GHSA CSV: all CVEs rejected by NVD that still have a live GHSA
    rejected_rows = []
    for r in all_records:
        nvd = r.get("sources", {}).get("nvd", {})
        github = r.get("sources", {}).get("github", {})
        if nvd.get("status") == "Rejected" and github.get("ghsa_id"):
            ghsa_id = github["ghsa_id"]
            rejected_rows.append({
                "cve_id": r["cve_id"],
                "ghsa_id": ghsa_id,
                "ghsa_url": f"https://github.com/advisories/{ghsa_id}",
                "github_cvss_score": github.get("cvss_score", ""),
                "github_cvss_version": github.get("cvss_version", ""),
                "nvd_status": "Rejected",
                "assigning_cna": r.get("assigning_cna", ""),
            })
    rejected_rows.sort(key=lambda x: (-(x["github_cvss_score"] or 0), x["cve_id"]))
    with REJECTED_CSV_PATH.open("w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["cve_id", "ghsa_id", "ghsa_url", "github_cvss_score", "github_cvss_version", "nvd_status", "assigning_cna"])
        writer.writeheader()
        writer.writerows(rejected_rows)
    print(f"Rejected-with-GHSA CSV written: {REJECTED_CSV_PATH} ({len(rejected_rows)} entries)")

    # Stats aggregates already computed above; conflicts CSV below
    # Conflicts CSV: all CVEs where NVD and GitHub have conflicting CVSS scores
    conflict_rows = []
    for r in conflict_records:
        nvd = r.get("sources", {}).get("nvd", {})
        github = r.get("sources", {}).get("github", {})
        conflict_rows.append({
            "cve_id": r["cve_id"],
            "cvss_variance": r.get("cvss_variance", 0),
            "nvd_score": nvd.get("cvss_score", ""),
            "nvd_cvss_version": nvd.get("cvss_version", ""),
            "github_score": github.get("cvss_score", ""),
            "github_cvss_version": github.get("cvss_version", ""),
            "assigning_cna": r.get("assigning_cna", ""),
            "nvd_status": nvd.get("status", ""),
            "published_date": _published_date(r) or "",
        })
    conflict_rows.sort(key=lambda x: -float(x["cvss_variance"] or 0))
    with CONFLICTS_CSV_PATH.open("w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["cve_id", "cvss_variance", "nvd_score", "nvd_cvss_version", "github_score", "github_cvss_version", "assigning_cna", "nvd_status", "published_date"])
        writer.writeheader()
        writer.writerows(conflict_rows)
    print(f"Conflicts CSV written: {CONFLICTS_CSV_PATH} ({len(conflict_rows)} entries)")

    # Stats JSON: aggregate numbers for the UI stat cards
    top_by_score = max(all_records, key=lambda r: r.get("drift_score", 0), default={})
    top_by_variance = max(all_records, key=lambda r: r.get("cvss_variance", 0), default={})

    variances = sorted(r["cvss_variance"] for r in conflict_records if r.get("cvss_variance") is not None)
    avg_variance = round(sum(variances) / len(variances), 2) if variances else 0
    mid = len(variances) // 2
    median_variance = round(
        variances[mid] if len(variances) % 2 else (variances[mid - 1] + variances[mid]) / 2, 2
    ) if variances else 0

    stats = {
        "total_cves": len(all_records),
        "conflict_count": len(conflict_records),
        "gap_count": len(gap_records),
        "rejected_scored_count": len(rejected_scored),
        "max_drift_score": top_by_score.get("drift_score", 0),
        "max_drift_cve": top_by_score.get("cve_id", ""),
        "max_variance": top_by_variance.get("cvss_variance", 0),
        "max_variance_cve": top_by_variance.get("cve_id", ""),
        "avg_variance": avg_variance,
        "median_variance": median_variance,
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    }
    STATS_PATH.write_text(json.dumps(stats, indent=2))
    print(f"Stats written: {STATS_PATH}")


if __name__ == "__main__":
    main()
