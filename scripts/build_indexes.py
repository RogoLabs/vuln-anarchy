#!/usr/bin/env python3
"""Build pre-computed index files: leaderboard.json, anarchy-map.json, stats.json, vector-analysis.json, cna-stats.json, backlog.json, coverage-gap.json, and CSV exports."""

import csv
import json
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path

DATA_DIR = Path(__file__).parent.parent / "docs" / "data"
INDEXES_DIR = DATA_DIR / "indexes"
LEADERBOARD_PATH = INDEXES_DIR / "leaderboard.json"
ANARCHY_MAP_PATH = INDEXES_DIR / "anarchy-map.json"
REJECTED_CSV_PATH = DATA_DIR / "rejected-with-ghsa.csv"
CONFLICTS_CSV_PATH = DATA_DIR / "conflicts.csv"

LEADERBOARD_SIZE = 500      # Top conflict CVEs (both NVD and GitHub have a CVSS score)
COVERAGE_GAP_SIZE = 500     # Top GitHub-only CVEs in coverage-gap.json

STATS_PATH = INDEXES_DIR / "stats.json"
VECTOR_ANALYSIS_PATH = INDEXES_DIR / "vector-analysis.json"
CNA_STATS_PATH = INDEXES_DIR / "cna-stats.json"
BACKLOG_PATH = INDEXES_DIR / "backlog.json"
COVERAGE_GAP_PATH = INDEXES_DIR / "coverage-gap.json"

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


def _has_both_scores(r: dict) -> bool:
    nvd_s = r.get("sources", {}).get("nvd", {}).get("cvss_score")
    gh_s = r.get("sources", {}).get("github", {}).get("cvss_score")
    return bool(nvd_s and nvd_s > 0 and gh_s)


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
        "metadata_conflict": record.get("metadata_conflict", 0),
        "severity_flip": record.get("severity_flip", False),
        "nvd_severity": record.get("nvd_severity"),
        "gh_severity": record.get("gh_severity"),
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


def build_cna_stats(all_records: list, conflict_records: list) -> list:
    """Build per-CNA conflict statistics for cna-stats.json."""
    cna_total: dict[str, int] = defaultdict(int)
    cna_comparable: dict[str, int] = defaultdict(int)
    cna_conflicts: dict[str, list] = defaultdict(list)
    cna_nvd_higher: dict[str, int] = defaultdict(int)
    cna_gh_higher: dict[str, int] = defaultdict(int)

    for r in all_records:
        cna = r.get("assigning_cna") or "unknown"
        cna_total[cna] += 1
        if _has_both_scores(r):
            cna_comparable[cna] += 1

    for r in conflict_records:
        cna = r.get("assigning_cna") or "unknown"
        nvd_s = r.get("sources", {}).get("nvd", {}).get("cvss_score") or 0
        gh_s = r.get("sources", {}).get("github", {}).get("cvss_score") or 0
        cna_conflicts[cna].append({
            "drift_score": r.get("drift_score", 0),
            "cve_id": r["cve_id"],
        })
        if nvd_s > gh_s:
            cna_nvd_higher[cna] += 1
        else:
            cna_gh_higher[cna] += 1

    result = []
    all_cnas = set(cna_comparable.keys()) | set(cna_conflicts.keys())

    for cna in all_cnas:
        comparable = cna_comparable.get(cna, 0)
        if comparable < 5:
            continue  # Skip CNAs with too few dual-scored CVEs
        conflicts = cna_conflicts.get(cna, [])
        conflict_count = len(conflicts)
        avg_drift = round(sum(c["drift_score"] for c in conflicts) / conflict_count, 2) if conflicts else 0
        top_cve = None
        if conflicts:
            top_cve = max(conflicts, key=lambda c: c["drift_score"])["cve_id"]
        result.append({
            "name": cna,
            "total": cna_total.get(cna, 0),
            "comparable": comparable,
            "conflicts": conflict_count,
            "conflict_rate": round(conflict_count / comparable * 100, 1) if comparable else 0,
            "avg_drift": avg_drift,
            "nvd_higher_count": cna_nvd_higher.get(cna, 0),
            "gh_higher_count": cna_gh_higher.get(cna, 0),
            "top_cve": top_cve,
        })

    result.sort(key=lambda x: -x["conflict_rate"])
    return result


def build_backlog(all_records: list) -> dict:
    """Build NVD analysis lag statistics for backlog.json."""
    days_list = []
    status_counts: dict[str, int] = defaultdict(int)

    for r in all_records:
        nvd = r.get("sources", {}).get("nvd", {})
        status = nvd.get("status") or "Unknown"
        status_counts[status] += 1
        dta = nvd.get("days_to_analysis")
        if dta is not None and dta >= 0:
            days_list.append(dta)

    days_list.sort()
    total = len(days_list)
    avg_dta = round(sum(days_list) / total, 1) if total else None
    p90_dta = days_list[int(total * 0.9)] if total else None

    bucket_defs = [
        ("0–7 days", 0, 7),
        ("8–30 days", 8, 30),
        ("31–90 days", 31, 90),
        ("91–180 days", 91, 180),
        ("181–365 days", 181, 365),
        (">365 days", 366, None),
    ]
    distribution = []
    for label, lo, hi in bucket_defs:
        if hi is None:
            count = sum(1 for d in days_list if d >= lo)
        else:
            count = sum(1 for d in days_list if lo <= d <= hi)
        distribution.append({"range": label, "count": count})

    return {
        "total_with_analysis_date": total,
        "avg_days_to_analysis": avg_dta,
        "p90_days_to_analysis": p90_dta,
        "awaiting_analysis_count": status_counts.get("Awaiting Analysis", 0),
        "undergoing_analysis_count": status_counts.get("Undergoing Analysis", 0),
        "deferred_count": status_counts.get("Deferred", 0),
        "status_breakdown": dict(status_counts),
        "distribution_buckets": distribution,
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    }


def build_coverage_gap(all_records: list) -> dict:
    """Build index of CVEs GitHub has scored but NVD has not for coverage-gap.json."""
    def _has_gh_score(r: dict) -> bool:
        return bool(r.get("sources", {}).get("github", {}).get("cvss_score"))

    def _has_nvd_score(r: dict) -> bool:
        score = r.get("sources", {}).get("nvd", {}).get("cvss_score")
        return bool(score and score > 0)

    gap = [r for r in all_records if _has_gh_score(r) and not _has_nvd_score(r)]

    gh_scores = [
        r["sources"]["github"]["cvss_score"]
        for r in gap
        if r.get("sources", {}).get("github", {}).get("cvss_score")
    ]
    avg_gh = round(sum(gh_scores) / len(gh_scores), 2) if gh_scores else 0

    severity_dist = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for s in gh_scores:
        if s >= 9.0:
            severity_dist["critical"] += 1
        elif s >= 7.0:
            severity_dist["high"] += 1
        elif s >= 4.0:
            severity_dist["medium"] += 1
        else:
            severity_dist["low"] += 1

    nvd_status_dist: dict[str, int] = defaultdict(int)
    for r in gap:
        status = r.get("sources", {}).get("nvd", {}).get("status") or "No NVD Record"
        nvd_status_dist[status] += 1

    top = sorted(gap, key=lambda r: -(r.get("sources", {}).get("github", {}).get("cvss_score") or 0))
    entries = []
    for r in top[:COVERAGE_GAP_SIZE]:
        nvd = r.get("sources", {}).get("nvd", {})
        github = r.get("sources", {}).get("github", {})
        entries.append({
            "cve_id": r["cve_id"],
            "github_score": github.get("cvss_score"),
            "github_cvss_version": github.get("cvss_version"),
            "ghsa_id": github.get("ghsa_id"),
            "nvd_status": nvd.get("status") or "No NVD Record",
            "assigning_cna": r.get("assigning_cna"),
            "published_date": _published_date(r),
        })

    return {
        "total": len(gap),
        "avg_github_score": avg_gh,
        "severity_distribution": severity_dist,
        "nvd_status_breakdown": dict(nvd_status_dist),
        "entries": entries,
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
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

    # Comparable = CVEs where BOTH NVD and GitHub have a CVSS score
    comparable_records = [r for r in all_records if _has_both_scores(r)]

    # Leaderboard: conflict CVEs only — both NVD and GitHub have a CVSS score and disagree
    sorted_conflicts = sorted(conflict_records, key=leaderboard_sort_key)
    leaderboard = [build_leaderboard_entry(r) for r in sorted_conflicts[:LEADERBOARD_SIZE]]

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

    # Direction asymmetry: which source scores higher across all conflict CVEs
    nvd_higher_count = sum(
        1 for r in conflict_records
        if (r.get("sources", {}).get("nvd", {}).get("cvss_score") or 0)
        > (r.get("sources", {}).get("github", {}).get("cvss_score") or 0)
    )
    gh_higher_count = len(conflict_records) - nvd_higher_count

    # Conflict by year
    conflict_by_year: dict[str, int] = defaultdict(int)
    for r in conflict_records:
        pub = r.get("sources", {}).get("nvd", {}).get("published", "")
        if pub:
            conflict_by_year[pub[:4]] += 1

    # Severity flip count (conflicts that cross a severity band boundary)
    severity_flip_count = sum(1 for r in conflict_records if r.get("severity_flip"))

    # Severity distribution among conflict CVEs (by NVD score)
    sev_dist: dict[str, int] = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    for r in conflict_records:
        nvd_s = r.get("sources", {}).get("nvd", {}).get("cvss_score") or 0
        if nvd_s >= 9.0:
            sev_dist["Critical"] += 1
        elif nvd_s >= 7.0:
            sev_dist["High"] += 1
        elif nvd_s >= 4.0:
            sev_dist["Medium"] += 1
        else:
            sev_dist["Low"] += 1

    # NVD backlog quick stats (from backlog index)
    days_list = sorted(
        nvd["days_to_analysis"]
        for r in all_records
        if (nvd := r.get("sources", {}).get("nvd", {})) and nvd.get("days_to_analysis") is not None and nvd["days_to_analysis"] >= 0
    )
    avg_dta = round(sum(days_list) / len(days_list), 1) if days_list else None
    p90_dta = days_list[int(len(days_list) * 0.9)] if days_list else None

    stats = {
        "total_cves": len(all_records),
        "comparable_count": len(comparable_records),
        "conflict_count": len(conflict_records),
        "conflict_rate": round(len(conflict_records) / len(comparable_records) * 100, 1) if comparable_records else 0,
        "gap_count": len(gap_records),
        "rejected_scored_count": len(rejected_scored),
        "max_drift_score": top_by_score.get("drift_score", 0),
        "max_drift_cve": top_by_score.get("cve_id", ""),
        "max_variance": top_by_variance.get("cvss_variance", 0),
        "max_variance_cve": top_by_variance.get("cve_id", ""),
        "avg_variance": avg_variance,
        "median_variance": median_variance,
        "direction_asymmetry": {
            "nvd_higher_count": nvd_higher_count,
            "gh_higher_count": gh_higher_count,
        },
        "conflict_by_year": dict(sorted(conflict_by_year.items())),
        "severity_flip_count": severity_flip_count,
        "severity_distribution": sev_dist,
        "avg_days_to_analysis": avg_dta,
        "p90_days_to_analysis": p90_dta,
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    }
    STATS_PATH.write_text(json.dumps(stats, indent=2))
    print(f"Stats written: {STATS_PATH}")

    # CNA Stats
    cna_stats = build_cna_stats(all_records, conflict_records)
    CNA_STATS_PATH.write_text(json.dumps({
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "cnas": cna_stats,
    }, indent=2))
    print(f"CNA Stats written: {CNA_STATS_PATH} ({len(cna_stats)} CNAs)")

    # Backlog
    backlog = build_backlog(all_records)
    BACKLOG_PATH.write_text(json.dumps(backlog, indent=2))
    print(f"Backlog written: {BACKLOG_PATH}")

    # Coverage Gap
    coverage_gap = build_coverage_gap(all_records)
    COVERAGE_GAP_PATH.write_text(json.dumps(coverage_gap, indent=2))
    print(f"Coverage Gap written: {COVERAGE_GAP_PATH} ({coverage_gap['total']} entries)")


if __name__ == "__main__":
    main()
