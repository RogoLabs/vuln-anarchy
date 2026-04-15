#!/usr/bin/env python3
"""Build pre-computed index files: leaderboard.json, anarchy-map.json, stats.json, and rejected-with-ghsa.csv."""

import csv
import json
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

    stats = {
        "total_cves": len(all_records),
        "conflict_count": len(conflict_records),
        "gap_count": len(gap_records),
        "rejected_scored_count": len(rejected_scored),
        "max_drift_score": top_by_score.get("drift_score", 0),
        "max_drift_cve": top_by_score.get("cve_id", ""),
        "max_variance": top_by_variance.get("cvss_variance", 0),
        "max_variance_cve": top_by_variance.get("cve_id", ""),
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    }
    STATS_PATH.write_text(json.dumps(stats, indent=2))
    print(f"Stats written: {STATS_PATH}")


if __name__ == "__main__":
    main()
