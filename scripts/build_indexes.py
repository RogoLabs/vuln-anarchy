#!/usr/bin/env python3
"""Build pre-computed index files: leaderboard.json, anarchy-map.json, and rejected-with-ghsa.csv."""

import csv
import json
from pathlib import Path

DATA_DIR = Path(__file__).parent.parent / "docs" / "data"
INDEXES_DIR = DATA_DIR / "indexes"
LEADERBOARD_PATH = INDEXES_DIR / "leaderboard.json"
ANARCHY_MAP_PATH = INDEXES_DIR / "anarchy-map.json"
REJECTED_CSV_PATH = DATA_DIR / "rejected-with-ghsa.csv"

LEADERBOARD_SIZE = 50


def leaderboard_sort_key(record: dict):
    """
    Sort key for leaderboard: rejected always floats to top,
    then by drift_score descending.
    """
    is_rejected = 1 if record.get("drift_type") == "rejected" else 0
    return (-is_rejected, -record.get("drift_score", 0))


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
    }


def build_anarchy_map_entry(record: dict):
    epss = record.get("sources", {}).get("epss", {})
    return {
        "cve_id": record["cve_id"],
        "cvss_variance": record.get("cvss_variance", 0),
        "drift_score": record.get("drift_score", 0),
        "drift_type": record.get("drift_type", "gap"),
        "source_count": record.get("source_count", 0),
        # EPSS fields null in Phase 1; populated in Phase 2
        "epss_score": epss.get("score"),
        "epss_percentile": epss.get("percentile"),
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

    # Leaderboard: top N sorted with rejected floated to top
    sorted_records = sorted(all_records, key=leaderboard_sort_key)
    leaderboard = [build_leaderboard_entry(r) for r in sorted_records[:LEADERBOARD_SIZE]]

    INDEXES_DIR.mkdir(parents=True, exist_ok=True)
    LEADERBOARD_PATH.write_text(json.dumps(leaderboard, indent=2))
    print(f"Leaderboard written: {LEADERBOARD_PATH} ({len(leaderboard)} entries)")

    # Anarchy Map: all CVEs with variance and EPSS data
    anarchy_map = [build_anarchy_map_entry(r) for r in all_records]
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


if __name__ == "__main__":
    main()
