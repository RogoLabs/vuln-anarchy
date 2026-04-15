#!/usr/bin/env python3
"""Compute Drift Score and drift_type for all CVE JSON files."""

import json
from pathlib import Path

DATA_DIR = Path(__file__).parent.parent / "docs" / "data"

# CWEs that are effectively meaningless for defenders
WEAK_CWES = {"NVD-CWE-noinfo", "NVD-CWE-Other", "CWE-noinfo", "CWE-Other"}
# Mid-level/generic CWEs — present but not specific
GENERIC_CWES = {"CWE-693", "CWE-664", "CWE-682", "CWE-435", "CWE-691", "CWE-703", "CWE-707", "CWE-710"}


def collect_cvss_scores(sources: dict):
    """
    Return a dict of {version: [scores]} across all sources.
    Only groups scores of the same version — cross-version comparison is forbidden.
    """
    by_version = {}
    for source_name, source in sources.items():
        if source_name in ("cisa_kev", "epss"):
            continue
        score = source.get("cvss_score")
        version = source.get("cvss_version")
        if score is not None and version is not None:
            by_version.setdefault(version, []).append(score)
    return by_version


def compute_cvss_variance(by_version: dict):
    """
    Return the max CVSS variance within any single version group.
    Returns 0.0 if fewer than 2 scores exist within the same version.
    """
    max_variance = 0.0
    for version, scores in by_version.items():
        if len(scores) >= 2:
            variance = round(max(scores) - min(scores), 2)
            max_variance = max(max_variance, variance)
    return max_variance


def compute_metadata_conflict(sources: dict):
    """
    Score metadata conflicts (CWE disagreements, version range gaps).
    Returns a float 0.0–1.0.
    """
    conflict = 0.0

    cwes = []
    for source_name, source in sources.items():
        if source_name in ("cisa_kev", "epss", "github"):
            continue
        cwe_list = source.get("cwe", [])
        if cwe_list:
            cwes.append(frozenset(cwe_list))

    # Multiple sources with different CWE sets = conflict
    if len(cwes) >= 2 and len(set(cwes)) > 1:
        conflict += 0.5

    # Weak/missing CWE from NVD = metadata gap
    nvd = sources.get("nvd", {})
    nvd_cwes = set(nvd.get("cwe", []))
    if not nvd_cwes or nvd_cwes.issubset(WEAK_CWES):
        conflict += 0.3
    elif nvd_cwes.issubset(GENERIC_CWES):
        conflict += 0.1

    # GitHub has version ranges but NVD has none = remediation gap
    github = sources.get("github", {})
    osv = sources.get("osv", {})
    has_version_data = bool(github.get("affected") or osv.get("affected"))
    nvd_has_cpe = bool(nvd.get("cpe"))
    if has_version_data and not nvd_has_cpe:
        conflict += 0.2

    return round(min(conflict, 1.0), 3)


def classify_drift_type(record: dict, cvss_variance: float, by_version: dict):
    """
    Determine drift_type:
    - 'rejected'  — NVD status is Rejected
    - 'conflict'  — sources disagree on CVSS value (same version, variance > 0)
    - 'gap'       — one or more sources have no data, or cross-version comparison would be needed
    """
    nvd = record.get("sources", {}).get("nvd", {})
    status = nvd.get("status", "")

    if status == "Rejected":
        return "rejected"

    # Cross-version gap: sources have scores but in different CVSS versions
    all_versions = set()
    sources = record.get("sources", {})
    for sname, s in sources.items():
        if sname in ("cisa_kev", "epss"):
            continue
        if s.get("cvss_score") is not None and s.get("cvss_version") is not None:
            all_versions.add(s.get("cvss_version"))
    if len(all_versions) > 1:
        return "gap"

    if cvss_variance > 0:
        return "conflict"

    # Check for outright missing data
    source_names = [k for k in sources if k not in ("cisa_kev", "epss")]
    sources_with_score = sum(
        1 for k in source_names if sources[k].get("cvss_score") is not None
    )
    if sources_with_score < len(source_names):
        return "gap"

    return "gap" if sources_with_score <= 1 else "conflict"


def source_conflict_count(sources: dict):
    """Count how many sources have data (for Anarchy Map color intensity)."""
    return sum(
        1 for k, v in sources.items()
        if k not in ("cisa_kev", "epss") and v.get("cvss_score") is not None
    )


def compute_drift_score(
    drift_type: str,
    cvss_variance: float,
    max_other_score: float | None = None,
):
    """
    Drift score = |GH − NVD| (i.e. cvss_variance) for conflict/gap CVEs.
    For rejected CVEs: the GitHub score itself (NVD has no score to compare).
    Tombstones (rejected, no other source): 0.0.
    """
    if drift_type == "rejected":
        return round(max_other_score, 2) if max_other_score is not None else 0.0
    return round(cvss_variance, 2)


def process_file(path: Path):
    record = json.loads(path.read_text())
    sources = record.get("sources", {})

    by_version = collect_cvss_scores(sources)
    cvss_variance = compute_cvss_variance(by_version)
    metadata_conflict = compute_metadata_conflict(sources)
    drift_type = classify_drift_type(record, cvss_variance, by_version)
    other_source_count = source_conflict_count(sources)

    # Max CVSS score from non-NVD sources (used for rejected CVE scoring)
    max_other_score = None
    for sname, s in sources.items():
        if sname in ("nvd", "cisa_kev", "epss"):
            continue
        score = s.get("cvss_score")
        if score is not None:
            max_other_score = max(max_other_score or 0, score)

    drift_score = compute_drift_score(
        drift_type, cvss_variance, max_other_score
    )

    record["drift_score"] = drift_score
    record["drift_type"] = drift_type
    record["cvss_variance"] = cvss_variance
    record["source_count"] = other_source_count

    path.write_text(json.dumps(record, indent=2))
    return drift_score, drift_type


def main():
    cve_files = sorted(DATA_DIR.glob("**/CVE-*.json"))
    if not cve_files:
        print("No CVE files found. Run ingestion scripts first.")
        return

    counts = {"conflict": 0, "gap": 0, "rejected": 0}
    total = 0

    print(f"Computing drift scores for {len(cve_files)} CVEs...")
    for path in cve_files:
        try:
            _, drift_type = process_file(path)
            counts[drift_type] = counts.get(drift_type, 0) + 1
            total += 1
        except Exception as e:
            print(f"  Error processing {path.name}: {e}")

        if total % 500 == 0:
            print(f"  {total} CVEs processed...")

    print(f"Done. {total} CVEs scored.")
    print(f"  conflict: {counts['conflict']}  gap: {counts['gap']}  rejected: {counts['rejected']}")


if __name__ == "__main__":
    main()
