#!/usr/bin/env python3
"""Ingest advisories from the GitHub Advisory Database and merge into CVE JSON files."""

import json
import os
import time
from datetime import datetime, timezone
from pathlib import Path

import requests
from tenacity import retry, stop_after_attempt, wait_exponential, retry_if_exception_type

GITHUB_API_BASE = "https://api.github.com/advisories"
DATA_DIR = Path(__file__).parent.parent / "docs" / "data"
INDEXES_DIR = DATA_DIR / "indexes"
GHSA_MAP_PATH = INDEXES_DIR / "ghsa-cve-map.json"
GITHUB_TOKEN = os.environ.get("GITHUB_TOKEN")


def build_headers():
    headers = {
        "User-Agent": "vuln-anarchy/1.0",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    if GITHUB_TOKEN:
        headers["Authorization"] = f"Bearer {GITHUB_TOKEN}"
    return headers


@retry(
    retry=retry_if_exception_type(requests.HTTPError),
    wait=wait_exponential(multiplier=1, min=4, max=60),
    stop=stop_after_attempt(5),
)
def fetch_page(url, params):
    resp = requests.get(url, headers=build_headers(), params=params, timeout=30)
    if resp.status_code == 429:
        raise requests.HTTPError("Rate limited", response=resp)
    resp.raise_for_status()
    return resp


def fetch_advisories():
    """Yield all GitHub Security Advisories, paginated."""
    params = {"per_page": 100, "page": 1, "type": "reviewed"}
    url = GITHUB_API_BASE

    while url:
        resp = fetch_page(url, params)
        advisories = resp.json()
        if not advisories:
            break

        for advisory in advisories:
            yield advisory

        # Follow Link header for next page
        link = resp.headers.get("Link", "")
        next_url = None
        for part in link.split(","):
            if 'rel="next"' in part:
                next_url = part.split(";")[0].strip().strip("<>")
                break

        url = next_url
        params = {}  # URL already contains pagination params when following Link header
        time.sleep(0.5)


def extract_cvss(advisory: dict):
    """Extract CVSS score and version from a GitHub advisory."""
    severity = advisory.get("severity")
    cvss = advisory.get("cvss", {}) or {}
    vector = cvss.get("vector_string")
    score = cvss.get("score")

    if not vector:
        return {"cvss_score": score, "cvss_version": None, "cvss_vector": None}

    if vector.startswith("CVSS:4.0"):
        version = "4.0"
    elif vector.startswith("CVSS:3.1"):
        version = "3.1"
    elif vector.startswith("CVSS:3.0"):
        version = "3.0"
    elif vector.startswith("CVSS:2.0") or vector.startswith("AV:"):
        version = "2.0"
    else:
        version = None

    return {"cvss_score": score, "cvss_version": version, "cvss_vector": vector}


def extract_affected(vulnerabilities: list):
    """Extract affected package/version ranges from GitHub advisory vulnerabilities."""
    affected = []
    for vuln in vulnerabilities or []:
        pkg = vuln.get("package", {}) or {}
        affected.append({
            "package": pkg.get("name"),
            "ecosystem": pkg.get("ecosystem"),
            "vulnerable_version_range": vuln.get("vulnerable_version_range"),
            "patched_versions": vuln.get("patched_versions"),
            "first_patched_version": vuln.get("first_patched_version"),
        })
    return affected


def parse_advisory(advisory: dict):
    ghsa_id = advisory["ghsa_id"]
    cve_ids = advisory.get("cve_id")
    # GitHub returns cve_id as a single string or null
    if isinstance(cve_ids, str):
        cve_ids = [cve_ids]
    elif not cve_ids:
        cve_ids = []

    cvss = extract_cvss(advisory)
    affected = extract_affected(advisory.get("vulnerabilities", []))

    return {
        "ghsa_id": ghsa_id,
        "cve_ids": cve_ids,
        "github_block": {
            "ghsa_id": ghsa_id,
            **cvss,
            "affected": affected,
            "fetched_at": datetime.now(timezone.utc).isoformat(),
        },
    }


def load_ghsa_map():
    if GHSA_MAP_PATH.exists():
        return json.loads(GHSA_MAP_PATH.read_text())
    return {}


def save_ghsa_map(mapping: dict):
    INDEXES_DIR.mkdir(parents=True, exist_ok=True)
    GHSA_MAP_PATH.write_text(json.dumps(mapping, indent=2))


def merge_into_cve(cve_id: str, github_block: dict):
    year = cve_id.split("-")[1]
    path = DATA_DIR / year / f"{cve_id}.json"

    if path.exists():
        record = json.loads(path.read_text())
    else:
        record = {"cve_id": cve_id, "sources": {}}

    record.setdefault("sources", {})["github"] = github_block
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(record, indent=2))


def main():
    ghsa_map = load_ghsa_map()
    count = 0
    merged = 0

    print("Fetching GitHub Security Advisories...")
    for advisory in fetch_advisories():
        parsed = parse_advisory(advisory)
        ghsa_id = parsed["ghsa_id"]

        # Update GHSA↔CVE mapping
        for cve_id in parsed["cve_ids"]:
            ghsa_map[ghsa_id] = cve_id
            merge_into_cve(cve_id, parsed["github_block"])
            merged += 1

        count += 1
        if count % 100 == 0:
            print(f"  {count} advisories processed, {merged} merged into CVE files...")

    save_ghsa_map(ghsa_map)
    print(f"Done. {count} advisories processed, {merged} CVEs updated.")
    print(f"GHSA↔CVE map written to {GHSA_MAP_PATH} ({len(ghsa_map)} entries)")


if __name__ == "__main__":
    main()
