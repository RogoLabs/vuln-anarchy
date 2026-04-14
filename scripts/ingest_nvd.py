#!/usr/bin/env python3
"""Ingest CVEs from NVD API 2.0 for the last 2 years."""

import json
import os
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

import requests
from tenacity import retry, stop_after_attempt, wait_exponential, retry_if_exception_type

NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
DATA_DIR = Path(__file__).parent.parent / "docs" / "data"
API_KEY = os.environ.get("NVD_API_KEY")

# 50 req/30s with key → 0.6s between requests (with small buffer)
REQUEST_DELAY = 0.7 if API_KEY else 6.5


def build_headers():
    headers = {"User-Agent": "vuln-anarchy/1.0"}
    if API_KEY:
        headers["apiKey"] = API_KEY
    return headers


@retry(
    retry=retry_if_exception_type(requests.HTTPError),
    wait=wait_exponential(multiplier=1, min=4, max=60),
    stop=stop_after_attempt(5),
)
def fetch_page(params):
    resp = requests.get(NVD_API_BASE, headers=build_headers(), params=params, timeout=30)
    if resp.status_code == 429:
        raise requests.HTTPError("Rate limited", response=resp)
    resp.raise_for_status()
    return resp.json()


def fetch_cves(start_date: datetime, end_date: datetime):
    """Yield all CVE items in a date range, handling NVD pagination."""
    params = {
        "pubStartDate": start_date.strftime("%Y-%m-%dT%H:%M:%S.000"),
        "pubEndDate": end_date.strftime("%Y-%m-%dT%H:%M:%S.000"),
        "resultsPerPage": 2000,
        "startIndex": 0,
    }
    total = None
    fetched = 0

    while total is None or fetched < total:
        data = fetch_page(params)
        total = data["totalResults"]
        vulnerabilities = data.get("vulnerabilities", [])

        for item in vulnerabilities:
            yield item["cve"]

        fetched += len(vulnerabilities)
        params["startIndex"] = fetched

        if fetched < total:
            time.sleep(REQUEST_DELAY)


def fetch_modified_since(since: datetime):
    """Yield CVEs modified since a given datetime (for daily incremental updates)."""
    params = {
        "lastModStartDate": since.strftime("%Y-%m-%dT%H:%M:%S.000"),
        "lastModEndDate": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000"),
        "resultsPerPage": 2000,
        "startIndex": 0,
    }
    total = None
    fetched = 0

    while total is None or fetched < total:
        data = fetch_page(params)
        total = data["totalResults"]
        vulnerabilities = data.get("vulnerabilities", [])

        for item in vulnerabilities:
            yield item["cve"]

        fetched += len(vulnerabilities)
        params["startIndex"] = fetched

        if fetched < total:
            time.sleep(REQUEST_DELAY)


def extract_cvss(metrics: dict):
    """Return the best available CVSS score and metadata, preferring highest version."""
    for key, version in [
        ("cvssMetricV40", "4.0"),
        ("cvssMetricV31", "3.1"),
        ("cvssMetricV30", "3.0"),
        ("cvssMetricV2", "2.0"),
    ]:
        entries = metrics.get(key, [])
        if entries:
            # Prefer the primary source entry
            entry = next((e for e in entries if e.get("type") == "Primary"), entries[0])
            data = entry.get("cvssData", {})
            return {
                "cvss_score": data.get("baseScore"),
                "cvss_version": version,
                "cvss_vector": data.get("vectorString"),
            }
    return {"cvss_score": None, "cvss_version": None, "cvss_vector": None}


def extract_cwe(weaknesses: list):
    cwes = []
    for w in weaknesses:
        for desc in w.get("description", []):
            value = desc.get("value", "")
            if value and value not in cwes:
                cwes.append(value)
    return cwes


def extract_cna(source_identifier: str, cve_tags: list):
    """Derive the assigning CNA from source identifier or CVE tags."""
    if cve_tags:
        for tag in cve_tags:
            if tag.get("sourceIdentifier") and tag.get("tags"):
                return tag["sourceIdentifier"].split("@")[-1].rstrip(".")
    if source_identifier:
        # e.g. "secure@microsoft.com" → "microsoft"
        domain = source_identifier.split("@")[-1]
        parts = domain.rstrip(".").split(".")
        return parts[-2] if len(parts) >= 2 else domain
    return None


def days_to_analysis(published: str, last_modified: str, status: str):
    """Days between publish date and NVD analysis completion."""
    if status not in ("Analyzed", "Modified"):
        return None
    try:
        pub = datetime.fromisoformat(published.replace("Z", "+00:00"))
        mod = datetime.fromisoformat(last_modified.replace("Z", "+00:00"))
        return (mod - pub).days
    except (ValueError, TypeError):
        return None


def parse_cve(cve: dict) -> dict:
    cve_id = cve["id"]
    published = cve.get("published", "")
    last_modified = cve.get("lastModified", "")
    status = cve.get("vulnStatus", "")

    cvss = extract_cvss(cve.get("metrics", {}))
    cwe = extract_cwe(cve.get("weaknesses", []))
    cna = extract_cna(cve.get("sourceIdentifier", ""), cve.get("cveTags", []))
    dta = days_to_analysis(published, last_modified, status)

    return {
        "cve_id": cve_id,
        "assigning_cna": cna,
        "sources": {
            "nvd": {
                **cvss,
                "cwe": cwe,
                "status": status,
                "published": published,
                "last_modified": last_modified,
                "days_to_analysis": dta,
                "fetched_at": datetime.now(timezone.utc).isoformat(),
            }
        },
    }


def write_cve(record: dict):
    cve_id = record["cve_id"]
    year = cve_id.split("-")[1]
    year_dir = DATA_DIR / year
    year_dir.mkdir(parents=True, exist_ok=True)
    path = year_dir / f"{cve_id}.json"

    if path.exists():
        existing = json.loads(path.read_text())
        existing["assigning_cna"] = record["assigning_cna"]
        existing.setdefault("sources", {})["nvd"] = record["sources"]["nvd"]
        path.write_text(json.dumps(existing, indent=2))
    else:
        path.write_text(json.dumps(record, indent=2))


def main():
    now = datetime.now(timezone.utc)
    two_years_ago = now - timedelta(days=730)

    # Check if we have existing data to determine if this is initial load or incremental
    existing_files = list(DATA_DIR.glob("**/CVE-*.json"))
    if existing_files:
        # Incremental: fetch only CVEs modified in the last 25 hours
        since = now - timedelta(hours=25)
        print(f"Incremental update: fetching CVEs modified since {since.isoformat()}")
        cves = fetch_modified_since(since)
    else:
        # Initial backfill: last 2 years
        print(f"Initial backfill: fetching CVEs published since {two_years_ago.date()}")
        cves = fetch_cves(two_years_ago, now)

    count = 0
    for cve in cves:
        write_cve(parse_cve(cve))
        count += 1
        if count % 100 == 0:
            print(f"  {count} CVEs processed...")
        time.sleep(REQUEST_DELAY)

    print(f"Done. {count} CVEs written to {DATA_DIR}")


if __name__ == "__main__":
    main()
