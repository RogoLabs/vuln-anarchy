#!/usr/bin/env python3
"""Ingest CVEs from NVD API 2.0 for the last 2 years."""

import json
import os
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

import requests
from tenacity import retry, stop_after_attempt, wait_exponential, retry_if_exception

NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
DATA_DIR = Path(__file__).parent.parent / "docs" / "data"
API_KEY = os.environ.get("NVD_API_KEY")

# 50 req/30s with key → 0.7s between requests (with small buffer)
REQUEST_DELAY = 0.7 if API_KEY else 6.5

# NVD API enforces a maximum date range of 120 days per request
NVD_MAX_RANGE_DAYS = 120


def build_headers():
    headers = {"User-Agent": "vuln-anarchy/1.0"}
    if API_KEY:
        headers["apiKey"] = API_KEY
    return headers


def _is_transient(exc):
    """Retry on 429 and 5xx only — not on 404 or other client errors."""
    if isinstance(exc, requests.HTTPError):
        status = exc.response.status_code if exc.response is not None else 0
        return status == 429 or status >= 500
    return False


@retry(
    retry=retry_if_exception(_is_transient),
    wait=wait_exponential(multiplier=1, min=4, max=60),
    stop=stop_after_attempt(5),
)
def fetch_page(params):
    resp = requests.get(NVD_API_BASE, headers=build_headers(), params=params, timeout=30)
    resp.raise_for_status()
    return resp.json()


def _date_windows(start: datetime, end: datetime):
    """Split a date range into ≤120-day windows (NVD API enforced limit)."""
    cursor = start
    while cursor < end:
        window_end = min(cursor + timedelta(days=NVD_MAX_RANGE_DAYS), end)
        yield cursor, window_end
        cursor = window_end


def fetch_cves(start_date: datetime, end_date: datetime):
    """Yield all CVE items in a date range, chunking into 120-day windows."""
    for window_start, window_end in _date_windows(start_date, end_date):
        print(f"  Fetching window {window_start.date()} → {window_end.date()}")
        params = {
            "pubStartDate": window_start.strftime("%Y-%m-%dT%H:%M:%S.000"),
            "pubEndDate": window_end.strftime("%Y-%m-%dT%H:%M:%S.000"),
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


def days_to_analysis(published: str, first_analyzed_at: str | None) -> int | None:
    """Days between CVE publish date and NVD first completing analysis.

    Uses first_analyzed_at rather than lastModified — lastModified is updated
    every time NVD touches a record (CNA corrections, rescores, etc.), which
    would produce an inflated backlog number.
    """
    if not first_analyzed_at:
        return None
    try:
        pub = datetime.fromisoformat(published.replace("Z", "+00:00"))
        analyzed = datetime.fromisoformat(first_analyzed_at.replace("Z", "+00:00"))
        return max(0, (analyzed - pub).days)
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

    # first_analyzed_at: the date NVD first completed analysis.
    # For newly-analyzed CVEs we use last_modified as the best available proxy.
    # write_cve() will preserve this value on subsequent updates so it is never
    # overwritten by a later lastModified date.
    first_analyzed_at = last_modified if status in ("Analyzed", "Modified") else None

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
                "first_analyzed_at": first_analyzed_at,
                "days_to_analysis": days_to_analysis(published, first_analyzed_at),
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

    new_nvd = record["sources"]["nvd"]

    if path.exists():
        existing = json.loads(path.read_text())
        existing_nvd = existing.get("sources", {}).get("nvd", {})

        # Preserve first_analyzed_at — only set once on the first transition to
        # Analyzed/Modified; never overwritten by a later lastModified date.
        if existing_nvd.get("first_analyzed_at"):
            new_nvd["first_analyzed_at"] = existing_nvd["first_analyzed_at"]
        # If we now have an analysis date for the first time, capture it
        # (new_nvd["first_analyzed_at"] is already set from parse_cve)

        # Recompute days_to_analysis against the now-stable first_analyzed_at
        new_nvd["days_to_analysis"] = days_to_analysis(
            new_nvd.get("published", ""), new_nvd.get("first_analyzed_at")
        )

        existing["assigning_cna"] = record["assigning_cna"]
        existing.setdefault("sources", {})["nvd"] = new_nvd
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
        if count % 500 == 0:
            print(f"  {count} CVEs processed...")

    print(f"Done. {count} CVEs written to {DATA_DIR}")


if __name__ == "__main__":
    main()
