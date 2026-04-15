# Copilot Instructions — vuln-anarchy (Vulnerability Anarchy / The Consensus Engine)

## Project Overview

A data-as-code project tracking **"Data Drift"** — the delta between how NVD and the GitHub Advisory Database score the same CVE. Launched at VulnCon 2026.

**Core constraint: No backend, no database.** The repository *is* the database (flat JSON files). All processing runs in GitHub Actions; the UI is 100% client-side on GitHub Pages.

## Architecture

```
vuln-anarchy/
├── .github/
│   ├── copilot-instructions.md
│   └── workflows/
│       └── ingest.yml          # Daily ingestion pipeline
├── docs/                       # GitHub Pages root
│   ├── index.html              # Drift Leaderboard
│   ├── anarchy-map.html        # Scatter plot + Conflicts by Year chart
│   └── data/                   # ⚠️ data lives inside docs/ so GitHub Pages serves it
│       ├── {year}/CVE-{ID}.json
│       ├── conflicts.csv
│       └── indexes/
│           ├── leaderboard.json
│           ├── anarchy-map.json
│           └── stats.json
└── scripts/
    ├── requirements.txt
    ├── ingest_nvd.py
    ├── ingest_github.py
    ├── compute_drift.py
    └── build_indexes.py
```

The Drift Leaderboard and all aggregate indexes **must be pre-computed by CI** and written as static JSON. Never compute rankings client-side from raw CVE files — there are 240k+ CVEs in the NVD corpus.

### Data Sources

| Source | Primary Contribution | Notes |
|---|---|---|
| NVD API 2.0 | CVSS scores, CWE, CPE strings, publish date | Increasingly republishes CNA data rather than scoring independently |
| GitHub Advisory Database | CVSS v3.1 scores, affected versions | Uses GHSA-* IDs; not all GHSAs have a CVE alias |

### Drift Score (Δ) Calculation

The Drift Score is simply `|GitHub CVSS − NVD CVSS|`. No metadata multiplier.

**Rules:**
- Both NVD and GitHub must have a CVSS score for a CVE to be `conflict`. One source missing → `gap`.
- Scores must be the **same CVSS version** — v3.1 vs v4.0 comparison is invalid → `gap`.
- `drift_type` is one of: `"conflict"`, `"gap"`, `"rejected"`.

**Critical CVSS rules:**
- Always record the CVSS *version* (v2, v3.0, v3.1, v4.0) alongside every score — do not compare scores across versions
- NVD is mid-transition from v3.1 → v4.0; GitHub Advisory DB is mostly v3.1; a numerical delta between different versions is meaningless
- Legacy CVEs (pre-~2015) may only have v2 scores; treat cross-version comparisons as a metadata gap, not a conflict

**Score absence vs. score conflict:**
- Many CVEs are stuck in NVD "Awaiting Analysis" or "Undergoing Analysis" with no CVSS at all — this is a **data gap**, not drift
- `drift_type` distinguishes: `"conflict"` (sources disagree on value) vs. `"gap"` (one or more sources have no data) vs. `"rejected"` (CVE existence disputed)

**REJECTED CVEs** are the most extreme drift case. A CVE where NVD has marked it REJECTED after the CNA already scored and published it is "anarchy" in its purest form. These surface at the top of the leaderboard.

### CNA Attribution

NVD mostly republishes CNA-provided scores now. Always record the **assigning CNA** (e.g., `"cna": "microsoft"`) alongside any NVD-sourced score.

### Frontend Views

- **Anarchy Map** (`anarchy-map.html`) — scatter plot, X=NVD CVSS, Y=GitHub CVSS. Dots above the diagonal = GitHub scores higher; below = NVD scores higher; red = Δ ≥ 4.0. Also includes a stacked bar chart of conflicts by publication year.
- **Drift Leaderboard** (`index.html`) — top 100 non-rejected CVEs by drift score, plus up to 15 rejected CVEs. Pre-computed at CI time; Hide Rejected toggle on by default. Sortable; CSV export.

## Data Schema

CVE records live at `/docs/data/{year}/CVE-{ID}.json`. Every field sourced from an external API must include `fetched_at` and `cvss_version` where applicable. Example shape:

```json
{
  "cve_id": "CVE-2024-XXXXX",
  "drift_score": 6.9,
  "drift_type": "conflict",
  "cvss_variance": 6.9,
  "assigning_cna": "microsoft",
  "source_count": 2,
  "sources": {
    "nvd": {
      "cvss_score": 9.8,
      "cvss_version": "3.1",
      "cvss_vector": "CVSS:3.1/...",
      "cwe": ["CWE-89"],
      "status": "Analyzed",
      "published": "2024-03-15T10:00:00",
      "last_modified": "2024-04-01T00:00:00",
      "days_to_analysis": 5,
      "fetched_at": "2026-04-15T00:00:00Z"
    },
    "github": {
      "ghsa_id": "GHSA-xxxx-xxxx-xxxx",
      "cvss_score": 2.9,
      "cvss_version": "3.1",
      "fetched_at": "2026-04-15T00:00:00Z"
    }
  }
}
```

## Operational Constraints

**NVD API rate limits:**
- Without API key: 5 requests / 30 seconds
- With API key: 50 requests / 30 seconds
- Ingestion scripts use tenacity retry with exponential backoff. The NVD API key is stored as a GitHub Actions secret (`NVD_API_KEY`).

**GHSA↔CVE ID mapping:**
- Not all GHSA IDs have a CVE alias. The ingest script skips GHSAs with no CVE alias.

**GitHub Pages scale:**
- 240k+ JSON files is within the 1GB soft limit but CI must pre-compute all aggregate/index files.

## Development Conventions

- **Python** for GitHub Actions ingestion/analysis scripts
- **Tailwind CSS + Alpine.js** for the frontend (no build step — CDN)
- **Flat JSON** — never introduce SQLite, DuckDB, or any other DB layer; the file tree is the store
- **GitHub Actions** handles all scheduled pulls and drift computations; no server-side compute outside CI

## Current Status

**Live** — launched at VulnCon 2026. Tracking NVD vs. GitHub Advisory Database CVSS drift across 240k+ CVEs. ~5,000 score conflicts identified.
