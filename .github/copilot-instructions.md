# Copilot Instructions — vuln-anarchy (Vulnerability Anarchy / The Consensus Engine)

## Project Overview

A data-as-code project tracking **"Data Drift"** — the delta between how different vulnerability authorities (NVD, GitHub Advisory Database, OSV.dev, CISA KEV/EPSS) score and describe the same CVE. Targeting launch at DEF CON 34 (August 2026).

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
│   ├── cve.html                # CVE Nutrition Label detail page
│   └── data/                   # ⚠️ data lives inside docs/ so GitHub Pages serves it
│       ├── {year}/CVE-{ID}.json
│       └── indexes/
│           ├── leaderboard.json
│           ├── anarchy-map.json
│           └── ghsa-cve-map.json
└── scripts/
    ├── requirements.txt
    ├── ingest_nvd.py
    ├── ingest_github.py
    ├── compute_drift.py
    └── build_indexes.py
```

The Drift Leaderboard and any aggregate indexes **must be pre-computed by CI** and written as static JSON. Never compute rankings client-side from raw CVE files — there are 240k+ CVEs in the NVD corpus.

### Data Sources

| Source | Primary Contribution | Notes |
|---|---|---|
| NVD API 2.0 | CVSS scores, CWE, CPE strings | Increasingly republishes CNA data rather than scoring independently |
| GitHub Advisory Database | CVSS v3.1 scores, affected versions | Uses GHSA-* IDs; not all GHSAs have a CVE alias |
| OSV.dev | Affected package/version ranges | Often has no CVSS; strongest for ecosystem metadata |
| CISA KEV | "Actively exploited" boolean flag | **Not a numeric score** — belongs in metadata/velocity, not CVSS variance |
| EPSS (First.org) | Probability of exploitation (0–1) | Updates daily; store with `fetched_at` timestamp, treat as time-series |

### Drift Score (Δ) Calculation

Three components combined per CVE:
1. **CVSS Variance** — numerical delta between highest and lowest reported score across sources
2. **Metadata Conflict** — inconsistencies in CWE assignments or CPE/affected-version strings
3. **Velocity** — which source first provided actionable intelligence (fix or PoC)

**Critical CVSS rules:**
- Always record the CVSS *version* (v2, v3.0, v3.1, v4.0) alongside every score — do not compare scores across versions
- NVD is mid-transition from v3.1 → v4.0; GitHub Advisory DB is mostly v3.1; a numerical delta between different versions is meaningless
- Legacy CVEs (pre-~2015) may only have v2 scores; treat cross-version comparisons as a metadata gap, not a conflict
- NVD Temporal Score modifiers exist but are almost never used by NVD; if a CNA uses them, the apparent score difference is intentional

**Score absence vs. score conflict:**
- Many CVEs are stuck in NVD "Awaiting Analysis" or "Undergoing Analysis" with no CVSS at all — this is a **data gap**, not drift
- `drift_type` should distinguish: `"conflict"` (sources disagree on value) vs. `"gap"` (one or more sources have no data) vs. `"rejected"` (CVE existence disputed)

**REJECTED/DISPUTED CVEs** are the most extreme drift case and should surface at the top of the leaderboard. A CVE where NVD has marked it REJECTED after CNAs already scored and published it is "anarchy" in its purest form.

### CNA Attribution

NVD mostly republishes CNA-provided scores now. Always record the **assigning CNA** (e.g., `"cna": "microsoft"`) alongside any NVD-sourced score. "NVD disagrees with the CNA" is a fundamentally different signal than "NVD created an independent score."

### Frontend Views

- **Anarchy Map** — scatter plot / heat-map. X axis = CVSS Variance; Y axis = EPSS percentile; color intensity = number of sources with conflicting data. The high-EPSS + high-variance quadrant is the "money" view: actively exploited CVEs that the industry can't agree how to score.
- **Drift Leaderboard** — top 50 most disputed CVEs (pre-computed JSON, not client-side ranked). REJECTED/DISPUTED CVEs sort to the top.
- **CVE Nutrition Labels** — traffic-light (🟢🟡🔴) per dimension, not a single letter grade. See rubric below.

## Data Schema

CVE records live at `/data/{year}/CVE-{ID}.json`. Every field sourced from an external API must include provenance: `source`, `fetched_at`, and `cvss_version` where applicable. Example shape:

```json
{
  "cve_id": "CVE-2024-XXXXX",
  "drift_score": 4.2,
  "drift_type": "conflict",
  "assigning_cna": "microsoft",
  "sources": {
    "nvd": {
      "cvss_score": 8.8,
      "cvss_version": "3.1",
      "cvss_vector": "CVSS:3.1/...",
      "cwe": ["CWE-89"],
      "status": "Analyzed",
      "fetched_at": "2026-01-15T00:00:00Z"
    },
    "github": {
      "ghsa_id": "GHSA-xxxx-xxxx-xxxx",
      "cvss_score": 6.5,
      "cvss_version": "3.1",
      "fetched_at": "2026-01-15T00:00:00Z"
    },
    "osv": { ... },
    "cisa_kev": {
      "in_kev": true,
      "date_added": "2024-03-01",
      "fetched_at": "2026-01-15T00:00:00Z"
    },
    "epss": {
      "score": 0.94,
      "percentile": 0.99,
      "score_30d_ago": 0.12,
      "score_peak": 0.96,
      "fetched_at": "2026-01-15T00:00:00Z"
    }
  }
}
```

## CVE Nutrition Label Rubric

Each CVE gets a traffic-light score (🟢 green / 🟡 yellow / 🔴 red) per dimension. Display all dimensions — never collapse to a single grade. The point is to show *why* a CVE's data quality is poor, not just that it is.

| Dimension | 🟢 Green | 🟡 Yellow | 🔴 Red |
|---|---|---|---|
| **Coverage** | 4/4 sources have data | 2–3/4 sources | 0–1/4 sources |
| **Agreement** | CVSS variance ≤ 0.5 | variance 0.5–3.0 | variance > 3.0 or `drift_type: rejected` |
| **Timeliness** | NVD analyzed within 7 days of publish | 8–90 days | >90 days or still "Awaiting Analysis" |
| **Exploitation Signal** | In KEV and/or EPSS > 90th percentile | EPSS 50th–90th | EPSS < 50th, not in KEV |
| **Remediation Clarity** | Exact semver/version ranges across sources, patch linked | Partial version info | CPE strings only or no version info |
| **CWE Quality** | Specific CWE (e.g., CWE-89, CWE-79) | Mid-level CWE (e.g., CWE-693) | CWE-noinfo, CWE-other, or missing |

**Color logic for Exploitation Signal is intentionally inverted from the others:** 🔴 means high exploitation risk (act now), not "bad data." Make this explicit in the UI to avoid misreading.

**Timeliness** is the most politically pointed dimension — it directly quantifies NVD backlog impact on defenders. Preserve the raw `days_to_analysis` value in the JSON so it can be displayed verbatim.

## Operational Constraints**NVD API rate limits:**
- Without API key: 5 requests / 30 seconds
- With API key: 50 requests / 30 seconds
- Ingestion scripts must implement explicit rate-limiting, backoff, and retry logic. The NVD API key should be stored as a GitHub Actions secret.

**GHSA↔CVE ID mapping:**
- Not all GHSA IDs have a CVE alias. Build and maintain an explicit mapping file; do not assume a 1:1 relationship.

**EPSS is a daily time-series — store smart, not everything:**
- Do NOT store daily snapshots per CVE — 240k CVEs × 365 days blows past GitHub Pages limits.
- Per-CVE file stores: `score` (current), `percentile`, `score_30d_ago`, `score_peak`, `fetched_at`. This covers the three interesting stories: sudden jump (new PoC), high CVSS / low EPSS (overhyped), low CVSS / high EPSS + KEV (secretly dangerous).
- For richer history, write a **weekly index** at `/data/epss/snapshots/YYYY-Www.json` containing scores only for CVEs above the 50th EPSS percentile. Per-CVE files stay lean; time-series is browsable without loading everything.

**GitHub Pages scale:**
- 240k+ JSON files is within the 1GB soft limit but CI must pre-compute all aggregate/index files. Individual CVE detail pages fetch a single `/data/year/CVE-ID.json` file; leaderboards and the Anarchy Map load pre-built index files.

## Development Conventions

- **Python** for GitHub Actions ingestion/analysis scripts
- **Tailwind CSS + Alpine.js** for the frontend (no build step — CDN or pre-compiled)
- **Flat JSON** — never introduce SQLite, DuckDB, or any other DB layer; the file tree is the store
- **GitHub Actions** handles all scheduled pulls and drift computations; no server-side compute outside CI

## Current Status

Pre-code. In concept/design phase. Phase 1 (Spring 2026) = Basic ingestion and CVSS comparison (NVD vs. GitHub).
