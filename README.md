# vuln-anarchy — Vulnerability Anarchy / The Consensus Engine

**Lab:** [RogoLabs](https://rogolabs.net) · **Status:** Concept / Summer 2026 Circuit · **Launch:** DEF CON 34 (August 2026) · **Deployment:** 100% Static (GitHub Actions + GitHub Pages)

> *The vulnerability management ecosystem is fracturing. With the rise of independent CNAs and the shifting role of the NVD, the "truth" of a vulnerability has become subjective.*

**Vulnerability Anarchy** is a data-as-code project that tracks **"Data Drift"** — the measurable delta between how different authorities (NVD, GitHub Advisory Database, OSV.dev, CISA KEV/EPSS) score and describe the same CVE.

## Philosophy

- **No Database:** The repository *is* the database. All data is stored as flat JSON files under `/data/`.
- **No Backend:** All processing runs in GitHub Actions. The UI is 100% client-side on GitHub Pages.
- **Transparency:** Every Drift Score is traceable to a specific commit hash and raw data source.

## Architecture

```
GitHub Actions (Python)          /data/year/CVE-ID.json          GitHub Pages (Static UI)
┌──────────────────────────┐    ┌────────────────────────┐    ┌──────────────────────────┐
│ Ingestion scripts pull   │───▶│ One JSON per CVE with  │───▶│ Tailwind + Alpine.js     │
│ from NVD API 2.0,        │    │ all source data +      │    │ fetches JSON directly,   │
│ GitHub Advisory DB,      │    │ computed Drift Score   │    │ no API calls to backend  │
│ OSV.dev, CISA KEV/EPSS   │    └────────────────────────┘    └──────────────────────────┘
└──────────────────────────┘
```

All aggregate indexes (leaderboard, Anarchy Map data) are **pre-computed by CI** — never ranked client-side.

## The Drift Score (Δ)

Three components combined per CVE:

1. **CVSS Variance** — numerical delta between the highest and lowest reported scores across sources (same CVSS version only — v3.1 vs. v4.0 comparisons are invalid)
2. **Metadata Conflict** — inconsistencies in CWE assignments or affected-version/CPE strings
3. **Velocity** — which source first provided actionable intelligence (fix or PoC)

`drift_type` is always one of:
- `"conflict"` — sources disagree on a value
- `"gap"` — one or more sources have no data (NVD "Awaiting Analysis", no CVSS from OSV, etc.)
- `"rejected"` — CVE existence is disputed; sorts to the top of the leaderboard

## Data Sources

| Source | Primary Contribution | Notes |
|---|---|---|
| NVD API 2.0 | CVSS scores, CWE, CPE strings | Largely republishes CNA-provided scores; record the assigning CNA |
| GitHub Advisory Database | CVSS v3.1 scores, affected versions | GHSA-* IDs; not all GHSAs have a CVE alias |
| OSV.dev | Affected package/version ranges | Often has no CVSS; strongest for ecosystem/version metadata |
| CISA KEV | "Actively exploited" boolean | Not a numeric score — binary flag only |
| EPSS (First.org) | Probability of exploitation (0–1) | Daily time-series; stored as current + 30d-ago + peak per CVE |

## Frontend Views

### 🗺️ Anarchy Map
Scatter plot: **X = CVSS Variance**, **Y = EPSS percentile**, **color intensity = source conflict count**. The high-variance + high-EPSS quadrant is the key view — actively exploited CVEs that the industry can't agree how to score.

### 🏆 Drift Leaderboard
Top 50 most disputed CVEs, pre-computed at CI time. REJECTED/DISPUTED CVEs surface first.

### 🥦 CVE Nutrition Labels
Traffic-light (🟢🟡🔴) per dimension — never a single letter grade. Each dimension tells a different story about *why* a CVE's data quality is poor.

| Dimension | 🟢 Green | 🟡 Yellow | 🔴 Red |
|---|---|---|---|
| **Coverage** | 4/4 sources have data | 2–3/4 | 0–1/4 |
| **Agreement** | CVSS variance ≤ 0.5 | 0.5–3.0 | > 3.0 or `rejected` |
| **Timeliness** | NVD analyzed ≤ 7 days after publish | 8–90 days | > 90 days or "Awaiting Analysis" |
| **Exploitation Signal** ⚠️ | In KEV or EPSS > 90th percentile | EPSS 50th–90th | EPSS < 50th, not in KEV |
| **Remediation Clarity** | Exact semver ranges, patch linked | Partial version info | CPE strings only or missing |
| **CWE Quality** | Specific CWE (e.g., CWE-89) | Mid-level CWE (e.g., CWE-693) | CWE-noinfo, CWE-other, or missing |

> ⚠️ **Exploitation Signal color logic is inverted.** 🔴 = high exploitation risk (act now), not bad data quality.

## Roadmap

- [ ] **Phase 1 (Spring 2026):** Basic ingestion and CVSS comparison (NVD vs. GitHub Advisory)
- [ ] **Phase 2 (Summer 2026):** Full Drift Engine, Nutrition Label generation, Anarchy Map
- [ ] **Phase 3 (August 2026):** Live launch at DEF CON 34

## Project Origin

An evolution of the **"CVE Decaf"** research, shifting focus from "Bad Data" to "Conflicting Data" in the global vulnerability ecosystem.

---
*Built by [Jerry Gamblin](https://github.com/jgamblin) at [RogoLabs](https://rogolabs.net).*