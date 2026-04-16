# The Consensus Engine

### The Vulnerability Data Integrity Gap

> **When two authoritative sources disagree on a CVSS score by 6.9 points, which one do you trust to set your SLA?**

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python](https://img.shields.io/badge/Python-3.12-blue.svg)](https://www.python.org/)
[![Data Updated](https://img.shields.io/badge/Data-Daily-brightgreen.svg)](https://rogolabs.github.io/consensus-engine/)
[![Built by RogoLabs](https://img.shields.io/badge/Built%20by-RogoLabs-orange.svg)](https://rogolabs.net)

**The Consensus Engine** is an open-source data project by [RogoLabs](https://rogolabs.net) that continuously measures **scoring divergence** between the [National Vulnerability Database (NVD)](https://nvd.nist.gov/) and the [GitHub Advisory Database](https://github.com/advisories). It surfaces every CVE where these two authoritative sources reach meaningfully different conclusions — and makes that data freely available for research, tooling, and advocacy.

**[→ Score Conflicts](https://rogolabs.github.io/consensus-engine/)** · **[→ Conflict Map](https://rogolabs.github.io/consensus-engine/conflict-map.html)** · **[→ Download CSV](https://rogolabs.github.io/consensus-engine/data/conflicts.csv)**

---

## The Cost of Scoring Inconsistency

Vulnerability management programs run on CVSS scores. Patch SLAs, risk acceptance workflows, and board-level reporting all flow from a number on a 0–10 scale. The implicit assumption is that the score is settled fact.

It is not.

The NVD and the GitHub Advisory Database independently score thousands of the same CVEs — and they frequently disagree. A **Drift Score of 5.0** means one source calls a vulnerability Critical while the other calls it Medium. An organization patching on a 30-day SLA for Medium vulnerabilities and a 7-day SLA for Critical ones will get the wrong answer 100% of the time if they rely on the lower source.

**Uncertainty about severity is as operationally dangerous as the vulnerability itself.** This project makes that uncertainty visible.

---

## Key Features

- **Drift Leaderboard** — top 100 CVEs ranked by scoring divergence, updated daily
- **NVD Rejected / GH Active tracking** — CVEs that NVD has withdrawn but GitHub Advisory continues to score as a live threat; the most extreme data integrity failures in the corpus
- **Conflict Map** — scatter plot of NVD vs. GitHub CVSS scores with year-over-year conflict trends
- **Bulk CSV export** — all scoring conflicts as a flat file, ready for SIEM ingestion, research, or further analysis
- **100% static** — no backend, no database; the repository *is* the dataset

---

## Current Statistics

| Metric | Value |
|---|---|
| Tracked scoring conflicts | **1,545** |
| NVD Rejected / GH Active | **~3,300+** |
| Average Drift Score (conflicts) | **4.36** |
| Maximum observed Drift Score | **6.9** |
| Data refresh cadence | **Daily (GitHub Actions)** |

*Statistics reflect the current live dataset. Updated automatically on each pipeline run.*

---

## The Drift Score (Δ)

The Drift Score is defined as the **absolute variance** between the two providers' CVSS scores for the same CVE and the same CVSS version:

```
Δ = | GitHub CVSS Score − NVD CVSS Score |
```

A Drift Score of **6.9** — the maximum observed in this dataset — means two organizations relying on different authoritative sources would classify the same vulnerability nearly 7 points apart on a 10-point scale.

**Classification rules:**

| `drift_type` | Meaning |
|---|---|
| `conflict` | Both sources assigned a score for the same CVSS version but reached different values |
| `gap` | One source has no score, or the two sources used incompatible CVSS versions |
| `rejected` | NVD has withdrawn the CVE entirely; GitHub Advisory may still score it as a live threat |

**On `rejected` CVEs:** This category represents a critical data point for defenders. When NVD rejects a CVE — often because it was determined to be a duplicate, incorrectly assigned, or out of scope — the GitHub Advisory Database does not always follow. Organizations using GitHub-sourced data will continue to see, and potentially act on, a threat that NVD has formally dismissed. Whether the dismissal or the advisory is correct is, itself, unknown — which is the point.

**CVSS version integrity:** Scores from different CVSS versions (e.g., v3.1 vs. v4.0) are **never compared**. A numerical difference across versions is not a conflict — it is an invalid comparison. Only same-version pairs qualify as `conflict`.

---

## Data Sources

| Source | Contribution | Notes |
|---|---|---|
| [NVD API 2.0](https://nvd.nist.gov/developers/vulnerabilities) | CVSS scores, CWE, CVE status, publish dates | Primary reference; mid-transition from v3.1 → v4.0 |
| [GitHub Advisory Database](https://github.com/advisories) | CVSS v3.1 scores, affected version ranges, GHSA IDs | Independent scoring; not all GHSAs have a CVE alias |

---

## Architecture

```
GitHub Actions (Python)        /docs/data/{year}/CVE-ID.json    GitHub Pages (Static UI)
┌─────────────────────────┐   ┌──────────────────────────┐   ┌──────────────────────────┐
│ Daily: ingest NVD API   │──▶│ One JSON per CVE with    │──▶│ Tailwind + Alpine.js     │
│ 2.0 + GitHub Advisory  │   │ raw source data +        │   │ fetches JSON directly,   │
│ DB. Compute Drift Score │   │ computed Drift Score     │   │ no backend               │
│ and pre-build indexes.  │   └──────────────────────────┘   └──────────────────────────┘
└─────────────────────────┘
```

All aggregate indexes (leaderboard, Conflict Map data) are **pre-computed by CI and committed to the repository** — never ranked or computed client-side. This ensures reproducibility and keeps the UI dependency-free.

---

## Getting Started

### Prerequisites

- Python 3.12+
- A [NVD API key](https://nvd.nist.gov/developers/request-an-api-key) (free; required for the full 50 req/30s rate limit)
- A [GitHub personal access token](https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/creating-a-personal-access-token) with `read:packages` scope

### Running locally

```bash
git clone https://github.com/RogoLabs/consensus-engine.git
cd vuln-anarchy

pip install -r requirements.txt

# Set credentials
export NVD_API_KEY="your-nvd-api-key"
export GH_TOKEN="your-github-token"

# Ingest data (runs NVD + GitHub Advisory fetches, computes Drift Scores)
python scripts/ingest.py

# Build pre-computed indexes (leaderboard, conflict-map, CSV)
python scripts/build_indexes.py
```

Output files are written to `docs/data/`. Serve `docs/` with any static HTTP server to view the UI locally:

```bash
python -m http.server 8080 --directory docs
```

### GitHub Actions (automated)

The pipeline runs on a daily cron. Add `NVD_API_KEY` and `GH_TOKEN` as repository secrets and the rest is automatic. See [`.github/workflows/ingest.yml`](.github/workflows/ingest.yml).

---

## Interpreting `conflicts.csv`

The CSV export at [`data/conflicts.csv`](https://rogolabs.github.io/consensus-engine/data/conflicts.csv) contains every CVE where both NVD and GitHub assigned a score for the same CVSS version and the scores differ.

| Column | Type | Description |
|---|---|---|
| `cve_id` | string | CVE identifier (e.g., `CVE-2025-1234`) |
| `cvss_variance` | float | Drift Score: `\|GitHub − NVD\|` on the 0–10 CVSS scale |
| `nvd_score` | float | NVD-assigned base score |
| `nvd_cvss_version` | string | CVSS version of the NVD score (e.g., `3.1`, `4.0`) |
| `github_score` | float | GitHub Advisory base score |
| `github_cvss_version` | string | CVSS version of the GitHub score |
| `assigning_cna` | string | CNA that originally submitted the CVE to NVD |
| `nvd_status` | string | NVD analysis status (`Analyzed`, `Awaiting Analysis`, etc.) |
| `published_date` | date | Date the CVE was first published in NVD (`YYYY-MM-DD`) |

**A note on `assigning_cna`:** NVD now largely republishes CNA-provided scores rather than scoring independently. A conflict between NVD and GitHub where the CNA is a major vendor (e.g., `microsoft`, `google`) often reflects a deliberate scoring difference by the vendor — a materially different signal than a conflict driven by NVD's own analysis lag.

---

## Research Applications

This dataset is well-suited for:

- **Longitudinal analysis** — do conflicts cluster around specific CNAs, vulnerability types, or time periods?
- **SLA impact modeling** — quantify the organizational risk of using a single scoring source for patch prioritization
- **CNA accountability research** — identify CNAs whose scores systematically diverge from independent assessors
- **ML/NLP feature engineering** — Drift Score as a feature in exploitability or patch-urgency models

If you publish research using this data, please cite this repository and consider opening an issue to share your findings. The goal is to create evidence that pressures CNAs and standards bodies toward better data quality.

---

## Contributing

Contributions are welcome. Areas of highest impact:

- **Data quality improvements** — corrections to scoring logic, CVSS version handling, or CNA attribution
- **New visualizations** — additional views of the conflict data
- **Documentation** — clearer explanations of edge cases, CVSS version nuances, or CNA workflows
- **Research** — opening issues with links to published findings that use this dataset

Please open an issue before submitting a large pull request.

---

## Philosophy

In vulnerability management, **uncertainty is as operationally dangerous as the vulnerability itself**. When two sources of truth disagree by 5+ points, the correct severity is currently unknown — and defenders have no authoritative signal to act on. Acknowledging and quantifying that uncertainty is the first step toward resolving it.

This project does not declare a winner between NVD and GitHub. It measures the gap and makes the data available. What you do with it is up to you.

---

*Built by [Jerry Gamblin](https://github.com/jgamblin) at [RogoLabs](https://rogolabs.net) · Presented at VulnCon 2026*