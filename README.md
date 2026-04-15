# vuln-anarchy — Vulnerability Anarchy / The Consensus Engine

**Lab:** [RogoLabs](https://rogolabs.net) · **Status:** Live · **Launch:** VulnCon 2026 · **Deployment:** 100% Static (GitHub Actions + GitHub Pages)

> *The vulnerability management ecosystem is fracturing. With the rise of independent CNAs and the shifting role of the NVD, the "truth" of a vulnerability has become subjective.*

**Vulnerability Anarchy** tracks **"Data Drift"** — the measurable delta between how different authorities score the same CVE. Right now it compares NVD and GitHub Advisory Database CVSS scores across the full corpus. If NVD says 9.8 and GitHub says 2.9, that's a Drift Score of 6.9 — and that matters to every defender who depends on these numbers.

## Live

- **[Drift Leaderboard](https://rogolabs.github.io/vuln-anarchy/)** — top 100 CVEs by score conflict, plus rejected CVEs that still have live GitHub advisories
- **[Anarchy Map](https://rogolabs.github.io/vuln-anarchy/anarchy-map.html)** — scatter plot of NVD vs GitHub CVSS scores; stacked bar chart of conflicts by publication year
- **[Export CSV](https://rogolabs.github.io/vuln-anarchy/data/conflicts.csv)** — all ~5,000+ score conflicts as a flat CSV

## Philosophy

- **No Database:** The repository *is* the database. All data is stored as flat JSON files under `/docs/data/`.
- **No Backend:** All processing runs in GitHub Actions. The UI is 100% client-side on GitHub Pages.
- **Transparency:** Every Drift Score is directly traceable to raw API source data and a specific commit.

## Architecture

```
GitHub Actions (Python)          /docs/data/{year}/CVE-ID.json   GitHub Pages (Static UI)
┌──────────────────────────┐    ┌────────────────────────┐    ┌──────────────────────────┐
│ Ingestion scripts pull   │───▶│ One JSON per CVE with  │───▶│ Tailwind + Alpine.js     │
│ from NVD API 2.0 and     │    │ all source data +      │    │ fetches JSON directly,   │
│ GitHub Advisory DB.      │    │ computed Drift Score   │    │ no API calls to backend  │
│ Runs daily via cron.     │    └────────────────────────┘    └──────────────────────────┘
└──────────────────────────┘
```

All aggregate indexes (leaderboard, Anarchy Map data) are **pre-computed by CI** — never ranked client-side.

## The Drift Score (Δ)

The Drift Score is simply `|GitHub CVSS − NVD CVSS|`. A score of 6.9 means the two authorities disagree by 6.9 CVSS points.

Rules:
- **Both sources must have a score** for a CVE to be classified as `conflict`. One source missing → `gap`.
- **Scores must be the same CVSS version** (v3.1 vs v4.0 comparison is invalid → `gap`).
- **Rejected CVEs** where NVD has tombstoned the CVE but GitHub still has a live advisory are the most extreme cases and are surfaced separately.

`drift_type` is always one of:
- `"conflict"` — both sources scored the same version; they disagree
- `"gap"` — one or more sources have no data or incompatible versions
- `"rejected"` — NVD has rejected the CVE; GitHub may still have a live advisory

## Data Sources

| Source | Primary Contribution | Status |
|---|---|---|
| NVD API 2.0 | CVSS scores, CWE, CPE strings, publish dates | ✅ Live |
| GitHub Advisory Database | CVSS v3.1 scores, affected versions, GHSA IDs | ✅ Live |

## What's Live

- [x] Daily ingestion from NVD API 2.0 and GitHub Advisory Database
- [x] Drift Score (`|GitHub CVSS − NVD CVSS|`) across 240k+ CVEs
- [x] Drift Leaderboard — top 100 conflicts + rejected CVEs with live GitHub advisories
- [x] Anarchy Map — scatter plot (X=NVD, Y=GitHub) + Conflicts by Year bar chart
- [x] Bulk CSV export of all ~5,000+ score conflicts
- [x] Pre-computed indexes, no backend, 100% static

## Project Origin

An evolution of the **"CVE Decaf"** research, shifting focus from "Bad Data" to "Conflicting Data" in the global vulnerability ecosystem.

---
*Built by [Jerry Gamblin](https://github.com/jgamblin) at [RogoLabs](https://rogolabs.net).*