# Vulnerability Anarchy (The Consensus Engine)
**Lab:** [RogoLabs](https://rogolabs.net)  
**Status:** Concept / Summer 2026 Circuit (DEF CON 34)  
**Deployment:** 100% Static (GitHub Actions + GitHub Pages)  

## 1. Executive Summary
The vulnerability management ecosystem is fracturing. With the rise of independent CNAs and the shifting role of the NVD, the "truth" of a vulnerability has become subjective. **Vulnerability Anarchy** is a data-as-code project that tracks "Data Drift"—the delta between how different authorities (NVD, GitHub, OSV, CISA) score and describe the same CVE.

## 2. The Philosophy
* **No Database:** The repository *is* the database. All data is stored as flat JSON.
* **No Backend:** Processing happens in GitHub Actions; the UI is 100% client-side.
* **Transparency:** Every "Anarchy Score" is traceable to a specific commit hash and raw data source.

## 3. Core Logic: The Drift Score ($\Delta$)
The engine calculates the **Drift Score** for every CVE by comparing:
* **CVSS Variance:** The numerical difference between the highest and lowest reported scores.
* **Metadata Conflict:** Inconsistencies in CWE assignments or "Affected Version" (CPE) strings.
* **Velocity:** Which source was the first to provide "Actionable Intelligence" (Fix/PoC).

## 4. Architecture
1. **Ingestion (GitHub Actions):** Periodic Python scripts pull from:
    * NVD API 2.0
    * GitHub Advisory Database
    * OSV.dev
    * CISA KEV & EPSS (First.org)
2. **Analysis:** A runner-side script compares the sources and generates a consolidated JSON object for each CVE in `/data/year/CVE-ID.json`.
3. **Frontend (GitHub Pages):** A lightweight Tailwind/Alpine.js site that fetches these JSON files to render:
    * **The Anarchy Map:** A visual heat-map of industry disagreement.
    * **The Drift Leaderboard:** The top 50 most disputed vulnerabilities.
    * **CVE Nutrition Labels:** A standardized quality grade for individual bugs.

## 5. Roadmap
- [ ] **Phase 1 (Spring 2026):** Basic ingestion and CVSS comparison (NVD vs. GitHub).
- [ ] **Phase 2 (Summer 2026):** Full "Drift Engine" and automated "Nutrition Label" generation.
- [ ] **Phase 3 (August 2026):** Live launch at DEF CON 34.

## 6. Project Origin
This project is an evolution of the **"CVE Decaf"** research, focusing on the transition from "Bad Data" to "Conflicting Data" in the global security research community.

---
*Built by [Jerry Gamblin](https://github.com/jgamblin) at RogoLabs.*