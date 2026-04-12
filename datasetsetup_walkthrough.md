# Dataset Setup — Walkthrough

## What Was Done

Created an automated dataset pipeline for the cybersecurity multi-agent capstone. Two files were added to the project:

| File | Purpose |
|------|---------|
| [setup_datasets.py](file:///Users/shashankrallabandi/CAPSTONE/setup_datasets.py) | Downloads all datasets, builds SQLite DB |
| [requirements.txt](file:///Users/shashankrallabandi/CAPSTONE/requirements.txt) | Python dependencies (`requests`, `nvdlib`, `python-nmap`) |

---

## Data Loaded into [datasets/vuln_lookup.db](file:///Users/shashankrallabandi/CAPSTONE/datasets/vuln_lookup.db)

| Table | Records | Source |
|-------|---------|--------|
| `cves` | **185,529** | NVD JSON feeds 2020–2025 (fkie-cad GitHub mirror) |
| `cve_cpes` | **1,501,826** | CPE match strings from CVE configurations |
| `cpes` | **171,520** | Unique CPEs extracted + parsed (vendor/product/version) |
| `exploits` | **46,968** | Exploit-DB `files_exploits.csv` (GitLab mirror) |

**DB size:** 437.5 MB  |  **Total dataset directory:** ~1.65 GB

---

## Verification Results

- ✅ **Log4Shell** (`CVE-2021-44228`): CVSS 10.0 CRITICAL, correct description + CPE matches
- ✅ **CPE parsing**: `apache/log4j/2.0` correctly extracted from CPE URIs
- ✅ **Top vendors**: Cisco (16K), HP (13K), Intel (8K) — realistic distribution
- ✅ **Out-of-range CVE** (`CVE-2017-0144`): correctly absent (only 2020–2025 data)
- ✅ **Exploit-DB**: 46,968 exploits with CVE cross-references working

---

## How to Re-run

```bash
cd /Users/shashankrallabandi/CAPSTONE
source venv/bin/activate
python setup_datasets.py
```

The script is idempotent — it skips already-downloaded files and rebuilds the DB fresh each run.

---

## How Your Agents Will Use This Data

| Agent | Queries | Example |
|-------|---------|---------|
| **Vulnerability Agent** | `SELECT * FROM cves c JOIN cve_cpes cc ON c.cve_id=cc.cve_id WHERE cc.cpe_uri LIKE 'cpe:2.3:a:apache:http_server:2.4.49%'` | Find CVEs affecting Apache 2.4.49 |
| **Vulnerability Agent** | `SELECT vendor, product FROM cpes WHERE product LIKE '%openssh%'` | Match detected service → CPE URI |
| **Reporting Agent** | `SELECT e.* FROM exploits e WHERE e.codes_json LIKE '%CVE-2021-44228%'` | Flag vulns with public exploits |

> [!TIP]
> For faster exploit cross-referencing, consider adding a `cve_exploits` junction table in a future iteration.
