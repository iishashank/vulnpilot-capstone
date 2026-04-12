#!/usr/bin/env python3
"""
setup_datasets.py — Downloads and processes all datasets needed for the
cybersecurity multi-agent vulnerability assessment capstone project.

Datasets:
    1. NVD/CVE JSON feeds (2020–2025) → datasets/nvd/
    2. CPE Dictionary XML              → datasets/cpe/
    3. Exploit-DB CSV                   → datasets/exploitdb/

All three are then loaded into a local SQLite database:
    datasets/vuln_lookup.db
"""

import gzip
import io
import json
import lzma
import os
import sqlite3
import sys
import time
import xml.etree.ElementTree as ET
import zipfile
from pathlib import Path

import requests

# ─── Configuration ───────────────────────────────────────────────────────────

BASE_DIR = Path(__file__).resolve().parent / "datasets"
NVD_DIR = BASE_DIR / "nvd"
CPE_DIR = BASE_DIR / "cpe"
EXPLOITDB_DIR = BASE_DIR / "exploitdb"
DB_PATH = BASE_DIR / "vuln_lookup.db"

# NVD CVE JSON feeds — community mirror (daily updated, xz-compressed)
NVD_YEARS = range(2020, 2026)
NVD_BASE_URL = "https://github.com/fkie-cad/nvd-json-data-feeds/releases/latest/download"

# CPE Dictionary — official NIST download
CPE_URL = "https://nvd.nist.gov/feeds/xml/cpe/dictionary/official-cpe-dictionary_v2.3.xml.gz"

# Exploit-DB — CSV from official GitLab mirror (raw)
EXPLOITDB_CSV_URL = (
    "https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv"
)

# ─── Helpers ─────────────────────────────────────────────────────────────────

def _print_header(title: str) -> None:
    print(f"\n{'='*60}")
    print(f"  {title}")
    print(f"{'='*60}")


def _download(url: str, dest: Path, description: str) -> bool:
    """Download a file with progress indication.  Returns True on success."""
    if dest.exists() and dest.stat().st_size > 0:
        print(f"  ✓ Already exists: {dest.name} ({dest.stat().st_size:,} bytes)")
        return True

    print(f"  ⬇ Downloading {description} …")
    print(f"    URL: {url}")

    try:
        resp = requests.get(url, stream=True, timeout=120)
        resp.raise_for_status()
    except requests.RequestException as exc:
        print(f"  ✗ FAILED: {exc}")
        return False

    total = int(resp.headers.get("content-length", 0))
    downloaded = 0

    with open(dest, "wb") as f:
        for chunk in resp.iter_content(chunk_size=1024 * 256):
            f.write(chunk)
            downloaded += len(chunk)
            if total:
                pct = downloaded * 100 // total
                print(f"\r    {downloaded:,} / {total:,} bytes ({pct}%)", end="")
    print()  # newline after progress
    print(f"  ✓ Saved: {dest.name} ({dest.stat().st_size:,} bytes)")
    return True


# ─── 1. NVD / CVE JSON Feeds ────────────────────────────────────────────────

def download_nvd_feeds() -> list[Path]:
    """Download NVD CVE JSON feeds (xz-compressed) and decompress them."""
    _print_header("1/3 · NVD CVE JSON Feeds (2020–2025)")
    NVD_DIR.mkdir(parents=True, exist_ok=True)
    json_files: list[Path] = []

    for year in NVD_YEARS:
        xz_name = f"CVE-{year}.json.xz"
        json_name = f"CVE-{year}.json"
        xz_path = NVD_DIR / xz_name
        json_path = NVD_DIR / json_name

        # If JSON already extracted, skip
        if json_path.exists() and json_path.stat().st_size > 0:
            print(f"  ✓ Already extracted: {json_name}")
            json_files.append(json_path)
            continue

        url = f"{NVD_BASE_URL}/{xz_name}"
        if not _download(url, xz_path, f"NVD CVE {year}"):
            # Fallback: try .gz variant
            gz_name = f"CVE-{year}.json.gz"
            gz_url = f"{NVD_BASE_URL}/{gz_name}"
            gz_path = NVD_DIR / gz_name
            if _download(gz_url, gz_path, f"NVD CVE {year} (.gz fallback)"):
                print(f"  📦 Decompressing {gz_name} …")
                with gzip.open(gz_path, "rb") as gz_in:
                    json_path.write_bytes(gz_in.read())
                print(f"  ✓ Extracted: {json_name}")
                json_files.append(json_path)
            continue

        # Decompress .xz → .json
        print(f"  📦 Decompressing {xz_name} …")
        with lzma.open(xz_path, "rb") as xz_in:
            json_path.write_bytes(xz_in.read())
        print(f"  ✓ Extracted: {json_name}")
        json_files.append(json_path)

    return json_files


# ─── 2. CPE Dictionary ──────────────────────────────────────────────────────

def download_cpe_dictionary() -> Path | None:
    """Download the official CPE Dictionary XML (gzip-compressed).
    
    Falls back to extracting CPE data from NVD CVE feeds if the
    NIST download URL is unavailable (deprecated in 2023).
    """
    _print_header("2/3 · CPE Dictionary")
    CPE_DIR.mkdir(parents=True, exist_ok=True)

    gz_path = CPE_DIR / "official-cpe-dictionary_v2.3.xml.gz"
    xml_path = CPE_DIR / "official-cpe-dictionary_v2.3.xml"

    if xml_path.exists() and xml_path.stat().st_size > 0:
        print(f"  ✓ Already extracted: {xml_path.name}")
        return xml_path

    if _download(CPE_URL, gz_path, "CPE Dictionary"):
        print(f"  📦 Decompressing {gz_path.name} …")
        with gzip.open(gz_path, "rb") as gz_in:
            xml_path.write_bytes(gz_in.read())
        print(f"  ✓ Extracted: {xml_path.name}")
        return xml_path

    print("  ⚠  NIST CPE feed unavailable — CPE data will be extracted from NVD CVE feeds instead.")
    print("     (This is normal since NIST deprecated the XML feed in late 2023.)")
    return None


# ─── 3. Exploit-DB CSV ──────────────────────────────────────────────────────

def download_exploitdb_csv() -> Path | None:
    """Download Exploit-DB files_exploits.csv."""
    _print_header("3/3 · Exploit-DB CSV")
    EXPLOITDB_DIR.mkdir(parents=True, exist_ok=True)

    csv_path = EXPLOITDB_DIR / "files_exploits.csv"
    if _download(EXPLOITDB_CSV_URL, csv_path, "Exploit-DB CSV"):
        return csv_path

    print("  ⚠  Exploit-DB download failed — enrichment will be unavailable.")
    return None


# ─── SQLite Database Builder ─────────────────────────────────────────────────

def _create_tables(conn: sqlite3.Connection) -> None:
    """Create the schema for the vulnerability lookup database."""
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS cves (
            cve_id          TEXT PRIMARY KEY,
            description     TEXT,
            cvss_v3_score   REAL,
            cvss_v3_severity TEXT,
            cvss_v2_score   REAL,
            published       TEXT,
            last_modified   TEXT,
            references_json TEXT   -- JSON array of reference URLs
        );

        CREATE TABLE IF NOT EXISTS cve_cpes (
            cve_id   TEXT NOT NULL,
            cpe_uri  TEXT NOT NULL,
            vulnerable INTEGER DEFAULT 1,
            FOREIGN KEY (cve_id) REFERENCES cves(cve_id)
        );

        CREATE TABLE IF NOT EXISTS cpes (
            cpe_uri  TEXT PRIMARY KEY,
            title    TEXT,
            vendor   TEXT,
            product  TEXT,
            version  TEXT
        );

        CREATE TABLE IF NOT EXISTS exploits (
            exploit_id   INTEGER PRIMARY KEY,
            description  TEXT,
            date         TEXT,
            author       TEXT,
            platform     TEXT,
            type         TEXT,
            codes_json   TEXT   -- JSON array of CVE / OSVDB codes
        );

        CREATE INDEX IF NOT EXISTS idx_cve_cpes_cpe  ON cve_cpes(cpe_uri);
        CREATE INDEX IF NOT EXISTS idx_cve_cpes_cve  ON cve_cpes(cve_id);
        CREATE INDEX IF NOT EXISTS idx_cpes_vendor   ON cpes(vendor);
        CREATE INDEX IF NOT EXISTS idx_cpes_product  ON cpes(product);
    """)


def _load_nvd_into_db(conn: sqlite3.Connection, json_files: list[Path]) -> int:
    """Parse NVD JSON feeds and insert CVEs + CPE match data."""
    total_cves = 0

    for json_path in json_files:
        print(f"  📥 Loading {json_path.name} …")
        try:
            data = json.loads(json_path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError) as e:
            print(f"    ⚠ Failed to parse {json_path.name}: {e}")
            continue

        # fkie-cad mirror format: {"cve_items": [...]}
        vulnerabilities = data.get("cve_items", [])
        if not vulnerabilities:
            # NVD JSON 2.0 format: {"vulnerabilities": [{"cve": {...}}, ...]}
            vulnerabilities = data.get("vulnerabilities", [])
        if not vulnerabilities:
            # Legacy format: {"CVE_Items": [...]}
            vulnerabilities = data.get("CVE_Items", [])

        count = 0
        for item in vulnerabilities:
            cve_data = item.get("cve", item)
            cve_id = cve_data.get("id", "")

            # --- Fall back to legacy ID path ---
            if not cve_id:
                meta = cve_data.get("CVE_data_meta", {})
                cve_id = meta.get("ID", "")
            if not cve_id:
                continue

            # Description
            desc = ""
            descriptions = cve_data.get("descriptions", [])
            if descriptions:
                for d in descriptions:
                    if d.get("lang", "en") == "en":
                        desc = d.get("value", "")
                        break
            if not desc:
                # Legacy path
                desc_data = cve_data.get("description", {})
                desc_list = desc_data.get("description_data", [])
                if desc_list:
                    desc = desc_list[0].get("value", "")

            # CVSS scores
            cvss3_score = None
            cvss3_severity = None
            cvss2_score = None

            metrics = cve_data.get("metrics", {})
            # v3.1
            cvss31 = metrics.get("cvssMetricV31", metrics.get("cvssMetricV30", []))
            if cvss31:
                cv = cvss31[0].get("cvssData", {})
                cvss3_score = cv.get("baseScore")
                cvss3_severity = cv.get("baseSeverity")
            # v2
            cvss2 = metrics.get("cvssMetricV2", [])
            if cvss2:
                cv = cvss2[0].get("cvssData", {})
                cvss2_score = cv.get("baseScore")

            # Legacy CVSS path
            if cvss3_score is None:
                impact = cve_data.get("impact", {})
                bm3 = impact.get("baseMetricV3", {})
                if bm3:
                    cv3 = bm3.get("cvssV3", {})
                    cvss3_score = cv3.get("baseScore")
                    cvss3_severity = cv3.get("baseSeverity")
                bm2 = impact.get("baseMetricV2", {})
                if bm2:
                    cv2 = bm2.get("cvssV2", {})
                    cvss2_score = cv2.get("baseScore")

            # Dates
            published = cve_data.get("published", "")
            last_modified = cve_data.get("lastModified", "")

            # References
            refs = []
            ref_list = cve_data.get("references", [])
            for r in ref_list:
                url = r.get("url", "")
                if url:
                    refs.append(url)

            conn.execute(
                """INSERT OR REPLACE INTO cves
                   (cve_id, description, cvss_v3_score, cvss_v3_severity,
                    cvss_v2_score, published, last_modified, references_json)
                   VALUES (?,?,?,?,?,?,?,?)""",
                (cve_id, desc, cvss3_score, cvss3_severity,
                 cvss2_score, published, last_modified, json.dumps(refs)),
            )

            # CPE match strings
            configurations = cve_data.get("configurations", [])
            for config in configurations:
                nodes = config.get("nodes", [])
                if not nodes and isinstance(config, dict):
                    nodes = [config]
                for node in nodes:
                    cpe_matches = node.get("cpeMatch", [])
                    # Legacy path
                    if not cpe_matches:
                        cpe_matches = node.get("cpe_match", [])
                    for match in cpe_matches:
                        cpe_uri = match.get("criteria", match.get("cpe23Uri", ""))
                        vulnerable = 1 if match.get("vulnerable", True) else 0
                        if cpe_uri:
                            conn.execute(
                                "INSERT INTO cve_cpes (cve_id, cpe_uri, vulnerable) VALUES (?,?,?)",
                                (cve_id, cpe_uri, vulnerable),
                            )
            count += 1

        conn.commit()
        total_cves += count
        print(f"    ✓ Loaded {count:,} CVEs from {json_path.name}")

    return total_cves


def _load_cpe_into_db(conn: sqlite3.Connection, xml_path: Path | None) -> int:
    """Parse CPE Dictionary XML and insert into DB."""
    if xml_path is None or not xml_path.exists():
        print("  ⚠ CPE Dictionary not available, skipping.")
        return 0

    print(f"  📥 Parsing CPE Dictionary (this may take a minute) …")

    ns = {
        "cpe": "http://cpe.mitre.org/dictionary/2.0",
        "cpe-23": "http://scap.nist.gov/schema/cpe-extension/2.3",
    }

    count = 0
    try:
        for event, elem in ET.iterparse(xml_path, events=("end",)):
            if not elem.tag.endswith("}cpe-item"):
                continue

            # CPE 2.3 URI
            cpe23_elem = elem.find(".//cpe-23:cpe23-item", ns)
            if cpe23_elem is None:
                elem.clear()
                continue
            cpe_uri = cpe23_elem.get("name", "")
            if not cpe_uri:
                elem.clear()
                continue

            # Title
            title_elem = elem.find("cpe:title", ns)
            title = title_elem.text if title_elem is not None else ""

            # Parse vendor/product/version from CPE URI
            # cpe:2.3:a:vendor:product:version:...
            parts = cpe_uri.split(":")
            vendor = parts[3] if len(parts) > 3 else ""
            product = parts[4] if len(parts) > 4 else ""
            version = parts[5] if len(parts) > 5 else ""

            conn.execute(
                "INSERT OR REPLACE INTO cpes (cpe_uri, title, vendor, product, version) VALUES (?,?,?,?,?)",
                (cpe_uri, title, vendor, product, version),
            )
            count += 1

            if count % 50000 == 0:
                conn.commit()
                print(f"    … {count:,} CPEs processed")

            elem.clear()

    except ET.ParseError as e:
        print(f"  ⚠ XML parse error: {e}")

    conn.commit()
    print(f"  ✓ Loaded {count:,} CPEs")
    return count


def _load_exploitdb_into_db(conn: sqlite3.Connection, csv_path: Path | None) -> int:
    """Parse Exploit-DB CSV and insert into DB."""
    if csv_path is None or not csv_path.exists():
        print("  ⚠ Exploit-DB CSV not available, skipping.")
        return 0

    import csv

    print(f"  📥 Loading Exploit-DB CSV …")
    count = 0

    with open(csv_path, "r", encoding="utf-8", errors="replace") as f:
        reader = csv.DictReader(f)
        for row in reader:
            try:
                exploit_id = int(row.get("id", 0))
            except (ValueError, TypeError):
                continue

            description = row.get("description", "")
            date = row.get("date_published", row.get("date", ""))
            author = row.get("author", "")
            platform = row.get("platform", "")
            etype = row.get("type", "")

            # CVE codes
            codes_str = row.get("codes", "")
            codes = [c.strip() for c in codes_str.split(";") if c.strip()] if codes_str else []

            conn.execute(
                """INSERT OR REPLACE INTO exploits
                   (exploit_id, description, date, author, platform, type, codes_json)
                   VALUES (?,?,?,?,?,?,?)""",
                (exploit_id, description, date, author, platform, etype, json.dumps(codes)),
            )
            count += 1

            if count % 10000 == 0:
                conn.commit()

    conn.commit()
    print(f"  ✓ Loaded {count:,} exploits")
    return count


def build_database(
    json_files: list[Path],
    cpe_xml: Path | None,
    exploitdb_csv: Path | None,
    output_path: Path | None = None,
) -> Path:
    """Build (or rebuild) the SQLite vulnerability lookup database."""
    _print_header("Building SQLite Database")
    target_db_path = output_path or DB_PATH

    # Remove old DB to rebuild fresh
    if target_db_path.exists():
        target_db_path.unlink()

    target_db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(target_db_path))
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")

    _create_tables(conn)

    total_cves = _load_nvd_into_db(conn, json_files)
    total_cpes = _load_cpe_into_db(conn, cpe_xml)

    # If CPE XML wasn't available, build CPE entries from NVD CVE feed data
    if total_cpes == 0:
        print("  📋 Building CPE entries from CVE feed cpeMatch data …")
        cursor = conn.execute("SELECT DISTINCT cpe_uri FROM cve_cpes WHERE cpe_uri != ''")
        batch = []
        for (cpe_uri,) in cursor:
            # cpe:2.3:part:vendor:product:version:update:edition:lang:sw_ed:tgt_sw:tgt_hw:other
            parts = cpe_uri.split(":")
            vendor  = parts[3] if len(parts) > 3 else ""
            product = parts[4] if len(parts) > 4 else ""
            version = parts[5] if len(parts) > 5 else ""
            batch.append((cpe_uri, "", vendor, product, version))
        conn.executemany(
            "INSERT OR IGNORE INTO cpes (cpe_uri, title, vendor, product, version) VALUES (?,?,?,?,?)",
            batch,
        )
        conn.commit()
        total_cpes = len(batch)
        print(f"  ✓ Built {total_cpes:,} CPE entries from CVE data")

    total_exploits = _load_exploitdb_into_db(conn, exploitdb_csv)

    conn.close()

    print(f"\n{'='*60}")
    print(f"  DATABASE SUMMARY: {target_db_path}")
    print(f"{'='*60}")
    print(f"  CVEs loaded      : {total_cves:,}")
    print(f"  CPEs loaded      : {total_cpes:,}")
    print(f"  Exploits loaded  : {total_exploits:,}")
    print(f"  DB size          : {target_db_path.stat().st_size / (1024*1024):.1f} MB")
    return target_db_path


# ─── Main ────────────────────────────────────────────────────────────────────

def main() -> None:
    print("╔══════════════════════════════════════════════════════════╗")
    print("║  Cybersecurity Multi-Agent Capstone — Dataset Setup     ║")
    print("╚══════════════════════════════════════════════════════════╝")

    start = time.time()

    # 1. NVD CVE feeds
    json_files = download_nvd_feeds()

    # 2. CPE Dictionary
    cpe_xml = download_cpe_dictionary()

    # 3. Exploit-DB
    exploitdb_csv = download_exploitdb_csv()

    # 4. Build SQLite DB
    build_database(json_files, cpe_xml, exploitdb_csv)

    elapsed = time.time() - start
    print(f"\n✅ All done in {elapsed:.0f}s")
    print(f"   Dataset directory: {BASE_DIR}")
    print(f"   SQLite database : {DB_PATH}")


if __name__ == "__main__":
    main()
