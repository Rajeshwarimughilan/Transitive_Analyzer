# 05_enrich_cves.py

import csv
import logging
import pickle
import sqlite3
import time
from pathlib import Path

import requests

from config import (
    GRAPHS_DIR,
    TARGETS_DIR,
    DB_PATH,
    PROJECT_LIST,
    LOGS_DIR,
    NVD_API_KEY,
)

# ---------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------

LOGS_DIR.mkdir(parents=True, exist_ok=True)
DB_PATH.parent.mkdir(parents=True, exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    handlers=[
        logging.FileHandler(
            str(LOGS_DIR / "05_enrich_cves.log"), encoding="utf-8"
        ),
        logging.StreamHandler(),
    ],
)

USER_AGENT = "TransitiveRiskResearch/1.0 (academic research)"

# ---------------------------------------------------------------------
# Database
# ---------------------------------------------------------------------

def init_db() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS osv_cache (
            package_name TEXT,
            version      TEXT,
            osv_id       TEXT,
            cve_id       TEXT,
            queried_at   TEXT,
            PRIMARY KEY (package_name, version, osv_id)
        );
        CREATE TABLE IF NOT EXISTS nvd_cache (
            cve_id       TEXT PRIMARY KEY,
            cvss_score   REAL,
            cvss_version TEXT,
            queried_at   TEXT
        );
        CREATE TABLE IF NOT EXISTS epss_cache (
            cve_id       TEXT PRIMARY KEY,
            epss_score   REAL,
            percentile   REAL,
            queried_at   TEXT
        );
        CREATE TABLE IF NOT EXISTS enrichment_log (
            package_name   TEXT PRIMARY KEY,
            total_nodes    INTEGER,
            nodes_with_cve INTEGER,
            total_cves     INTEGER,
            enriched_at    TEXT
        );
    """)
    conn.commit()
    return conn

# ---------------------------------------------------------------------
# Version Resolution
# ---------------------------------------------------------------------

def get_root_version(package_name: str) -> str:
    version_file = TARGETS_DIR / f"{package_name}_env" / "installed_version.txt"
    if version_file.exists():
        v = version_file.read_text(encoding="utf-8").strip()
        if v and v != "unknown":
            return v
    return ""

# ---------------------------------------------------------------------
# OSV API
# ---------------------------------------------------------------------

def extract_affected_functions(vuln: dict, package_name: str) -> list[str] | None:
    """
    Best-effort extraction of function-level affected-range data from an OSV
    record, for use by the reachability stage (build_callgraphs.py).

    OSV's schema does not guarantee function-level granularity — most
    advisories only give package/version ranges. Some GHSA-sourced records
    carry extra detail under database_specific/ecosystem_specific keys, but
    the key names are not standardized across advisories. This looks for the
    known variants and returns None (not []) when nothing is found, so
    downstream code can distinguish "checked, nothing there" from "not
    checked yet" — reachability then falls back to import-level analysis
    (see docs/DESIGN.md §4.2) rather than silently treating None as "no
    functions affected".
    """
    for affected in vuln.get("affected", []):
        pkg = affected.get("package", {})
        if pkg.get("name", "").lower() != package_name.lower():
            continue
        for key in ("database_specific", "ecosystem_specific"):
            specific = affected.get(key, {}) or {}
            for func_key in ("affected_functions", "affected_symbols", "functions"):
                funcs = specific.get(func_key)
                if funcs:
                    return list(funcs)
    return None


def query_osv(package_name: str, version: str, conn: sqlite3.Connection) -> list:
    if not version:
        logging.debug(f"  [OSV] Skipping {package_name} — no version")
        return []

    cached = conn.execute(
        "SELECT osv_id, cve_id FROM osv_cache WHERE package_name=? AND version=?",
        (package_name, version),
    ).fetchall()

    if cached:
        return [
            {"osv_id": r[0], "cve_id": r[1]}
            for r in cached
            if r[1] != "NONE"
        ]

    try:
        response = requests.post(
            "https://api.osv.dev/v1/query",
            json={
                "package": {"name": package_name, "ecosystem": "PyPI"},
                "version": version,
            },
            headers={"User-Agent": USER_AGENT},
            timeout=15,
        )
        time.sleep(0.2)
    except requests.RequestException as e:
        logging.warning(f"  [OSV] Network error {package_name}@{version}: {e}")
        return []

    if response.status_code != 200:
        logging.warning(f"  [OSV] HTTP {response.status_code} for {package_name}@{version}")
        return []

    vulns = response.json().get("vulns", [])
    results = []

    for vuln in vulns:
        osv_id  = vuln["id"]
        cve_ids = [a for a in vuln.get("aliases", []) if a.startswith("CVE-")]
        affected_functions = extract_affected_functions(vuln, package_name)
        for cve_id in cve_ids:
            results.append({
                "osv_id": osv_id,
                "cve_id": cve_id,
                "affected_functions": affected_functions,
            })
            conn.execute(
                "INSERT OR IGNORE INTO osv_cache VALUES (?,?,?,?,datetime('now'))",
                (package_name, version, osv_id, cve_id),
            )

    if not vulns:
        conn.execute(
            "INSERT OR IGNORE INTO osv_cache VALUES (?,?,?,?,datetime('now'))",
            (package_name, version, "NONE", "NONE"),
        )

    conn.commit()
    return results

# ---------------------------------------------------------------------
# NVD API
# ---------------------------------------------------------------------

def get_cvss(cve_id: str, conn: sqlite3.Connection) -> tuple[float, str]:
    if not cve_id or cve_id == "NONE":
        return 0.0, ""

    cached = conn.execute(
        "SELECT cvss_score, cvss_version FROM nvd_cache WHERE cve_id=?",
        (cve_id,),
    ).fetchone()
    if cached:
        return cached[0] or 0.0, cached[1] or ""

    try:
        response = requests.get(
            "https://services.nvd.nist.gov/rest/json/cves/2.0",
            params={"cveId": cve_id},
            headers={"apiKey": NVD_API_KEY, "User-Agent": USER_AGENT},
            timeout=15,
        )
        time.sleep(0.6)
    except requests.RequestException as e:
        logging.warning(f"  [NVD] Network error {cve_id}: {e}")
        return 0.0, ""

    if response.status_code != 200:
        logging.warning(f"  [NVD] HTTP {response.status_code} for {cve_id}")
        return 0.0, ""

    score, cvss_version = 0.0, ""
    vulns = response.json().get("vulnerabilities", [])

    if vulns:
        metrics = vulns[0]["cve"].get("metrics", {})
        for key, label in [
            ("cvssMetricV31", "3.1"),
            ("cvssMetricV30", "3.0"),
            ("cvssMetricV2",  "2.0"),
        ]:
            if key in metrics:
                score        = metrics[key][0]["cvssData"]["baseScore"]
                cvss_version = label
                break

    conn.execute(
        "INSERT OR REPLACE INTO nvd_cache VALUES (?,?,?,datetime('now'))",
        (cve_id, score, cvss_version),
    )
    conn.commit()
    return score, cvss_version

# ---------------------------------------------------------------------
# EPSS API (FIRST.org — exploit-likelihood, separate from CVSS severity)
# ---------------------------------------------------------------------

def get_epss(cve_id: str, conn: sqlite3.Connection) -> float:
    """
    Returns EPSS score in [0, 1] — probability of exploitation in the next
    30 days. No API key required. Distinct from CVSS: a CVE can be severe
    (high CVSS) but rarely exploited (low EPSS), or the reverse.
    """
    if not cve_id or cve_id == "NONE":
        return 0.0

    cached = conn.execute(
        "SELECT epss_score FROM epss_cache WHERE cve_id=?",
        (cve_id,),
    ).fetchone()
    if cached:
        return cached[0] or 0.0

    try:
        response = requests.get(
            "https://api.first.org/data/v4/epss",
            params={"cve": cve_id},
            headers={"User-Agent": USER_AGENT},
            timeout=15,
        )
        time.sleep(0.2)
    except requests.RequestException as e:
        logging.warning(f"  [EPSS] Network error {cve_id}: {e}")
        return 0.0

    if response.status_code != 200:
        logging.warning(f"  [EPSS] HTTP {response.status_code} for {cve_id}")
        return 0.0

    data = response.json().get("data", [])
    score, percentile = 0.0, 0.0
    if data:
        score      = float(data[0].get("epss", 0.0))
        percentile = float(data[0].get("percentile", 0.0))

    conn.execute(
        "INSERT OR REPLACE INTO epss_cache VALUES (?,?,?,datetime('now'))",
        (cve_id, score, percentile),
    )
    conn.commit()
    return score

# ---------------------------------------------------------------------
# Graph Enrichment
# ---------------------------------------------------------------------

def enrich_graph(package_name: str, conn: sqlite3.Connection) -> bool:
    graph_path = GRAPHS_DIR / f"{package_name}_graph.pkl"

    if not graph_path.exists():
        logging.error(f"[SKIP] {package_name} — graph not found, run 04 first")
        return False

    try:
        with open(graph_path, "rb") as f:
            G = pickle.load(f)
    except Exception as e:
        logging.error(f"[FAIL] Could not load graph for {package_name}: {e}")
        return False

    root           = package_name.lower()
    nodes_with_cve = 0
    total_cves     = 0

    for node in G.nodes():
        if node == root:
            version = get_root_version(package_name)
            G.nodes[node]["version"] = version
        else:
            version = G.nodes[node].get("version", "").strip()

        if not version:
            logging.debug(f"  [SKIP node] {node} — no version")
            G.nodes[node].update({
                "cves": [], "cve_count": 0,
                "max_cvss": 0.0, "sum_cvss": 0.0, "epss": 0.0,
            })
            continue

        osv_results = query_osv(node, version, conn)

        scored_cves = []
        for r in osv_results:
            if r["cve_id"] == "NONE":
                continue
            score, cvss_ver = get_cvss(r["cve_id"], conn)
            epss = get_epss(r["cve_id"], conn)
            if score > 0:
                scored_cves.append({
                    "cve_id":             r["cve_id"],
                    "osv_id":             r["osv_id"],
                    "cvss":               score,
                    "cvss_version":       cvss_ver,
                    "epss":               epss,
                    "affected_functions": r.get("affected_functions"),
                })

        G.nodes[node]["cves"]      = scored_cves
        G.nodes[node]["cve_count"] = len(scored_cves)
        G.nodes[node]["max_cvss"]  = max((c["cvss"] for c in scored_cves), default=0.0)
        G.nodes[node]["sum_cvss"]  = sum(c["cvss"] for c in scored_cves)
        G.nodes[node]["epss"]      = max((c["epss"] for c in scored_cves), default=0.0)

        if scored_cves:
            nodes_with_cve += 1
            total_cves     += len(scored_cves)
            logging.info(
                f"  {node}@{version}: {len(scored_cves)} CVEs, "
                f"max_cvss={G.nodes[node]['max_cvss']:.1f}"
            )

    try:
        with open(graph_path, "wb") as f:
            pickle.dump(G, f)
    except Exception as e:
        logging.error(f"[FAIL] Could not save graph for {package_name}: {e}")
        return False

    conn.execute(
        "INSERT OR REPLACE INTO enrichment_log VALUES (?,?,?,?,datetime('now'))",
        (package_name, G.number_of_nodes(), nodes_with_cve, total_cves),
    )
    conn.commit()

    logging.info(
        f"[DONE] {package_name} — "
        f"{nodes_with_cve}/{G.number_of_nodes()} nodes with CVEs, "
        f"{total_cves} total CVEs"
    )
    return True

# ---------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------

def main():
    conn = init_db()

    with open(PROJECT_LIST, newline="", encoding="utf-8") as f:
        packages = [row["project_name"].strip() for row in csv.DictReader(f)]

    logging.info(f"Enriching {len(packages)} packages")

    success, failed, failed_list = 0, 0, []

    for pkg in packages:
        logging.info(f"[START] {pkg}")
        if enrich_graph(pkg, conn):
            success += 1
        else:
            failed += 1
            failed_list.append(pkg)

    conn.close()

    logging.info("=" * 60)
    logging.info(f"Enriched : {success}")
    logging.info(f"Failed   : {failed}")
    if failed_list:
        logging.warning(f"Failed   : {failed_list}")
    logging.info("=" * 60)


if __name__ == "__main__":
    main()