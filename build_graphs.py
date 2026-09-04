# 04_build_graphs.py

import csv
import json
import logging
import pickle

import networkx as nx
import pandas as pd

from config import (
    DEPTREES_DIR,
    GRAPHS_DIR,
    PROJECT_LIST,
    RESULTS_DIR,
    LOGS_DIR,
    TOOL_PACKAGES,
)

# ---------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------

LOGS_DIR.mkdir(parents=True, exist_ok=True)
GRAPHS_DIR.mkdir(parents=True, exist_ok=True)
RESULTS_DIR.mkdir(parents=True, exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    handlers=[
        logging.FileHandler(
            str(LOGS_DIR / "04_build_graphs.log"), encoding="utf-8"
        ),
        logging.StreamHandler(),
    ],
)

# ---------------------------------------------------------------------
# Graph Construction
# ---------------------------------------------------------------------

def find_root_entry(tree: list, package_name: str) -> dict | None:
    """
    Case-insensitive, hyphen/underscore-normalized root match.
    Same logic as generate_deptrees.py for consistency.
    """
    normalized = package_name.lower().replace("-", "_")

    # Pass 1 — exact normalized match
    for entry in tree:
        entry_name = entry.get("package_name", "").lower().replace("-", "_")
        if entry_name == normalized:
            return entry

    # Pass 2 — fallback: first non-tool entry
    logging.warning(
        f"[WARN] '{package_name}' not found as root. "
        f"Available: {[e.get('package_name') for e in tree]}"
    )
    return None


def build_graph(package_name: str, tree: list) -> nx.DiGraph | None:
    """
    Builds a directed dependency graph from a pipdeptree JSON tree.

    Nodes carry:
      depth      — hops from root (0 = root)
      version    — installed version string
      is_root    — True only for the root package
      max_cvss   — filled by enrich_cves.py
      cve_count  — filled by enrich_cves.py
      cves       — filled by enrich_cves.py (each entry may carry epss, affected_functions)
      sum_cvss   — filled by enrich_cves.py
      epss       — filled by enrich_cves.py (max EPSS across the node's CVEs)
      reachable  — filled by build_callgraphs.py; None until that stage runs
                   (True/False/None — None means "not yet analyzed", not
                   "assumed reachable"; see docs/DESIGN.md §4.1)

    Returns None if the tree is empty or root cannot be found.
    """
    G = nx.DiGraph()
    root = package_name.lower()

    G.add_node(root,
        depth=0,
        version="",
        is_root=True,
        max_cvss=0.0,
        cve_count=0,
        cves=[],
        sum_cvss=0.0,
        epss=0.0,
        reachable=True,   # the root is trivially reachable from itself
    )

    def recurse(parent: str, deps: list, depth: int):
        for dep in deps:
            child   = dep.get("package_name", "").lower().replace("-", "_")
            version = dep.get("installed_version", "")

            if not child:
                continue

            if not G.has_node(child):
                G.add_node(child,
                    depth=depth,
                    version=version,
                    is_root=False,
                    max_cvss=0.0,
                    cve_count=0,
                    cves=[],
                    sum_cvss=0.0,
                    epss=0.0,
                    reachable=None,
                )

            if not G.has_edge(parent, child):
                G.add_edge(parent, child)

            if dep.get("dependencies"):
                recurse(child, dep["dependencies"], depth + 1)

    root_entry = find_root_entry(tree, package_name)

    if root_entry is None:
        logging.error(f"[FAIL] {package_name} — cannot find root entry in tree")
        return None

    recurse(root, root_entry.get("dependencies", []), depth=1)

    # Recompute shortest-path depth from root
    # Handles diamond dependencies correctly — a node reachable via two
    # paths gets the shorter depth, not whichever was visited first
    depths = nx.single_source_shortest_path_length(G, root)
    nx.set_node_attributes(G, depths, "depth")

    return G


# ---------------------------------------------------------------------
# Graph Validation
# ---------------------------------------------------------------------

def validate_graph(G: nx.DiGraph, package_name: str) -> bool:
    """
    A valid graph must have:
    - More than 1 node (root + at least one dependency)
    - At least 1 edge
    - Be a DAG

    Cycles are a hard failure, not a warning. compute_transrisk() processes
    nodes leaves-first via reverse BFS layers, which is only well-defined on
    a DAG; on a cyclic graph some nodes would be processed before their
    children finish, silently defaulting those contributions to 0 with no
    indication anything was wrong (see docs/DESIGN.md §9). pipdeptree/PyPI
    dependency graphs can contain cycles in principle, so surface it here
    rather than let it corrupt scores downstream.
    """
    if G.number_of_nodes() <= 1:
        logging.warning(
            f"[WARN] {package_name} graph has only 1 node — "
            f"dependency tree may be empty or package has no dependencies"
        )
        # Not a hard failure — some packages (e.g. numpy) have minimal deps
        # But flag it so we can inspect
        return True   # allow it through, just warn

    if G.number_of_edges() == 0:
        logging.error(f"[FAIL] {package_name} graph has nodes but no edges")
        return False

    if not nx.is_directed_acyclic_graph(G):
        cycle = nx.find_cycle(G)
        logging.error(
            f"[FAIL] {package_name} graph contains a cycle: {cycle} — "
            f"leaves-first propagation order is undefined on cyclic graphs"
        )
        return False

    return True


# ---------------------------------------------------------------------
# Statistics
# ---------------------------------------------------------------------

def get_graph_stats(G: nx.DiGraph, package_name: str) -> dict:
    root   = package_name.lower()
    depths = list(nx.get_node_attributes(G, "depth").values())

    return {
        "project":      package_name,
        "total_nodes":  G.number_of_nodes(),
        "total_edges":  G.number_of_edges(),
        "direct_deps":  len(list(G.successors(root))) if root in G else 0,
        "max_depth":    max(depths) if depths else 0,
        "avg_depth":    round(sum(depths) / len(depths), 2) if depths else 0,
        "is_dag":       nx.is_directed_acyclic_graph(G),
        # nodes_with_cve is NOT available at this stage — enrich_cves.py runs
        # after this and never regenerates dataset_stats.csv. Previously this
        # was a hardcoded 0 left in every row of the paper's Table 1 dataset
        # stats, silently wrong for every package. Dropped rather than kept
        # as a stale placeholder; evaluate.py should compute it from the
        # enriched graphs directly once stage 06/07 has run.
    }


# ---------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------

def main():
    with open(PROJECT_LIST, newline="", encoding="utf-8") as f:
        packages = [row["project_name"].strip() for row in csv.DictReader(f)]

    logging.info(f"Building graphs for {len(packages)} packages")

    stats_table          = []
    success, failed      = 0, 0
    failed_list          = []

    for package in packages:
        tree_path  = DEPTREES_DIR / f"{package}_tree.json"
        graph_path = GRAPHS_DIR   / f"{package}_graph.pkl"

        if not tree_path.exists():
            logging.error(f"[SKIP] {package} — tree not found, run 03 first")
            failed += 1
            failed_list.append(package)
            continue

        try:
            with open(tree_path, encoding="utf-8") as f:
                tree = json.load(f)

            if not tree:
                logging.error(
                    f"[SKIP] {package} — tree file is empty list. "
                    f"Delete {tree_path.name} and re-run 03."
                )
                failed += 1
                failed_list.append(package)
                continue

            G = build_graph(package, tree)

            if G is None:
                failed += 1
                failed_list.append(package)
                continue

            if not validate_graph(G, package):
                failed += 1
                failed_list.append(package)
                continue

            with open(graph_path, "wb") as f:
                pickle.dump(G, f)

            stats = get_graph_stats(G, package)
            stats_table.append(stats)

            logging.info(
                f"[DONE] {package} — "
                f"{G.number_of_nodes()} nodes, "
                f"{G.number_of_edges()} edges, "
                f"max_depth={stats['max_depth']}"
            )
            success += 1

        except Exception:
            logging.exception(f"Unexpected error processing {package}")
            failed += 1
            failed_list.append(package)

    # Save dataset stats — this becomes Table 1 in your paper
    if stats_table:
        pd.DataFrame(stats_table).to_csv(
            RESULTS_DIR / "dataset_stats.csv", index=False
        )
        logging.info("Saved dataset_stats.csv")

    logging.info("=" * 60)
    logging.info(f"Graphs Built : {success}")
    logging.info(f"Failures     : {failed}")
    if failed_list:
        logging.warning(f"Failed : {failed_list}")
    logging.info("=" * 60)


if __name__ == "__main__":
    main()
