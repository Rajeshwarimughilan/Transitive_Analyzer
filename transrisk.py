# 07_transrisk.py

import csv
import logging
import math
import pickle

import networkx as nx
import pandas as pd

from config import (
    GRAPHS_DIR,
    RESULTS_DIR,
    PROJECT_LIST,
    LOGS_DIR,
    ALPHA_VALUES,
    DEFAULT_ALPHA,
)

# ---------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------

LOGS_DIR.mkdir(parents=True, exist_ok=True)
RESULTS_DIR.mkdir(parents=True, exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    handlers=[
        logging.FileHandler(
            str(LOGS_DIR / "07_transrisk.log"), encoding="utf-8"
        ),
        logging.StreamHandler(),
    ],
)

# ---------------------------------------------------------------------
# Reachability weighting — the ablation knob
#
# v1 assumed every transitive dependency is equally "reachable" (the
# reachability_proxy heuristic, since removed — see docs/DESIGN.md §4.1).
# v2 makes reachability a real, measured signal (build_callgraphs.py sets
# node["reachable"] to True/False/None) and lets the weighting mode be
# swapped at evaluation time, so the same pipeline run produces the full
# ablation matrix (decay-correction x reachability x EPSS) instead of a
# single point estimate. See docs/DESIGN.md §5.2 and §8.
# ---------------------------------------------------------------------

DEFAULT_EPSS_PRIOR = 0.5  # used only when a CVE has no EPSS data at all

REACHABILITY_WEIGHTS_SOFT = {
    True:  1.0,   # confirmed reachable via call-graph analysis
    False: 0.1,   # confirmed unreachable — never exactly 0, static analysis
                  # has false negatives (dynamic imports, reflection, etc.)
    None:  0.75,  # not yet analyzed / no function-level data to check against
}


def reachability_weight(cve: dict, node_attrs: dict, mode: str = "gate") -> float:
    """
    mode:
      "off"  — reachability is ignored (reproduces the old implicit
               assumption that every transitive dependency is fully
               reachable; this is the ablation baseline showing what
               reachability *adds*)
      "gate" — binary: 1.0 if reachable, 0.0 if confirmed unreachable,
               1.0 if unknown (matches industry practice of only
               suppressing what's positively ruled out — see Snyk/Endor
               Labs treatment described in docs/DESIGN.md §1)
      "soft" — continuous weighting per REACHABILITY_WEIGHTS_SOFT
    """
    if mode == "off":
        return 1.0

    reachable = node_attrs.get("reachable")
    # Function-level reachability (per-CVE) takes precedence over the
    # node-level fallback once build_callgraphs.py starts populating it.
    if cve.get("reachable") is not None:
        reachable = cve["reachable"]

    if mode == "gate":
        return 0.0 if reachable is False else 1.0
    if mode == "soft":
        return REACHABILITY_WEIGHTS_SOFT.get(reachable, 0.75)

    raise ValueError(f"Unknown reachability_mode: {mode!r}")


# ---------------------------------------------------------------------
# Local node risk — severity x exploit-likelihood x reachability,
# summed per CVE (a node with 5 CVEs is riskier than one with 1, unlike
# v1's log(1+cve_count) saturation which barely distinguished them)
# ---------------------------------------------------------------------

def local_node_risk(
    node_attrs: dict,
    reachability_mode: str = "gate",
    use_epss: bool = True,
) -> float:
    total = 0.0
    for cve in node_attrs.get("cves", []):
        cvss = cve.get("cvss", 0.0)
        epss = cve.get("epss", DEFAULT_EPSS_PRIOR) if use_epss else 1.0
        if use_epss and not epss:
            epss = DEFAULT_EPSS_PRIOR
        reach = reachability_weight(cve, node_attrs, mode=reachability_mode)
        total += cvss * epss * reach
    return total


# ---------------------------------------------------------------------
# TransRisk propagation algorithm
# ---------------------------------------------------------------------

def compute_transrisk(
    G: nx.DiGraph,
    root: str,
    alpha: float = DEFAULT_ALPHA,
    reachability_mode: str = "gate",
    use_epss: bool = True,
    dampen_fanout: bool = True,
) -> dict:
    """
    Processes nodes leaves-first (reverse BFS order) so every child's risk
    score is finalized before its parent is computed. Requires G to be a
    DAG — build_graphs.validate_graph() rejects cyclic graphs before they
    reach this stage (see docs/DESIGN.md §9).

    For each node v, with children c1..cn:

        LocalRisk(v) = sum_i( cvss_i * epss_i * reachability_weight_i )
                       over v's own CVEs

        PropagatedRisk(v) = sum_j( risk(c_j) * alpha )
                       — ONE factor of alpha per edge traversed, not
                       alpha ** absolute_depth(c_j). This is the fix for
                       the v1 bug (transrisk.py, old line 106): depth
                       attenuation still compounds correctly across a path
                       because each edge's factor is folded into the
                       child's already-computed risk score recursively —
                       it just no longer double-counts a deep node's own
                       depth on top of every ancestor's absolute depth too.

        Risk(v) = LocalRisk(v) + PropagatedRisk(v)     [optionally dampened,
                                                          see dampen_fanout]

    v1 aggregated children by MEAN, which made a node with one risky
    dependency score identically to one with ten equally-risky
    dependencies — directly contradicting "more risky deps = more risk".
    v2 sums instead. dampen_fanout applies a log(1+n) divisor to the
    summed contribution to prevent unbounded blowup on very wide fan-out
    nodes (e.g. a package with 200 direct deps) while still preserving the
    monotonic "more/riskier deps -> higher score" property a pure mean
    destroys. Whether dampening is warranted, and by how much, is an
    empirical question — see docs/DESIGN.md §5.1 — so it's a toggle, not
    baked in silently.

    Returns:
        dict mapping node_name -> risk_score for all nodes in G
    """
    risk_scores = {}

    try:
        bfs_layers = dict(enumerate(nx.bfs_layers(G, root)))
    except Exception as e:
        logging.error(f"BFS failed for {root}: {e}")
        return {}

    processing_order = []
    for layer_idx in sorted(bfs_layers.keys(), reverse=True):
        processing_order.extend(bfs_layers[layer_idx])

    for node in processing_order:
        node_attrs = G.nodes[node]
        local_risk = local_node_risk(
            node_attrs, reachability_mode=reachability_mode, use_epss=use_epss
        )

        children = list(G.successors(node))
        propagated = 0.0
        if children:
            contributions = [
                risk_scores.get(child, 0.0) * alpha
                for child in children
            ]
            summed = sum(contributions)
            propagated = (
                summed / math.log(1 + len(children) + 1)
                if dampen_fanout
                else summed
            )

        risk_scores[node] = round(local_risk + propagated, 6)

    return risk_scores


# ---------------------------------------------------------------------
# Baselines
# ---------------------------------------------------------------------

def compute_baselines(G: nx.DiGraph, root: str, pagerank_damping: float = 0.85) -> dict:
    """
    Seven baselines for comparison against TransRisk.

    B1 — Max CVSS        : standard scanner output (flat, depth-unaware)
    B2 — Sum CVSS        : aggregate all severities (size-biased)
    B3 — Average CVSS    : mean severity across all deps
    B4 — Depth-unaware   : local risk sum without propagation
    B5 — Centrality risk : PageRank-weighted severity score
    B6 — EPSS-alone      : max exploit-likelihood across all transitive
                            CVEs, no graph structure at all
    B7 — Reachability-alone : max CVSS among only the CVEs whose
                            reachability is confirmed True (or unknown),
                            i.e. severity with unreachable findings
                            dropped, but no hop-decay

    B6/B7 are the two comparators the literature review flagged as what
    reviewers will actually expect alongside the classic five — EPSS and
    reachability are the dominant signals in industry practice (Snyk,
    Endor Labs) and neither existed in v1. See docs/DESIGN.md §6.

    Note: pagerank_damping is PageRank's own damping factor, unrelated to
    the propagation decay `alpha` above — v1 reused the name `alpha` for
    both, which is confusing when read alongside the paper's notation.
    """
    non_root = [n for n in G.nodes() if n != root]

    if not non_root:
        return {
            "baseline_max_cvss":      0.0,
            "baseline_sum_cvss":      0.0,
            "baseline_avg_cvss":      0.0,
            "baseline_depth_unaware": 0.0,
            "baseline_centrality":    0.0,
            "baseline_epss_alone":    0.0,
            "baseline_reachability_alone": 0.0,
        }

    all_cvss = [G.nodes[n].get("max_cvss", 0.0) for n in non_root]
    all_epss = [G.nodes[n].get("epss", 0.0) for n in non_root]

    b1 = max(all_cvss, default=0.0)
    b2 = sum(all_cvss)
    b3 = sum(all_cvss) / len(all_cvss)
    b4 = sum(
        G.nodes[n].get("max_cvss", 0.0)
        * math.log(1 + G.nodes[n].get("cve_count", 0))
        for n in non_root
    )

    try:
        pr = nx.pagerank(G, alpha=pagerank_damping)
        b5 = sum(pr[n] * G.nodes[n].get("max_cvss", 0.0) for n in non_root)
    except Exception:
        b5 = 0.0

    b6 = max(all_epss, default=0.0)

    reachable_cvss = [
        G.nodes[n].get("max_cvss", 0.0)
        for n in non_root
        if G.nodes[n].get("reachable") is not False
    ]
    b7 = max(reachable_cvss, default=0.0)

    return {
        "baseline_max_cvss":      round(b1, 4),
        "baseline_sum_cvss":      round(b2, 4),
        "baseline_avg_cvss":      round(b3, 4),
        "baseline_depth_unaware": round(b4, 4),
        "baseline_centrality":    round(b5, 4),
        "baseline_epss_alone":    round(b6, 4),
        "baseline_reachability_alone": round(b7, 4),
    }


# ---------------------------------------------------------------------
# Per-node breakdown (needed for paper figures)
# ---------------------------------------------------------------------

def compute_node_breakdown(
    G: nx.DiGraph,
    root: str,
    risk_scores: dict,
    package_name: str,
    alpha: float,
) -> list:
    """
    Returns per-node risk data for all non-root nodes.
    Used to generate:
      - Figure: depth vs risk contribution
      - Figure: reachability distribution
      - Case study tables
    """
    rows = []
    for node in G.nodes():
        if node == root:
            continue
        rows.append({
            "project":         package_name,
            "alpha":           alpha,
            "node":            node,
            "depth":           G.nodes[node].get("depth", 0),
            "version":         G.nodes[node].get("version", ""),
            "cve_count":       G.nodes[node].get("cve_count", 0),
            "max_cvss":        G.nodes[node].get("max_cvss", 0.0),
            "sum_cvss":        G.nodes[node].get("sum_cvss", 0.0),
            "epss":            G.nodes[node].get("epss", 0.0),
            "reachable":       G.nodes[node].get("reachable"),
            "node_risk_score": risk_scores.get(node, 0.0),
            "in_degree":       G.in_degree(node),
            "out_degree":      G.out_degree(node),
        })
    return rows


# ---------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------

def main():
    with open(PROJECT_LIST, newline="", encoding="utf-8") as f:
        packages = [row["project_name"].strip() for row in csv.DictReader(f)]

    logging.info(f"Running TransRisk on {len(packages)} packages")

    all_scores    = []   # one row per (project, alpha)
    all_nodes     = []   # one row per (project, alpha, node) — for figures
    failed_list   = []

    for pkg in packages:
        graph_path = GRAPHS_DIR / f"{pkg}_graph.pkl"

        if not graph_path.exists():
            logging.error(f"[SKIP] {pkg} — graph not found, run 04 first")
            failed_list.append(pkg)
            continue

        try:
            with open(graph_path, "rb") as f:
                G = pickle.load(f)
        except Exception as e:
            logging.error(f"[FAIL] Could not load graph for {pkg}: {e}")
            failed_list.append(pkg)
            continue

        root      = pkg.lower()
        baselines = compute_baselines(G, root)

        # Quick sanity check — warn if no CVE data found
        cve_nodes = [
            n for n in G.nodes()
            if G.nodes[n].get("cve_count", 0) > 0
        ]
        if not cve_nodes:
            logging.warning(
                f"[WARN] {pkg} — no nodes have CVE data. "
                f"Run 05_enrich_cves.py first, or check OSV returned results."
            )

        for alpha in ALPHA_VALUES:
            risk_scores = compute_transrisk(G, root, alpha=alpha)
            transrisk_score = risk_scores.get(root, 0.0)

            all_scores.append({
                "project":         pkg,
                "alpha":           alpha,
                "transrisk_score": transrisk_score,
                "nodes_total":     G.number_of_nodes(),
                "nodes_with_cve":  len(cve_nodes),
                **baselines,
            })

            # Collect per-node breakdown only for default alpha
            # (avoids 3x bloat in node CSV — sensitivity analysis
            #  is at project level, not node level)
            if alpha == DEFAULT_ALPHA:
                node_rows = compute_node_breakdown(
                    G, root, risk_scores, pkg, alpha
                )
                all_nodes.extend(node_rows)

            logging.info(
                f"[{pkg}] alpha={alpha} -> "
                f"TransRisk={transrisk_score:.4f} | "
                f"MaxCVSS={baselines['baseline_max_cvss']:.1f} | "
                f"CVE_nodes={len(cve_nodes)}"
            )

    # Save project-level scores — main results table
    scores_path = RESULTS_DIR / "all_scores.csv"
    pd.DataFrame(all_scores).to_csv(scores_path, index=False)
    logging.info(f"Saved {scores_path.name} ({len(all_scores)} rows)")

    # Save node-level breakdown — used for paper figures
    nodes_path = RESULTS_DIR / "node_breakdown.csv"
    pd.DataFrame(all_nodes).to_csv(nodes_path, index=False)
    logging.info(f"Saved {nodes_path.name} ({len(all_nodes)} rows)")

    logging.info("=" * 60)
    logging.info(f"Completed : {len(packages) - len(failed_list)}/{len(packages)}")
    if failed_list:
        logging.warning(f"Failed    : {failed_list}")
    logging.info("=" * 60)


if __name__ == "__main__":
    main()
