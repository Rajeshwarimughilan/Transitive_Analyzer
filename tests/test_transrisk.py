"""
Unit tests for the corrected propagation algorithm in transrisk.py.

Run with: venv310\\Scripts\\python.exe -m pytest tests\\ -v

These are the tests the v1 pipeline never had (see docs/DESIGN.md §9) —
they exist specifically to pin down the two bugs the redesign fixes
(absolute-depth decay, mean aggregation) so they can't silently come back,
plus the new reachability/EPSS ablation knobs and cycle rejection.
"""

import math
import sys
from pathlib import Path

import networkx as nx
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from transrisk import compute_transrisk, compute_baselines, local_node_risk
from build_graphs import validate_graph


def make_node(cvss=0.0, epss=0.5, reachable=None, depth=0, is_root=False):
    cves = []
    if cvss:
        cves.append({"cve_id": "CVE-TEST", "cvss": cvss, "epss": epss})
    return dict(
        depth=depth, version="1.0", is_root=is_root,
        max_cvss=cvss, cve_count=len(cves), cves=cves, sum_cvss=cvss,
        epss=epss if cvss else 0.0, reachable=reachable,
    )


# ---------------------------------------------------------------------
# Per-edge decay (the absolute-depth bug fix)
# ---------------------------------------------------------------------

def test_linear_chain_decays_per_edge_not_absolute_depth():
    """
    root -> a -> b -> c, only c has a vulnerability.
    v1 bug: c's contribution to b used alpha**depth(c) == alpha**3.
    Correct: each edge contributes exactly one factor of alpha, so c's
    risk reaches root attenuated by alpha**3 via three separate single-hop
    multiplications (c->b, b->a, a->root), not by re-applying c's absolute
    depth at every step.
    """
    alpha = 0.8
    G = nx.DiGraph()
    G.add_node("root", **make_node(is_root=True, reachable=True))
    G.add_node("a", **make_node(depth=1, reachable=True))
    G.add_node("b", **make_node(depth=2, reachable=True))
    G.add_node("c", **make_node(cvss=8.0, epss=1.0, depth=3, reachable=True))
    G.add_edge("root", "a")
    G.add_edge("a", "b")
    G.add_edge("b", "c")

    scores = compute_transrisk(
        G, "root", alpha=alpha, reachability_mode="off",
        use_epss=False, dampen_fanout=False,
    )

    # c's own local risk = cvss * epss(=1, use_epss off->1.0) * reach(=1) = 8.0
    assert scores["c"] == pytest.approx(8.0)
    # b = 0 (no own CVE) + c's risk * alpha (single edge)
    assert scores["b"] == pytest.approx(8.0 * alpha)
    assert scores["a"] == pytest.approx(8.0 * alpha ** 2)
    assert scores["root"] == pytest.approx(8.0 * alpha ** 3)


# ---------------------------------------------------------------------
# Weighted-sum aggregation (the mean-aggregation bug fix)
# ---------------------------------------------------------------------

def test_more_risky_children_means_more_risk():
    """
    v1 used mean(), so a node with 1 risky child scored identically to one
    with 10 equally-risky children. A node with two risky children must
    score strictly higher than a node with only one of them.
    """
    def build(n_children):
        G = nx.DiGraph()
        G.add_node("root", **make_node(is_root=True, reachable=True))
        for i in range(n_children):
            name = f"dep{i}"
            G.add_node(name, **make_node(cvss=7.0, epss=1.0, depth=1, reachable=True))
            G.add_edge("root", name)
        return G

    score_one  = compute_transrisk(
        build(1), "root", reachability_mode="off",
        use_epss=False, dampen_fanout=False,
    )["root"]
    score_two  = compute_transrisk(
        build(2), "root", reachability_mode="off",
        use_epss=False, dampen_fanout=False,
    )["root"]

    assert score_two > score_one


def test_fanout_dampening_still_preserves_monotonicity():
    """dampen_fanout must not flip the direction of the effect above."""
    def build(n_children):
        G = nx.DiGraph()
        G.add_node("root", **make_node(is_root=True, reachable=True))
        for i in range(n_children):
            name = f"dep{i}"
            G.add_node(name, **make_node(cvss=7.0, epss=1.0, depth=1, reachable=True))
            G.add_edge("root", name)
        return G

    score_two  = compute_transrisk(
        build(2), "root", reachability_mode="off",
        use_epss=False, dampen_fanout=True,
    )["root"]
    score_five = compute_transrisk(
        build(5), "root", reachability_mode="off",
        use_epss=False, dampen_fanout=True,
    )["root"]

    assert score_five > score_two


# ---------------------------------------------------------------------
# Diamond dependency — shared child must not be silently dropped/doubled
# ---------------------------------------------------------------------

def test_diamond_dependency_processes_shared_child_once():
    #      root
    #     /    \
    #    a      b
    #     \    /
    #      c (vulnerable)
    G = nx.DiGraph()
    G.add_node("root", **make_node(is_root=True, reachable=True))
    G.add_node("a", **make_node(depth=1, reachable=True))
    G.add_node("b", **make_node(depth=1, reachable=True))
    G.add_node("c", **make_node(cvss=9.0, epss=1.0, depth=2, reachable=True))
    G.add_edge("root", "a")
    G.add_edge("root", "b")
    G.add_edge("a", "c")
    G.add_edge("b", "c")

    scores = compute_transrisk(
        G, "root", alpha=0.8, reachability_mode="off",
        use_epss=False, dampen_fanout=False,
    )

    assert scores["c"] == pytest.approx(9.0)
    assert scores["a"] == pytest.approx(9.0 * 0.8)
    assert scores["b"] == pytest.approx(9.0 * 0.8)
    # root sees c's risk via BOTH a and b — this is intentional (two
    # independent paths genuinely both carry the risk), not a bug.
    assert scores["root"] == pytest.approx(scores["a"] * 0.8 + scores["b"] * 0.8)


# ---------------------------------------------------------------------
# Reachability gating
# ---------------------------------------------------------------------

def test_reachability_gate_zeroes_confirmed_unreachable():
    node = make_node(cvss=9.0, epss=1.0, reachable=False)
    node["cves"][0]["reachable"] = False
    risk = local_node_risk(node, reachability_mode="gate", use_epss=False)
    assert risk == 0.0


def test_reachability_gate_keeps_unknown_at_full_weight():
    node = make_node(cvss=9.0, epss=1.0, reachable=None)
    risk = local_node_risk(node, reachability_mode="gate", use_epss=False)
    assert risk == pytest.approx(9.0)


def test_reachability_soft_mode_never_fully_zeroes():
    node = make_node(cvss=9.0, epss=1.0, reachable=False)
    node["cves"][0]["reachable"] = False
    risk = local_node_risk(node, reachability_mode="soft", use_epss=False)
    assert 0.0 < risk < 9.0


def test_reachability_off_ignores_reachable_flag():
    node = make_node(cvss=9.0, epss=1.0, reachable=False)
    node["cves"][0]["reachable"] = False
    risk = local_node_risk(node, reachability_mode="off", use_epss=False)
    assert risk == pytest.approx(9.0)


# ---------------------------------------------------------------------
# EPSS toggle
# ---------------------------------------------------------------------

def test_epss_scales_local_risk_when_enabled():
    node = make_node(cvss=10.0, epss=0.2, reachable=True)
    risk_with_epss    = local_node_risk(node, reachability_mode="off", use_epss=True)
    risk_without_epss = local_node_risk(node, reachability_mode="off", use_epss=False)
    assert risk_with_epss == pytest.approx(10.0 * 0.2)
    assert risk_without_epss == pytest.approx(10.0)


# ---------------------------------------------------------------------
# Cycle rejection (validate_graph)
# ---------------------------------------------------------------------

def test_validate_graph_rejects_cycles():
    G = nx.DiGraph()
    G.add_node("root", **make_node(is_root=True))
    G.add_node("a", **make_node(depth=1))
    G.add_node("b", **make_node(depth=2))
    G.add_edge("root", "a")
    G.add_edge("a", "b")
    G.add_edge("b", "a")  # cycle

    assert validate_graph(G, "root") is False


def test_validate_graph_accepts_dag():
    G = nx.DiGraph()
    G.add_node("root", **make_node(is_root=True))
    G.add_node("a", **make_node(depth=1))
    G.add_edge("root", "a")

    assert validate_graph(G, "root") is True


# ---------------------------------------------------------------------
# alpha / pagerank_damping naming collision fix
# ---------------------------------------------------------------------

def test_baselines_accept_independent_pagerank_damping():
    G = nx.DiGraph()
    G.add_node("root", **make_node(is_root=True, reachable=True))
    G.add_node("a", **make_node(cvss=5.0, depth=1, reachable=True))
    G.add_edge("root", "a")

    # Must not raise, and must not be confused with propagation alpha —
    # this just exercises the renamed parameter.
    result = compute_baselines(G, "root", pagerank_damping=0.5)
    assert "baseline_centrality" in result
    assert "baseline_epss_alone" in result
    assert "baseline_reachability_alone" in result
