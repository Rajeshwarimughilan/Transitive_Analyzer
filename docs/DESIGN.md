# TransRisk v2 — Reachability-Gated Transitive Risk Scoring

Design doc. Status: proposed, pending review.

## 1. Why this redesign

The current pipeline (`transrisk.py`, `build_graphs.py`, `enrich_cves.py`) computes a
depth-decayed CVE severity score over a package's transitive dependency graph and
compares it against naive baselines (max/sum/avg CVSS, PageRank). Two problems make it
not worth publishing as-is:

**It's broken.**
- `compute_transrisk` (`transrisk.py:106`) decays by `alpha ** child_depth` — the
  *absolute* depth of the child from the root — not by the single edge just traversed.
  A node at depth 5 gets attenuated by `alpha^6` for a 1-hop contribution to its depth-4
  parent, and that parent's own contribution up the chain repeats the over-penalty. Deep
  subtrees are crushed twice; shallow ones barely decay.
- Child aggregation is a **mean** (`transrisk.py:108`), so a node with one risky
  dependency scores identically to one with ten equally-risky dependencies. This
  suppresses the exact signal ("more risky deps → more risk") the paper needs to show.
- The validation set is broken: `pillow`, `pyyaml`, `numpy` — chosen specifically for
  known incidents — resolve to `total_nodes=1, total_edges=0`. No transitive graph, no
  possible demonstration of hop-based propagation for the cases meant to prove it works.
- `results/all_scores.csv` is empty; the pipeline has never completed end-to-end in this
  checkout (log shows 0/15, stale run order).

**Even fixed, it wouldn't be novel.** Two 2025 papers already occupy "graph position +
severity, evaluated on real CVEs":

- Ruan et al., *Propagation-Based Vulnerability Impact Assessment for Software Supply
  Chains* (arXiv:2506.01342) — breadth/depth-factor composition (not per-edge decay),
  binary Soot-based reachability gate, no EPSS, Java/Maven only.
- *On the Effect of Transitivity and Granularity on Vulnerability Propagation in the
  Maven Ecosystem* (arXiv:2301.07972) — pure binary reachability via OPAL/BFS, no
  scoring formula at all, Java/Maven only.

Both confirmed read in full (not abstract-only). Neither uses Python/PyPI, neither has a
validated per-edge decay + weighted aggregation formula, and **neither uses EPSS**.
Industry tools (Snyk, Endor Labs) treat reachability as the dominant signal and
subordinate depth to it, but no peer-reviewed work formally combines reachability +
corrected graph decay + exploit-likelihood into one validated package-level score. That
combination, on Python/PyPI, is the open gap. See `docs/research/related-work.md`
(§3 below) for the full literature map.

## 2. What the new system computes

For a root package, a single risk score plus a full attribution breakdown per
dependency, from three signals per vulnerable node:

1. **Severity** — CVSS (existing: OSV → NVD lookup, kept).
2. **Exploit likelihood** — EPSS score (new: FIRST.org EPSS API, free, no key required).
3. **Reachability** — is the vulnerable function actually on a call path from the root
   package's import surface (new: static call-graph analysis, Python-specific).

These combine through a **corrected propagation model**: per-edge multiplicative decay
(not absolute depth), weighted-sum child aggregation (not mean), and a reachability gate
that zeroes or down-weights unreachable nodes' contribution.

## 3. Architecture

Keeps the existing 6-stage batch-pipeline shape (it's the right shape for this workload —
no server, no API, just a research pipeline that produces CSVs and figures). Stages
change as follows:

```
01 generate_envs.py     — UNCHANGED (per-package isolated venv, pinned version)
02 generate_sboms.py    — DROP. Dead output today (nothing downstream reads sboms/);
                           CycloneDX data doesn't feed reachability either. Cut it.
03 generate_deptrees.py — UNCHANGED (pipdeptree JSON dump)
04 build_graphs.py      — REWRITE: fix depth computation edge cases (already mostly
                           correct — keep the BFS shortest-path depth fix), drop the
                           `reachability_proxy` heuristic (§5a of the audit — ungrounded,
                           replaced by real reachability in stage 06)
05 enrich_cves.py       — EXTEND: keep OSV/NVD CVSS lookup + SQLite cache, add EPSS
                           lookup (new table `epss_cache`), add OSV "affected function
                           ranges" extraction where available (needed for reachability
                           targeting)
06 build_callgraphs.py  — NEW STAGE: static call-graph construction, scoped to the root
                           package's import surface (not whole-program — see §4.2)
07 transrisk.py         — REWRITE: corrected propagation formula, reachability gating,
                           new baselines (EPSS-alone, reachability-alone)
08 evaluate.py          — NEW (currently referenced but never implemented): ground-truth
                           correlation (Kendall's tau, NDCG), case studies, figures
```

Numbering shifts by one after dropping SBOM generation; keep the numeric prefixes in
filenames this time (`01_generate_envs.py`, etc.) instead of only in header comments —
it's the only reason the current pipeline's run order is legible at all.

## 4. Data model

### 4.1 Graph (networkx.DiGraph, still pickled — fine at this scale)

Node attributes:

| attribute | source | notes |
|---|---|---|
| `depth` | build_graphs (BFS shortest-path from root) | unchanged, this part was correct |
| `version` | build_graphs / enrich_cves | unchanged |
| `is_root` | build_graphs | unchanged |
| `cves` | enrich_cves | list of `{cve_id, cvss_score, cvss_version, affected_functions}` — `affected_functions` is new, pulled from OSV `affected[].ranges`/GHSA data where present, else null |
| `epss` | enrich_cves (new) | max EPSS score across the node's CVEs, `[0,1]` |
| `reachable` | build_callgraphs (new) | bool per-CVE where function-level data exists, else per-package boolean (import reached) as fallback |
| ~~`reachability_proxy`~~ | — | **removed** — replaced by `reachable` |

Drop `reachability_proxy` entirely rather than keep it as a fallback baseline; it's an
ungrounded heuristic and keeping it invites confusing it with real reachability in
figures/tables. If a "no-reachability-data" baseline is wanted, that's just "reachability
= 1 for all nodes" (equivalent to today's unweighted-by-reachability score) — no separate
field needed.

### 4.2 Reachability scope — why not whole-program call graphs

PyCG (arXiv:2103.00587, ~99% precision Python call-graph builder) is explicitly noted in
the literature as not scaling to whole-program analysis (app + all transitive deps).
Don't fight that: scope the call graph to **root package's public API entry points →
call chains into each dependency**, not full whole-program reachability. Concretely:

1. Statically enumerate the root package's top-level module namespace (its own source,
   already available from the isolated venv built in stage 01).
2. Build the call graph starting from those entry points using PyCG (or JARVIS,
   arXiv:2305.05949, if PyCG's precision/recall tradeoff proves worse in practice —
   pilot both on 2-3 packages before committing).
3. For each dependency node with CVE data that includes affected-function info, check:
   is any affected function reachable from an entry-point call chain?
4. Where OSV/GHSA lacks function-level affected-range data (common — expect this to be
   the minority case, not the default), fall back to **import-reachability**: is the
   module even imported anywhere in the reachable call graph, regardless of which
   function. This is weaker than function-level reachability but strictly better than
   assuming reachability=1 for every transitive dependency, which is what the current
   pipeline effectively does.

This needs a pilot before full commitment — run stage 06 against 2-3 packages first
and inspect precision/recall qualitatively before wiring it into the full 15-package (or
larger, see §7) run.

## 5. Propagation algorithm

### 5.1 Corrected decay + aggregation

Replace `transrisk.py:42-112`. Core fix: decay by the single edge being traversed, not
by the child's absolute depth, and aggregate by weighted sum, not mean.

```python
def compute_transrisk(G, root, alpha=DEFAULT_ALPHA, reachability_mode="gate"):
    risk_scores = {}
    order = leaves_to_root_order(G, root)  # unchanged: reverse BFS layers

    for node in order:
        local_risk = local_node_risk(G, node)  # see 5.2

        children = list(G.successors(node))
        propagated = 0.0
        for child in children:
            child_risk = risk_scores.get(child, 0.0)
            propagated += child_risk * alpha   # ONE hop of decay per edge, not alpha**depth

        # weighted sum, not mean: more risky children -> more risk.
        # Optional normalization by log(1+len(children)) to prevent unbounded
        # blowup on very wide fan-out nodes — needs empirical tuning, not a mean.
        risk_scores[node] = round(local_risk + propagated, 6)

    return risk_scores
```

The `alpha ** child_depth` bug is gone by construction: each edge contributes exactly
one factor of `alpha`, and because propagation is recursive (a depth-5 node's risk
already had 5 factors of `alpha` baked in by the time its depth-4 parent uses it), depth
attenuation still compounds correctly across the path — it just no longer double-counts.

Whether the "sum" in weighted-sum should be a raw sum (risk of over-inflating from a
package with many CVE-laden transitive deps) or a dampened sum (e.g. `log(1+n)`-scaled)
is an open tuning question — resolve empirically against the ground-truth dataset (§7),
don't guess a constant.

### 5.2 Local node risk — folding in reachability and EPSS

Replace the CVSS-and-cve-count-only local risk (`transrisk.py:60-63`) with a per-CVE sum
that incorporates reachability and EPSS:

```python
def local_node_risk(G, node):
    total = 0.0
    for cve in G.nodes[node].get("cves", []):
        reach_weight = reachability_weight(cve, G.nodes[node])  # see below
        exploit_weight = cve.get("epss", DEFAULT_EPSS_PRIOR)    # [0,1]
        total += cve["cvss_score"] * exploit_weight * reach_weight
    return total
```

`reachability_weight` should be configurable across three modes, run as an ablation
(this is what makes Option B — the tri-factor ablation — fall out of the same codebase
for free, per the research recommendation):

- `"gate"` — binary: `1.0` if reachable, `0.0` if not (matches how Snyk/Endor Labs treat
  it in practice)
- `"soft"` — continuous: reachable=1.0, import-reachable-only=0.5, unknown=0.75,
  confirmed-unreachable=0.1 (never exactly 0 — static analysis has false negatives)
  — exact constants are a tuning target, not fixed at design time
- `"off"` — always 1.0 (this reproduces today's implicit assumption — the ablation
  baseline showing what reachability *adds*)

Same treatment for EPSS: a `"with_epss"` / `"without_epss"` toggle. This turns the
evaluation directly into the ablation matrix the research recommended (decay-correction ×
reachability × EPSS, each on/off), rather than a single "ours vs. baselines" comparison.

## 6. Baselines (existing + new)

Keep the existing five (`transrisk.py:119-163`): max/sum/avg CVSS, depth-unaware weighted
sum, PageRank-centrality. Add two the research flagged as what reviewers will actually
expect:

- **EPSS-alone** — score = max EPSS across all transitive CVEs, no graph structure at all
- **Reachability-alone** — score = count or max-CVSS of *reachable* CVEs only, no decay

Fix the `alpha` naming collision (`transrisk.py:152`) — PageRank's damping factor and the
propagation decay factor must not share a variable/symbol name in code or in the paper's
notation.

## 7. Ground-truth dataset — fixing the validation-set problem

Current `project_list.csv` picks 15 packages including "known incident" ones
(pillow/pyyaml/numpy) that resolve to trivial graphs — likely because those particular
pinned versions have few/no transitive deps, or the venv resolution step is dropping
edges. Root-cause this (quick check: run `generate_deptrees.py` + `debug_check.py`
manually against one of them and inspect the raw pipdeptree JSON before deciding it's a
pipeline bug vs. a genuinely shallow dependency tree for that version).

Regardless of root cause, the selection methodology itself needs to change:

1. Don't hand-pick 15 packages. Pull incident data from **OSV/GHSA** for PyPI packages
   with disclosed CVEs, cross-reference against **deps.dev** to confirm each has actual
   transitive depth (≥3 hops, ≥20 transitive deps as a floor — tune after inspecting
   distribution) before including it in the dataset.
2. Target a few dozen root packages minimum, not 15 — the closest prior art evaluated on
   100 CVEs (Ruan et al.) or ecosystem-scale (Maven granularity paper); a few dozen with
   real incidents is the realistic floor for a defensible quantitative claim (Kendall's
   tau / NDCG need more than 15 points to mean anything).
3. For each included CVE, record ground truth: was this CVE actually exploited /
   associated with a real incident (not just disclosed)? This is the label the ranking
   metrics are computed against. GHSA "withdrawn"/"reviewed" status and public incident
   reports (Socket.dev/Snyk advisories often reference real exploitation) are usable
   sources — this is manual curation work, budget real time for it.

## 8. Evaluation methodology

- **Ranking correlation**: Kendall's tau and NDCG between each scoring method's ranking
  and the curated incident-severity ground truth, for all 7 methods (5 old baselines + 2
  new + the corrected TransRisk score across ablation modes).
- **Ablation table**: the 2×2×2 matrix from §5.2 (decay-correction × reachability ×
  EPSS), each cell's correlation score — this is the paper's core empirical result and
  directly answers "which part of the model is doing the work," which the research
  flagged as what reviewers now expect (see the FSE'26 GNN attack-chain paper's rigor
  bar) rather than a bare "ours beats baselines."
- **Case studies**: 3-5 real CVEs walked through in detail (own graph, own reachability
  determination, own score vs. baselines) — same device Ruan et al. used with 4 CVEs,
  keep it as a complement to the quantitative table, not a replacement for it.
- **Statistical significance**: report p-values on the correlation results, not just
  point estimates — flagged by the research as expected rigor at target venues.

Target venue: MSR/ICSE-adjacent empirical SE venue, or the SCORED workshop (ACM Supply
Chain Offensive Research and Ecosystem Defenses) — a strong fit for this scope and scale.

## 9. Implementation plan

Rough phases, not a schedule — sequence matters more than dates here:

1. **Pilot reachability on 2-3 packages** (§4.2) before committing to PyCG vs. JARVIS or
   to the whole pipeline shape. This is the highest-uncertainty new component; validate
   it works before building the rest of stage 06 around it.
2. **Fix/rebuild the dataset** (§7) — root-cause the empty-graph problem, then expand
   selection methodology. Do this in parallel with (1); they don't depend on each other.
3. **Rewrite propagation + baselines** (§5, §6) — mechanical once (1) and (2) land;
   write unit tests first on synthetic graphs (linear chain, diamond, wide fan-out, and
   a cycle to confirm it's rejected or handled explicitly — `validate_graph` currently
   lets cycles through with just a warning, which silently corrupts leaves-first
   processing order; decide explicitly whether to reject cycles outright or handle them,
   don't leave it implicit).
4. **EPSS integration** (§5.2, §5) — mechanical, free API, no blockers.
5. **evaluate.py** (§8) — depends on (2) and (3)/(4) being complete.
6. Rotate the leaked NVD API key in `commands.txt` and remove it from source — unrelated
   to the redesign but should happen regardless, independent of the above sequencing.

## 10. Open questions to resolve before/during implementation

- PyCG vs. JARVIS for call-graph construction — pilot both, pick by measured
  precision/recall on a few packages, not by literature reputation alone.
- Exact constants in the `"soft"` reachability-weight mode (§5.2) and whether to dampen
  the weighted-sum aggregation (§5.1) — both are empirical tuning targets against the
  ground-truth dataset, not fixed at design time.
- Minimum dataset size and incident-labeling process (§7) — needs manual curation time
  budgeted, not automatable end-to-end.
- Whether `git init` should happen now, before implementation starts, so the redesign
  has real commit history (currently `.git/` is an empty, uninitialized directory) —
  recommended, orthogonal to everything else above.
