#!/usr/bin/env python3
"""Turn the CSV results into paper-ready tables (results/summary.md) and figures (results/*.png).

    python experiments/analyze.py            # uses whatever CSVs exist in results/

Statistics: detection rates with Wilson 95% intervals; delays as median / p95 / mean with a 95% CI of
the mean; paired Wilcoxon signed-rank test (live vs batch) on delays measured on identical runs.
"""
import csv
import json
import math
import os
import statistics
import sys
from collections import defaultdict

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
from scipy import stats  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RES = os.path.join(ROOT, "results")


def read(name):
    p = os.path.join(RES, name)
    if not os.path.exists(p):
        return None
    with open(p, newline="") as f:
        return list(csv.DictReader(f))


def wilson(k, n, z=1.96):
    if n == 0:
        return (0.0, 0.0)
    p = k / n
    d = 1 + z * z / n
    c = p + z * z / (2 * n)
    m = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n))
    return ((c - m) / d, (c + m) / d)


def pct(xs, p):
    xs = sorted(xs)
    return xs[min(len(xs) - 1, int(p * (len(xs) - 1) + 0.5))]


def mean_ci(xs):
    if len(xs) < 2:
        return (xs[0] if xs else float("nan"), 0.0)
    return statistics.mean(xs), 1.96 * statistics.stdev(xs) / math.sqrt(len(xs))


def fmt_rate(k, n):
    lo, hi = wilson(k, n)
    return "%d/%d = %.0f%% [%.0f-%.0f]" % (k, n, 100.0 * k / max(n, 1), 100 * lo, 100 * hi)


def main():
    out = ["# Results summary\n"]
    sim = read("simulation.csv")
    if sim:
        out.append("## 1. Detection coverage (offline simulation)\n")
        out.append("Detection = an ACTIVE alert (rules: any rule hit) on the attack. 'covered' families are the five "
                   "techniques simple stateless rules were written for; 'uncovered' ones are not. 95% Wilson intervals.\n")
        out.append("| family | live engine | batch scan 15 min | batch scan 60 min | stateless rules |")
        out.append("|---|---|---|---|---|")
        for fam in ("covered", "uncovered"):
            cells = []
            for mode, iv in (("live", "0"), ("batch", "900"), ("batch", "3600"), ("rules", "0")):
                rows = [r for r in sim if r["family"] == fam and r["mode"] == mode and r["interval_s"] == iv]
                cells.append(fmt_rate(sum(int(r["detected"]) for r in rows), len(rows)))
            out.append("| %s | %s |" % (fam, " | ".join(cells)))
        out.append("\nAttribution (names the origin identity and the full path): live engine and batch scan: yes, "
                   "stateless rules: never.\n")
        out.append("## 2. Model staleness: delay between the last attack step and the alert (seconds, simulation)\n")
        out.append("Excludes the CloudTrail delivery delay that every approach shares. Live = alert on arrival of the event.\n")
        out.append("| mode | n | median | p95 | mean ± 95% CI |")
        out.append("|---|---|---|---|---|")
        by_mode = defaultdict(list)
        for r in sim:
            if r["detected"] == "1" and r["staleness_s"] != "":
                by_mode[(r["mode"], r["interval_s"])].append(float(r["staleness_s"]))
        for key in sorted(by_mode, key=lambda k: (k[0], int(k[1]))):
            xs = by_mode[key]
            m, ci = mean_ci(xs)
            label = "live" if key[0] == "live" else ("batch %d min" % (int(key[1]) // 60) if key[0] == "batch" else "rules")
            out.append("| %s | %d | %.1f | %.1f | %.1f ± %.1f |" % (label, len(xs), statistics.median(xs), pct(xs, 0.95), m, ci))
        paired = defaultdict(dict)
        for r in sim:
            if r["detected"] == "1" and r["staleness_s"] != "":
                paired[(r["scenario"], r["rep"])][(r["mode"], r["interval_s"])] = float(r["staleness_s"])
        out.append("\nPaired Wilcoxon signed-rank (live vs batch, same runs):\n")
        for iv in ("300", "900", "1800", "3600"):
            pairs = [(v[("live", "0")], v[("batch", iv)]) for v in paired.values() if ("live", "0") in v and ("batch", iv) in v]
            if len(pairs) > 5 and any(a != b for a, b in pairs):
                stat, p = stats.wilcoxon([a for a, _ in pairs], [b for _, b in pairs])
                out.append("- batch %d min: n=%d, W=%.1f, p=%.2g" % (int(iv) // 60, len(pairs), stat, p))
        # figure: CDF of staleness
        plt.figure(figsize=(6, 3.6))
        for key in sorted(by_mode, key=lambda k: (k[0], int(k[1]))):
            xs = sorted(by_mode[key])
            label = "live" if key[0] == "live" else ("batch %d min" % (int(key[1]) // 60) if key[0] == "batch" else "rules")
            plt.step(xs, [i / len(xs) for i in range(1, len(xs) + 1)], where="post", label=label)
        plt.xscale("symlog", linthresh=10)
        plt.xlabel("seconds from last attack step to alert (CloudTrail delay excluded)")
        plt.ylabel("fraction of detections")
        plt.legend(fontsize=7)
        plt.grid(alpha=.3)
        plt.tight_layout()
        plt.savefig(os.path.join(RES, "fig_staleness_cdf.png"), dpi=160)
        plt.close()
    aw = read("awareness.csv")
    if aw:
        out.append("\n## 3. Fresh misconfiguration: time until a newly created dangerous path is known (seconds)\n")
        out.append("| mode | n | median | p95 | mean ± 95% CI |")
        out.append("|---|---|---|---|---|")
        g = defaultdict(list)
        for r in aw:
            g[(r["mode"], r["interval_s"])].append(float(r["awareness_s"]))
        for key in sorted(g, key=lambda k: (k[0], int(k[1]))):
            xs = g[key]
            m, ci = mean_ci(xs)
            label = "live" if key[0] == "live" else "batch %d min" % (int(key[1]) // 60)
            out.append("| %s | %d | %.1f | %.1f | %.1f ± %.1f |" % (label, len(xs), statistics.median(xs), pct(xs, .95), m, ci))
    fa = read("falsealerts.csv")
    if fa:
        out.append("\n## 4. False alerts on a benign workload (about 90 events per run)\n")
        n = len(fa)
        for col, label in (("live_active", "live engine ACTIVE"), ("live_watch", "live engine WATCH (ticket-level)"),
                           ("batch900_active", "batch 15 min ACTIVE"), ("rules", "stateless rules")):
            xs = [int(r[col]) for r in fa]
            out.append("- %s: mean %.2f per run (max %d, %d runs)" % (label, statistics.mean(xs), max(xs), n))
    sc = read("scaling.csv")
    if sc:
        out.append("\n## 5. Graph layer scaling (synthetic graphs; ms per single change)\n")
        out.append("| nodes | operation | exact update median / p95 | k-ball update median | full rebuild | nodes touched (exact, median / max) |")
        out.append("|---|---|---|---|---|---|")
        idx = defaultdict(dict)
        for r in sc:
            idx[(int(r["nodes"]), r["op"])][r["algorithm"]] = r
        for key in sorted(idx):
            e, b = idx[key].get("exact"), idx[key].get("ball")
            if e and b:
                out.append("| %d | %s | %s / %s | %s | %s | %s / %s |" % (
                    key[0], key[1], e["update_ms_median"], e["update_ms_p95"], b["update_ms_median"],
                    e["full_rebuild_ms"], e["touched_median"], e["touched_max"]))
        plt.figure(figsize=(6, 3.6))
        for op in ("insert", "delete", "hub_insert"):
            pts = sorted((int(r["nodes"]), float(r["update_ms_median"])) for r in sc if r["op"] == op and r["algorithm"] == "exact")
            if pts:
                plt.plot([p[0] for p in pts], [p[1] for p in pts], marker="o", label="exact update: " + op)
        pts = sorted({(int(r["nodes"]), float(r["full_rebuild_ms"])) for r in sc})
        plt.plot([p[0] for p in pts], [p[1] for p in pts], "k--", marker="s", label="full rebuild")
        plt.xscale("log"); plt.yscale("log")
        plt.xlabel("nodes"); plt.ylabel("ms per change (median)")
        plt.legend(fontsize=7); plt.grid(alpha=.3, which="both"); plt.tight_layout()
        plt.savefig(os.path.join(RES, "fig_scaling_graph.png"), dpi=160)
        plt.close()
    es = read("engine_scaling.csv")
    if es:
        out.append("\n## 6. Engine scaling: one IAM event vs full re-derivation of all edges (synthetic accounts)\n")
        out.append("| principals | event type | event median ms | p95 ms | principals recomputed | full rebuild ms | speed-up |")
        out.append("|---|---|---|---|---|---|---|")
        for r in es:
            out.append("| %s | %s | %s | %s | %s | %s | x%.0f |" % (
                r["principals"], r["event"], r["event_ms_median"], r["event_ms_p95"], r["recomputed_nodes_median"],
                r["full_rebuild_ms"], float(r["speedup_median"])))
        plt.figure(figsize=(6, 3.6))
        for ev in sorted({r["event"] for r in es}):
            pts = sorted((int(r["principals"]), float(r["event_ms_median"])) for r in es if r["event"] == ev)
            plt.plot([p[0] for p in pts], [p[1] for p in pts], marker="o", label=ev)
        pts = sorted({(int(r["principals"]), float(r["full_rebuild_ms"])) for r in es})
        plt.plot([p[0] for p in pts], [p[1] for p in pts], "k--", marker="s", label="full rebuild")
        plt.xscale("log"); plt.yscale("log")
        plt.xlabel("principals"); plt.ylabel("ms (median)")
        plt.legend(fontsize=6); plt.grid(alpha=.3, which="both"); plt.tight_layout()
        plt.savefig(os.path.join(RES, "fig_scaling_engine.png"), dpi=160)
        plt.close()
    real = read("attacks_real.csv")
    if real:
        out.append("\n## 7. Real AWS runs (deployed stack)\n")
        by = defaultdict(list)
        for r in real:
            by[r["scenario"]].append(r)
        out.append("| scenario | runs | detected | rules detected | median total s | p95 total s | median delivery s | median queue s | median processing s |")
        out.append("|---|---|---|---|---|---|---|---|---|")
        allt = []
        for k in sorted(by):
            rs = by[k]
            det = [r for r in rs if r["detected"] == "1"]
            tot = [float(r["total_s"]) for r in det if r.get("total_s")]
            allt += tot
            col = lambda c: [float(r[c]) for r in det if r.get(c)]
            med = lambda xs: "%.1f" % statistics.median(xs) if xs else "-"
            out.append("| %s | %d | %s | %d/%d | %s | %s | %s | %s | %s |" % (
                k, len(rs), fmt_rate(len(det), len(rs)), sum(int(r["rules_detected"]) for r in rs), len(rs), med(tot),
                "%.1f" % pct(tot, .95) if tot else "-", med(col("delivery_s")), med(col("queue_s")), med(col("processing_s"))))
        bs = os.path.join(RES, "batch_scan.json")
        if os.path.exists(bs):
            b = json.load(open(bs))
            out.append("\nBatch scan runtime here: %.2f s. A scheduled scan every T minutes detects a new state after "
                       "T/2 + %.1f s on average and T + %.1f s at worst (plus the same CloudTrail delay):\n" % (b["runtime_s"], b["runtime_s"], b["runtime_s"]))
            for t in (15, 30, 60):
                out.append("- every %d min: mean %.0f s, worst %.0f s" % (t, t * 30 + b["runtime_s"], t * 60 + b["runtime_s"]))
        if allt:
            plt.figure(figsize=(6, 3.2))
            xs = sorted(allt)
            plt.step(xs, [i / len(xs) for i in range(1, len(xs) + 1)], where="post")
            plt.xlabel("seconds from last attack step (CloudTrail eventTime) to alert")
            plt.ylabel("fraction of detections"); plt.grid(alpha=.3); plt.tight_layout()
            plt.savefig(os.path.join(RES, "fig_real_latency_cdf.png"), dpi=160)
            plt.close()
    with open(os.path.join(RES, "summary.md"), "w") as f:
        f.write("\n".join(out) + "\n")
    print("\n".join(out))
    print("\nwrote results/summary.md and figures")


if __name__ == "__main__":
    main()
