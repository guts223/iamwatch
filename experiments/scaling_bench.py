#!/usr/bin/env python3
"""Scaling micro-benchmark of the graph layer on synthetic graphs (no AWS needed).

Compares, per graph size, three ways of repairing the hop-to-ADMIN table after ONE change
(edge insert / delete / new admin edge / insert at a hub node):
    exact    Graph.update_dist       touches only nodes whose distance really changes
    ball     Graph.update_dist_ball  recomputes every node within k hops of the change (coarse)
    rebuild  Graph.rebuild_dist      a bounded reverse BFS from ADMIN
HONEST NOTE: the rebuild is itself only a k-bounded search from ADMIN, so it is cheap.  The big
saving of the event-driven design is NOT here - it is in avoiding re-downloading IAM and
re-deriving every edge from policies (see experiments/engine_scaling.py).

    python experiments/scaling_bench.py --sizes 1000 10000 50000 100000 --ops 200

Scope note (state it in the paper): this measures the graph/distance layer only, on synthetic
graphs with hub nodes - NOT the policy-evaluation layer, and not real IAM data.
"""
import argparse
import csv
import os
import random
import statistics
import sys
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "src"))
from iamwatch.graph import Graph  # noqa: E402
from iamwatch.model import ADMIN  # noqa: E402


def make_graph(n, deg, rng, k=5, admin_frac=0.005, hub_frac=0.005, hub_p=0.3):
    g = Graph(k)
    nodes = ["n%d" % i for i in range(n)]
    hubs = nodes[: max(1, int(n * hub_frac))]
    for u in nodes:
        out = {}
        for _ in range(max(1, int(rng.expovariate(1.0 / deg)))):
            v = rng.choice(hubs) if rng.random() < hub_p else rng.choice(nodes)
            if v != u:
                out[(v, "AssumeRole", "")] = False
        if rng.random() < admin_frac:
            out[(ADMIN, "HasAdmin", "")] = False
        g.set_out(u, out)
    t = time.perf_counter()
    g.rebuild_dist()
    return g, nodes, hubs, (time.perf_counter() - t) * 1000


def pct(xs, p):
    xs = sorted(xs)
    return xs[min(len(xs) - 1, int(p * len(xs)))]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--sizes", type=int, nargs="+", default=[1000, 10000, 50000, 100000])
    ap.add_argument("--deg", type=float, default=4.0, help="mean out-degree")
    ap.add_argument("--ops", type=int, default=200)
    ap.add_argument("--k", type=int, default=5)
    ap.add_argument("--seed", type=int, default=1)
    ap.add_argument("--out", default=os.path.join(ROOT, "results", "scaling.csv"))
    args = ap.parse_args()
    os.makedirs(os.path.dirname(args.out), exist_ok=True)
    rows = []
    for n in args.sizes:
        rng = random.Random(args.seed)
        g, nodes, hubs, _ = make_graph(n, args.deg, rng, args.k)
        edges = sum(len(v) for v in g.out.values())
        full = []
        for _ in range(3):
            t = time.perf_counter()
            g.rebuild_dist()
            full.append((time.perf_counter() - t) * 1000)
        full_ms = statistics.median(full)
        for op in ("insert", "delete", "new_admin_edge", "hub_insert"):
            res = {"exact": ([], []), "ball": ([], [])}
            for _ in range(args.ops):
                u = rng.choice(hubs) if op == "hub_insert" else rng.choice(nodes)
                cur = dict(g.out.get(u, {}))
                if op in ("insert", "hub_insert"):
                    v = rng.choice(nodes)
                    if v == u:
                        continue
                    cur[(v, "AssumeRole", "")] = False
                elif op == "delete":
                    if not cur:
                        continue
                    cur.pop(rng.choice(list(cur)))
                else:
                    cur[(ADMIN, "HasAdmin", "")] = False
                g.set_out(u, cur)
                snapshot = dict(g.dist)
                for name, fn in (("ball", g.update_dist_ball), ("exact", g.update_dist)):
                    g.dist = dict(snapshot)
                    t = time.perf_counter()
                    _, _, aff = fn({u})
                    res[name][0].append((time.perf_counter() - t) * 1000)
                    res[name][1].append(aff)
                # both algorithms must agree with the oracle
                ref = Graph(g.k)
                ref.out, ref.pred = g.out, g.pred
                ref.rebuild_dist()
                assert g.dist == ref.dist
            for name in ("exact", "ball"):
                times, affected = res[name]
                rows.append({"nodes": n, "edges": edges, "op": op, "algorithm": name, "ops": len(times),
                             "update_ms_median": round(statistics.median(times), 4),
                             "update_ms_p95": round(pct(times, 0.95), 4),
                             "update_ms_max": round(max(times), 4),
                             "touched_median": int(statistics.median(affected)),
                             "touched_max": max(affected), "full_rebuild_ms": round(full_ms, 3)})
                r = rows[-1]
                print("n=%-7d %-15s %-5s median %.3f ms  p95 %.3f ms  touched median %d (max %d)   [rebuild %.2f ms]"
                      % (n, op, name, r["update_ms_median"], r["update_ms_p95"], r["touched_median"],
                         r["touched_max"], full_ms))
        if True:            # every change above was checked against the full rebuild (the oracle)
            print("n=%-7d exact and ball updates matched the full rebuild after every one of %d changes: OK"
                  % (n, 4 * args.ops))
    with open(args.out, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        w.writeheader()
        w.writerows(rows)
    print("wrote", args.out)


if __name__ == "__main__":
    main()
