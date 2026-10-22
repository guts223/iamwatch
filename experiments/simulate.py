#!/usr/bin/env python3
"""Offline evaluation (no AWS needed): live engine vs batch-style scanning vs stateless rules.

    python experiments/simulate.py --reps 30 --out results/simulation.csv

For each attack family (s1-s5 covered by simple rules, x1-x4 NOT covered) and each repetition
(random noise accounts, random hop gaps, random scan phase) it records, for every mode:
    detected        did an ACTIVE alert (rules: any rule hit) fire on the attack?
    attributed      did the alert name the real origin identity and the full path? (rules: never)
    staleness_s     seconds between the last attack event and the alert becoming visible,
                    EXCLUDING the CloudTrail delivery delay that all modes share
    awareness_s     (fresh-misconfiguration test) seconds until a newly created dangerous
                    path is known to the system
and, separately, the number of false alerts on a benign workload.
"""
import argparse
import csv
import os
import random
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "src"))

from iamwatch import simlab as S  # noqa: E402
from iamwatch.baselines import StaleEngine, StatelessRules  # noqa: E402
from iamwatch.engine import Engine  # noqa: E402
from iamwatch.events import _parse_time  # noqa: E402

INTERVALS = [300, 900, 1800, 3600]
T0 = 1_800_000_000


def run_live(details, events, origin_name, last_attack_time, awareness_event_time=None):
    eng = Engine.from_snapshot(details)
    first = None
    for d in sorted(events, key=lambda x: _parse_time(x["eventTime"])):
        for a in eng.process(d):
            if a["level"] == "ACTIVE" and a["origin"].endswith("/" + origin_name) and first is None:
                first = (_parse_time(d["eventTime"]), a)
    if first is None:
        return {"detected": 0, "attributed": 0, "staleness_s": ""}
    return {"detected": 1, "attributed": 1, "staleness_s": max(0.0, first[0] - last_attack_time)}


def run_batch(details, events, origin_name, last_attack_time, interval, phase):
    se = StaleEngine(details, interval, phase)
    alerts = []
    for d in sorted(events, key=lambda x: _parse_time(x["eventTime"])):
        alerts += se.process(d)
    alerts += se.finish(3 * interval)
    hits = [a for a in alerts if a["level"] == "ACTIVE" and a["origin"].endswith("/" + origin_name)]
    if not hits:
        return {"detected": 0, "attributed": 0, "staleness_s": ""}
    return {"detected": 1, "attributed": 1, "staleness_s": max(0.0, min(a["visible_at"] for a in hits) - last_attack_time)}


def run_rules(events, attack_ids):
    """Rules are credited only for hits on the attack events themselves (not on background noise)."""
    r = StatelessRules()
    hits = [h for d in sorted(events, key=lambda x: _parse_time(x["eventTime"])) for h in r.process(d)
            if h["event"] in attack_ids]
    return {"detected": int(bool(hits)), "attributed": 0, "staleness_s": 0.0 if hits else ""}


def noise_events(rng, t_start, t_end, n):
    evs = S.benign_workload(rng, t_start, n)
    return [e for e in evs if _parse_time(e["eventTime"]) < t_end]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--reps", type=int, default=30)
    ap.add_argument("--noise", type=int, default=25, help="noise principals in the account")
    ap.add_argument("--out", default=os.path.join(ROOT, "results", "simulation.csv"))
    ap.add_argument("--seed", type=int, default=7)
    args = ap.parse_args()
    os.makedirs(os.path.dirname(args.out), exist_ok=True)
    rows = []
    for kind in S.ALL:
        for rep in range(args.reps):
            rng = random.Random("%s-%d-%d" % (kind, rep, args.seed))
            details = S.build_details(rng, args.noise)
            t_attack = T0 + rng.randint(1000, 5000)
            gap = rng.choice([10, 30, 60, 120, 300])
            attack = S.attack_events(kind, t_attack, gap, key_suffix="r%d" % rep)
            last_attack = max(_parse_time(e["eventTime"]) for e in attack)
            before = noise_events(rng, T0, t_attack - 5, 12)
            events = before + attack
            origin = S.ORIGIN[kind]
            row = lambda mode, interval, res: rows.append(dict(
                scenario=kind, family="covered" if kind in S.COVERED else "uncovered", rep=rep, mode=mode,
                interval_s=interval, hop_gap_s=gap, **res))
            row("live", 0, run_live(details, events, origin, last_attack))
            for iv in INTERVALS:
                row("batch", iv, run_batch(details, events, origin, last_attack, iv, rng.uniform(0, iv)))
            row("rules", 0, run_rules(events, {e["eventID"] for e in attack}))
    # ---- fresh-misconfiguration test: how long until a NEW dangerous path is known?
    aw = []
    for kind in ["s2", "s3", "s4", "s5", "x2", "x3", "x4"]:
        for rep in range(args.reps):
            rng = random.Random("aw-%s-%d-%d" % (kind, rep, args.seed))
            base = S.build_details(rng, args.noise)
            t_enable = T0 + rng.randint(1000, 5000)
            stripped, enabling = S.enabling_events(base, S.ORIGIN[kind], t_enable)
            origin_node = "user:" + S.ORIGIN[kind]
            eng = Engine.from_snapshot(stripped)
            assert eng.graph.dist.get(origin_node) is None, kind
            for d in enabling:
                eng.process(d)
            live_known = eng.graph.dist.get(origin_node) is not None
            for iv in INTERVALS:
                phase = rng.uniform(0, iv)
                se = StaleEngine(stripped, iv, phase)
                for d in enabling:
                    se.process(d)
                next_scan = se._boundary_after(t_enable)
                aw.append(dict(scenario=kind, rep=rep, mode="batch", interval_s=iv,
                               awareness_s=next_scan - t_enable, known=1))
            aw.append(dict(scenario=kind, rep=rep, mode="live", interval_s=0, awareness_s=0.0, known=int(live_known)))
    # ---- benign workload: false alerts
    fp = []
    for rep in range(args.reps):
        rng = random.Random("fp-%d-%d" % (rep, args.seed))
        details = S.build_details(rng, args.noise)
        events = sorted(S.benign_workload(rng, T0, 60), key=lambda d: _parse_time(d["eventTime"]))
        eng = Engine.from_snapshot(details)
        n_active = sum(1 for d in events for a in eng.process(d) if a["level"] == "ACTIVE")
        eng2 = Engine.from_snapshot(details)
        n_watch = sum(1 for d in events for a in eng2.process(d) if a["level"] == "WATCH")
        se = StaleEngine(details, 900, rng.uniform(0, 900))
        al = []
        for d in events:
            al += se.process(d)
        al += se.finish(3600)
        fp.append(dict(rep=rep, events=len(events), live_active=n_active, live_watch=n_watch,
                       batch900_active=sum(1 for a in al if a["level"] == "ACTIVE"),
                       rules=_rule_hits(events)))
    for name, data in (("simulation", rows), ("awareness", aw), ("falsealerts", fp)):
        path = os.path.join(os.path.dirname(args.out), name + ".csv")
        with open(path, "w", newline="") as f:
            w = csv.DictWriter(f, fieldnames=list(data[0].keys()))
            w.writeheader()
            w.writerows(data)
        print("wrote", path, len(data), "rows")


def _rule_hits(events):
    r = StatelessRules()
    return sum(len(r.process(d)) for d in events)


if __name__ == "__main__":
    main()
