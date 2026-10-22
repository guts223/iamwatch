#!/usr/bin/env python3
"""Robustness / stress tests (offline, no AWS): what happens when conditions are NOT ideal.

    python experiments/robustness.py --reps 30

R1 noise     attack hidden among N unrelated benign events inside the same time window
R2 loss      each CloudTrail event of the attack is lost independently with probability p; second pass: the
             gap-fill job recovers the lost events later (recall --gapfill-recall, validated live by
             experiments/live_gapfill.py) and they reach the engine late and out of order
R3 slow      the attacker spaces the hops further apart; fixed 3600 s window vs the 12 h linked window
R4 pair      two different attacks run at the same time in one account (attribution test)
R5 decoy     benign-only runs with N events: ACTIVE and WATCH alerts (false-alert check under load)

Writes results/robustness_<name>.csv for every test.  Detection = an ACTIVE alert naming the real origin.
"""
import argparse
import csv
import os
import random
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "src"))
from iamwatch import simlab as S  # noqa: E402
from iamwatch import synth  # noqa: E402
from iamwatch.baselines import StatelessRules  # noqa: E402
from iamwatch.engine import Engine  # noqa: E402
from iamwatch.events import _parse_time  # noqa: E402

T0 = 1_800_000_000
OUT = os.path.join(ROOT, "results")


def run_engine(details, events, late=(), **kw):
    """Process `events` in time order, then the `late` events (gap-filled ones arrive afterwards)."""
    eng = Engine.from_snapshot(details, **kw)
    alerts = []
    for d in sorted(events, key=lambda d: _parse_time(d["eventTime"])):
        alerts += eng.process(d)
    for d in sorted(late, key=lambda d: _parse_time(d["eventTime"])):
        alerts += eng.process(d, late=True)
    return alerts


def active_any(alerts):
    """An ACTIVE alert exists, whoever it names (a lost first hop can shift the blame to the role)."""
    return int(any(a["level"] == "ACTIVE" for a in alerts))


def hit(alerts, origin, level="ACTIVE"):
    return int(any(a["level"] == level and a["origin"].endswith("/" + origin) for a in alerts))


def seen(alerts, origin):
    return int(any(a["level"] in ("ACTIVE", "WATCH") and a["origin"].endswith("/" + origin) for a in alerts))


def rules_hit(events, attack_ids):
    r = StatelessRules()
    return int(any(h["event"] in attack_ids for d in sorted(events, key=lambda x: _parse_time(x["eventTime"]))
                   for h in r.process(d)))


def retime(events, start, end):
    """Squeeze a benign workload into [start, end] keeping its order."""
    ts = [_parse_time(e["eventTime"]) for e in events]
    lo, hi = min(ts), max(ts)
    for e, t in zip(events, ts):
        e["eventTime"] = synth.iso(start + (t - lo) * (end - start) / max(1.0, hi - lo))
    return events


def noise_in_window(rng, n, start, end):
    if n <= 0:
        return []
    evs = S.benign_workload(rng, T0, max(1, n // 2))   # about 2 events per step on average
    return retime(evs[:n], start, end)


def write(name, rows):
    os.makedirs(OUT, exist_ok=True)
    path = os.path.join(OUT, "robustness_%s.csv" % name)
    with open(path, "w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=list(rows[0]))
        w.writeheader()
        w.writerows(rows)
    print("wrote", path, len(rows), "rows")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--reps", type=int, default=30)
    ap.add_argument("--seed", type=int, default=11)
    ap.add_argument("--gapfill-recall", type=float, default=1.0)
    ap.add_argument("--only", nargs="*", default=["noise", "loss", "slow", "pair", "decoy"])
    a = ap.parse_args()
    cov = lambda k: "covered" if k in S.COVERED else "uncovered"

    if 'noise' in a.only:
        # R1 noise
        rows = []
        for kind in S.ALL:
            for n in (0, 100, 500, 1000):
                for rep in range(a.reps):
                    rng = random.Random("n-%s-%d-%d-%d" % (kind, n, rep, a.seed))
                    det = S.build_details(rng, 25)
                    ta = T0 + 2000
                    atk = S.attack_events(kind, ta, 60, key_suffix="r%d" % rep)
                    ev = noise_in_window(rng, n, ta - 1500, ta + 1500) + atk
                    al = run_engine(det, ev)
                    rows.append(dict(scenario=kind, family=cov(kind), noise_events=n, rep=rep,
                                     engine=hit(al, S.ORIGIN[kind]), engine_any=seen(al, S.ORIGIN[kind]),
                                     active_any=active_any(al),
                                     rules=rules_hit(ev, {e["eventID"] for e in atk})))
        write("noise", rows)


    if 'loss' in a.only:
        # R2 loss
        rows = []
        for kind in S.ALL:
            for p in (0.0, 0.05, 0.10, 0.20, 0.30):
                for rep in range(a.reps):
                    rng = random.Random("l-%s-%s-%d-%d" % (kind, p, rep, a.seed))
                    det = S.build_details(rng, 25)
                    ta = T0 + 2000
                    atk = S.attack_events(kind, ta, 60, key_suffix="r%d" % rep)
                    kept = [e for e in atk if rng.random() >= p]
                    ev = noise_in_window(rng, 100, ta - 1500, ta + 1500) + kept
                    al = run_engine(det, ev)
                    lost = [e for e in atk if e not in kept]
                    back = [e for e in lost if rng.random() < a.gapfill_recall]
                    al2 = run_engine(det, ev, late=back)
                    rows.append(dict(scenario=kind, family=cov(kind), loss=p, rep=rep, events=len(atk), kept=len(kept),
                                     engine=hit(al, S.ORIGIN[kind]), engine_any=seen(al, S.ORIGIN[kind]),
                                     active_any=active_any(al),
                                     engine_gf=hit(al2, S.ORIGIN[kind]), engine_any_gf=seen(al2, S.ORIGIN[kind]),
                                     rules=rules_hit(ev, {e["eventID"] for e in kept})))
        write("loss", rows)


    if 'slow' in a.only:
        # R3 slow attacker (only the multi-event scenarios)
        rows = []
        for kind in ("s1", "s3", "x1"):
            for gap in (30, 600, 1800, 3000, 3500, 3700, 7200, 21600, 43000, 50000):
                for rep in range(a.reps):
                    rng = random.Random("g-%s-%d-%d-%d" % (kind, gap, rep, a.seed))
                    det = S.build_details(rng, 25)
                    ta = T0 + 2000
                    atk = S.attack_events(kind, ta, gap, key_suffix="r%d" % rep)
                    for i, e in enumerate(atk[1:], start=1):          # every later hop is `gap` s after the first
                        e["eventTime"] = synth.iso(ta + gap + (i - 1))
                    al = run_engine(det, atk)
                    al2 = run_engine(det, atk, linked_window=43200)
                    rows.append(dict(scenario=kind, gap_s=gap, rep=rep, engine=hit(al, S.ORIGIN[kind]),
                                     engine_any=seen(al, S.ORIGIN[kind]),
                                     engine_lw=hit(al2, S.ORIGIN[kind]), engine_any_lw=seen(al2, S.ORIGIN[kind]),
                                     rules=rules_hit(atk, {e["eventID"] for e in atk})))
        write("slow", rows)


    if 'pair' in a.only:
        # R4 two attacks at the same time
        pairs = [("s1", "s3"), ("s2", "s4"), ("s5", "x1"), ("x2", "s1"), ("s3", "x1"), ("s4", "s5"), ("x3", "s2"),
                 ("x4", "s1")]
        rows = []
        for k1, k2 in pairs:
            for rep in range(a.reps):
                rng = random.Random("p-%s-%s-%d-%d" % (k1, k2, rep, a.seed))
                det = S.build_details(rng, 25)
                ta = T0 + 2000
                e1 = S.attack_events(k1, ta, 60, key_suffix="a%d" % rep)
                e2 = S.attack_events(k2, ta + rng.randint(1, 50), 60, key_suffix="b%d" % rep)
                ev = noise_in_window(rng, 200, ta - 1500, ta + 1500) + e1 + e2
                al = run_engine(det, ev)
                rows.append(dict(pair="%s+%s" % (k1, k2), rep=rep, both=hit(al, S.ORIGIN[k1]) & hit(al, S.ORIGIN[k2]),
                                 first=hit(al, S.ORIGIN[k1]), second=hit(al, S.ORIGIN[k2])))
        write("pair", rows)


    if 'decoy' in a.only:
        # R5 benign-only load
        rows = []
        for n in (100, 500, 1000, 2000):
            for rep in range(a.reps):
                rng = random.Random("b-%d-%d-%d" % (n, rep, a.seed))
                det = S.build_details(rng, 25)
                ev = S.benign_workload(rng, T0, n)
                al = run_engine(det, ev)
                rows.append(dict(events=len(ev), rep=rep, active=sum(1 for x in al if x["level"] == "ACTIVE"),
                                 watch=sum(1 for x in al if x["level"] == "WATCH")))
        write("decoy", rows)



if __name__ == "__main__":
    main()
