#!/usr/bin/env python3
"""Replay saved CloudTrail events through the engine, offline (no AWS needed for the engine).

    python scripts/replay.py --snapshot data/snapshot.json --events data/events.json
    python scripts/replay.py --demo          # built-in lab account + the five attack scenarios

Events file: a JSON list of CloudTrail records (or EventBridge events with a "detail" field).
After the replay the incremental graph is compared with one rebuilt from scratch.
"""
import argparse

from _common import fmt_path, load_json
from iamwatch import labspec as L
from iamwatch import synth
from iamwatch.engine import Engine
from iamwatch.events import _parse_time


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--snapshot")
    ap.add_argument("--events")
    ap.add_argument("--demo", action="store_true")
    ap.add_argument("--k", type=int, default=5)
    ap.add_argument("--window", type=int, default=3600)
    args = ap.parse_args()
    if args.demo:
        acct = "123456789012"
        eng = Engine.from_snapshot(L.lab_authorization_details(acct), k=args.k, window=args.window)
        events, t = [], 1_800_000_000
        for kind in L.SCENARIOS:
            events += synth.scenario_events(kind, acct, t, key_suffix=kind)
            t += 7200
        events += synth.benign_events(acct, t)
    else:
        eng = Engine.from_snapshot(load_json(args.snapshot), k=args.k, window=args.window)
        events = [e.get("detail", e) for e in load_json(args.events)]
    events.sort(key=lambda d: _parse_time(d["eventTime"]))
    n_alerts = 0
    for d in events:
        for a in eng.process(d):
            n_alerts += 1
            print("%-6s %-12s %s   (evidence %d/%d%s)" % (
                a["level"], a["origin"].rsplit("/", 1)[-1], fmt_path(a["path"]), a["matched_count"],
                a["required_count"], ", session-linked" if a["linked"] else ""))
    ok, diffs = eng.check_equivalence()
    print("\n%d events, %d alerts. incremental graph == rebuilt-from-scratch graph: %s" % (len(events), n_alerts, ok))
    if not ok:
        print(diffs)


if __name__ == "__main__":
    main()
