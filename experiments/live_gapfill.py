#!/usr/bin/env python3
"""Real-AWS test of the gap-fill job: attacks whose events are NEVER delivered by EventBridge.

    python experiments/live_gapfill.py --scenarios s1 x1 s3 --reps 5

For every repetition: (1) the EventBridge rule is switched off, (2) the attack runs, (3) the rule is switched
back on, (4) the gap-fill job is invoked every 30 s (the deployed stack also runs it every 5 minutes) until the
ACTIVE alert naming the right origin appears or the timeout is reached.  Records whether it was detected and how
many seconds after the last attack event.  The rule is ALWAYS restored, even on Ctrl+C.
"""
import argparse
import csv
import json
import os
import sys
import time

import boto3
from boto3.dynamodb.conditions import Attr

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "src"))
sys.path.insert(0, os.path.join(ROOT, "lab"))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from iamwatch import labspec as L  # noqa: E402
import attacks as lab  # noqa: E402
import run_attacks as ra  # noqa: E402

REGION = "us-east-1"


class RuleSwitch:
    def __init__(self, name):
        self.ev = boto3.client("events", region_name=REGION)
        self.name = name
        d = self.ev.describe_rule(Name=name)
        self.pattern, self.state, self.desc = d["EventPattern"], d["State"], d.get("Description", "")

    def set(self, state):
        self.ev.put_rule(Name=self.name, EventPattern=self.pattern, State=state, Description=self.desc)

    def off(self):
        self.set("DISABLED")

    def on(self):
        self.set(self.state)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--scenarios", nargs="+", default=["s1", "x1", "s3"], choices=L.LIVE_SCENARIOS)
    ap.add_argument("--reps", type=int, default=5)
    ap.add_argument("--timeout", type=int, default=900)
    ap.add_argument("--poll", type=int, default=30)
    ap.add_argument("--out", default=os.path.join(ROOT, "results", "gapfill_real.csv"))
    args = ap.parse_args()
    outs = json.load(open(os.path.join(ROOT, "build", "outputs.json")))
    events_t, alerts_t = ra.tables()
    lam = boto3.client("lambda", region_name=REGION)
    acct = lab.account()
    rule = RuleSwitch(outs["IamEventRuleName"])
    fields = ["scenario", "rep", "detected", "seconds_after_last_event", "gapfill_calls", "events_recovered"]
    new = not os.path.exists(args.out)
    done = {}
    if not new:
        for r in csv.DictReader(open(args.out)):
            done[r["scenario"]] = max(done.get(r["scenario"], -1), int(r["rep"]))
    try:
        with open(args.out, "a", newline="") as fh:
            w = csv.DictWriter(fh, fieldnames=fields)
            if new:
                w.writeheader()
            for kind in args.scenarios:
                for rep in range(done.get(kind, -1) + 1, args.reps):
                    t_reset = time.time()
                    lab.reset(acct)
                    ra.settle(events_t, t_reset)
                    rule.off()
                    time.sleep(8)
                    t0 = time.time()
                    rec = lab.run(kind, acct)
                    time.sleep(5)
                    rule.on()
                    since_ms = int(t0 * 1000) - 5000
                    row = {"scenario": kind, "rep": rep, "detected": 0, "gapfill_calls": 0, "events_recovered": 0}
                    deadline = time.time() + args.timeout
                    while time.time() < deadline:
                        time.sleep(args.poll)
                        resp = lam.invoke(FunctionName=outs["FunctionName"], Payload=json.dumps(
                            {"action": "gapfill", "lookback_minutes": 30, "min_age_seconds": 10}).encode())
                        res = json.loads(resp["Payload"].read() or b"{}")
                        row["gapfill_calls"] += 1
                        row["events_recovered"] += int(res.get("sent", 0)) if isinstance(res, dict) else 0
                        alert = ra.wait_for_alert(alerts_t, L.SCENARIO_ORIGIN[kind], since_ms, 15)
                        if alert:
                            row["detected"] = 1
                            row["seconds_after_last_event"] = round(int(alert["detected_ms"]) / 1000.0 - rec["attack_end_epoch"], 1)
                            break
                    w.writerow(row)
                    fh.flush()
                    print("   ->", json.dumps(row))
            lab.reset(acct)
    finally:
        rule.on()
        print("EventBridge rule restored to", rule.state)


if __name__ == "__main__":
    main()
