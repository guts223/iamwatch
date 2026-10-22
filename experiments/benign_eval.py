#!/usr/bin/env python3
"""Count what the DEPLOYED stack and the stateless rules said while lab/benign_load.py was running.

    python experiments/benign_eval.py            # uses results/benign_ops.csv for the time window

Writes results/benign_live.json:  operations, events seen, ACTIVE / WATCH / EVASION alerts raised by IAMWatch,
and rule hits of the stateless baseline on the same raw events.  Any ACTIVE alert here is a false alert.
"""
import argparse
import csv
import json
import os
import sys
from collections import Counter

import boto3
from boto3.dynamodb.conditions import Attr

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "src"))
from iamwatch.baselines import StatelessRules  # noqa: E402
from iamwatch.events import _parse_time  # noqa: E402

REGION = "us-east-1"


def scan_all(table, **kw):
    items, resp = [], table.scan(**kw)
    items += resp["Items"]
    while "LastEvaluatedKey" in resp:
        resp = table.scan(ExclusiveStartKey=resp["LastEvaluatedKey"], **kw)
        items += resp["Items"]
    return items


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--ops", default=os.path.join(ROOT, "results", "benign_ops.csv"))
    ap.add_argument("--out", default=os.path.join(ROOT, "results", "benign_live.json"))
    args = ap.parse_args()
    ops = list(csv.DictReader(open(args.ops)))
    t0 = min(float(o["start"]) for o in ops) - 5
    t1 = max(float(o["end"]) for o in ops) + 120
    out = json.load(open(os.path.join(ROOT, "build", "outputs.json")))
    ddb = boto3.resource("dynamodb", region_name=REGION)
    alerts = scan_all(ddb.Table(out["AlertsTableName"]), FilterExpression=Attr("detected_ms").between(int(t0 * 1000), int(t1 * 1000)))
    events = scan_all(ddb.Table(out["EventsTableName"]))
    events = [e for e in events if t0 <= _parse_time(e["eventTime"]) <= t1]
    rules = StatelessRules()
    hits = Counter()
    for d in sorted((json.loads(e["raw"]) for e in events), key=lambda d: _parse_time(d["eventTime"])):
        for h in rules.process(d):
            hits[h["rule"]] += 1
    levels = Counter(a["level"] for a in alerts)
    res = {"operations": len(ops), "operations_failed": sum(1 for o in ops if o["ok"] == "0"),
           "minutes": round((t1 - 120 - t0) / 60.0, 1), "events_seen": len(events),
           "iamwatch_active": levels.get("ACTIVE", 0), "iamwatch_watch": levels.get("WATCH", 0),
           "iamwatch_evasion": levels.get("EVASION", 0),
           "active_alerts": [{"origin": a["origin"], "path": a["path"]} for a in alerts if a["level"] == "ACTIVE"],
           "stateless_rule_hits": sum(hits.values()), "stateless_by_rule": dict(hits)}
    json.dump(res, open(args.out, "w"), indent=1)
    print(json.dumps(res, indent=1))


if __name__ == "__main__":
    main()
