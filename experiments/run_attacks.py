#!/usr/bin/env python3
"""Real-AWS experiment: run the attack scenarios N times against the DEPLOYED stack and measure.

    python experiments/run_attacks.py --reps 10                       # all nine families, 10 each
    python experiments/run_attacks.py --scenarios x1 x2 --reps 3      # a subset

The file is appended to and the run is RESUMABLE: if it stops (laptop sleeps, Wi-Fi drops) start the
same command again and it continues with the repetitions that are still missing.

Prerequisites: stack deployed (scripts/deploy.py ... --cooldown 1), lab created (lab/setup_lab.py),
SNS e-mail confirmed.  One repetition takes about 1-2 minutes.

For every run it records:
    detected            an ACTIVE alert naming the right origin identity appeared in the alerts table
    delivery_s          CloudTrail eventTime -> message placed on the queue by EventBridge   (not under our control)
    queue_s             queue -> Lambda start
    processing_s        Lambda start -> alert stored
    total_s             CloudTrail eventTime of the LAST attack step -> alert stored           (end to end)
    rules_detected      would the stateless rule baseline have fired on the same raw events?
and one extra file results/batch_scan.json: how long a full batch scan (download + graph build) takes
here; the expected detection delay of a scheduled scan is interval/2 + that runtime (mean) and
interval + runtime (worst case).
"""
import argparse
import csv
import json
import os
import sys
import time
from datetime import datetime, timezone

import boto3
from boto3.dynamodb.conditions import Attr

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "src"))
sys.path.insert(0, os.path.join(ROOT, "lab"))
from iamwatch import labspec as L  # noqa: E402
from iamwatch.awsio import get_authorization_details  # noqa: E402
from iamwatch.baselines import StatelessRules  # noqa: E402
from iamwatch.engine import Engine  # noqa: E402
from iamwatch.events import _parse_time  # noqa: E402
import attacks as lab  # noqa: E402

REGION = "us-east-1"


def tables():
    out = json.load(open(os.path.join(ROOT, "build", "outputs.json")))
    ddb = boto3.resource("dynamodb", region_name=REGION)
    return ddb.Table(out["EventsTableName"]), ddb.Table(out["AlertsTableName"])


def scan_all(table, **kw):
    items, resp = [], table.scan(**kw)
    items += resp["Items"]
    while "LastEvaluatedKey" in resp:
        resp = table.scan(ExclusiveStartKey=resp["LastEvaluatedKey"], **kw)
        items += resp["Items"]
    return items


def iso(t):
    return datetime.fromtimestamp(t, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def settle(events_t, since_epoch, timeout=240):
    """Wait until every event since `since_epoch` has reached the stack AND been processed."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        items = scan_all(events_t, FilterExpression=Attr("eventTime").gte(iso(since_epoch - 2)))
        newest = max([_parse_time(i["eventTime"]) for i in items] or [0])
        if items and newest >= since_epoch - 2 and all("processed_ms" in i for i in items):
            time.sleep(3)
            return True
        time.sleep(4)
    return False


def wait_for_alert(alerts_t, origin_name, since_ms, timeout):
    deadline = time.time() + timeout
    while time.time() < deadline:
        for a in scan_all(alerts_t, FilterExpression=Attr("level").eq("ACTIVE") & Attr("detected_ms").gte(since_ms)):
            # the alert must be built from THIS attack's events, never from an older chain
            if a["origin"].endswith("/" + origin_name) and int(a["last_matched_time_ms"]) >= since_ms + 3000:
                return a
        time.sleep(4)
    return None


def measure_batch_scan(out_path):
    times = []
    for _ in range(3):
        t0 = time.time()
        details = get_authorization_details(boto3.client("iam", region_name=REGION))
        t1 = time.time()
        Engine.from_snapshot(details)
        t2 = time.time()
        times.append((t1 - t0, t2 - t1))
    best = {"download_s": sorted(t[0] for t in times)[1], "build_s": sorted(t[1] for t in times)[1]}
    best["runtime_s"] = best["download_s"] + best["build_s"]
    json.dump(best, open(out_path, "w"), indent=1)
    print("batch scan runtime: %.2fs (download %.2fs + build %.3fs)" % (best["runtime_s"], best["download_s"], best["build_s"]))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--scenarios", nargs="+", default=L.LIVE_SCENARIOS, choices=L.LIVE_SCENARIOS)
    ap.add_argument("--reps", type=int, default=10)
    ap.add_argument("--timeout", type=int, default=240, help="seconds to wait for an alert per run")
    ap.add_argument("--out", default=os.path.join(ROOT, "results", "attacks_real.csv"))
    args = ap.parse_args()
    os.makedirs(os.path.dirname(args.out), exist_ok=True)
    events_t, alerts_t = tables()
    acct = lab.account()
    measure_batch_scan(os.path.join(os.path.dirname(args.out), "batch_scan.json"))
    fields = ["scenario", "rep", "attack_start", "attack_end", "detected", "delivery_s", "queue_s", "processing_s", "total_s",
              "matched", "required", "linked", "rules_detected", "origin"]
    new_file = not os.path.exists(args.out)
    done = {}
    if not new_file:
        for r in csv.DictReader(open(args.out)):
            done[r["scenario"]] = max(done.get(r["scenario"], -1), int(r["rep"]))
    with open(args.out, "a", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=fields)
        if new_file:
            w.writeheader()
        for kind in args.scenarios:
            for rep in range(done.get(kind, -1) + 1, args.reps):
                t_reset = time.time()
                lab.reset(acct)
                print("[%s #%d] reset done, waiting for the stack to catch up ..." % (kind, rep))
                settle(events_t, t_reset)
                t0 = time.time()
                rec = lab.run(kind, acct)
                print("[%s #%d] attack executed, waiting for an alert (CloudTrail delay: minutes) ..." % (kind, rep))
                alert = wait_for_alert(alerts_t, L.SCENARIO_ORIGIN[kind], int(t0 * 1000) - 5000, args.timeout)
                if alert:
                    settle(events_t, t0)
                row = {"scenario": kind, "rep": rep, "attack_start": iso(t0), "attack_end": iso(rec["attack_end_epoch"]),
                       "detected": 0, "rules_detected": 0,
                       "origin": L.SCENARIO_ORIGIN[kind]}
                raw = [json.loads(i["raw"]) for i in scan_all(
                    events_t, FilterExpression=Attr("eventTime").gte(iso(t0 - 2)))]
                if alert:
                    ids = {e["id"] for e in json.loads(alert["alert_json"])["matched_events"]}
                    ev_items = {i["eventID"]: i for i in scan_all(events_t, FilterExpression=Attr("eventTime").gte(iso(t0 - 2)))}
                    last = max((ev_items[i] for i in ids if i in ev_items), key=lambda i: _parse_time(i["eventTime"]),
                               default=None)
                    row.update(detected=1, matched=int(alert["matched_count"]), required=int(alert["required_count"]),
                               linked=int(bool(alert["linked"])),
                               total_s=round(int(alert["detected_ms"]) / 1000.0 - int(alert["last_matched_time_ms"]) / 1000.0, 2))
                    if last:
                        sent = int(last["sqs_sent_ms"]) / 1000.0
                        rec_ms = int(last["lambda_received_ms"]) / 1000.0
                        row.update(delivery_s=round(sent - _parse_time(last["eventTime"]), 2),
                                   queue_s=round(rec_ms - sent, 2),
                                   processing_s=round(int(alert["detected_ms"]) / 1000.0 - rec_ms, 2))
                rules = StatelessRules()
                attack_ids = set()
                for d in sorted(raw, key=lambda d: _parse_time(d["eventTime"])):
                    for h in rules.process(d):
                        if (d.get("userIdentity", {}).get("arn", "") + (d.get("userIdentity", {}).get("sessionContext", {})
                                                                         .get("sessionIssuer", {}).get("arn", ""))):
                            attack_ids.add(h["rule"])
                row["rules_detected"] = int(bool(attack_ids))
                w.writerow(row)
                fh.flush()
                print("   ->", json.dumps(row))
        lab.reset(acct)
    print("wrote", args.out)


if __name__ == "__main__":
    main()