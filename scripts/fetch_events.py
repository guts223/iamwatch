#!/usr/bin/env python3
"""Download recent CloudTrail management events (from Event history) for offline replay.

    python scripts/fetch_events.py --minutes 120 --out data/events.json

CloudTrail Event history shows events 5-15 minutes after they happen and allows ~2 requests/s.
"""
import argparse
import json
import time
from datetime import datetime, timedelta, timezone

import boto3

from _common import ROOT, dump_json
from iamwatch import events as E


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--minutes", type=int, default=120)
    ap.add_argument("--out", default=ROOT + "/data/events.json")
    args = ap.parse_args()
    ct = boto3.client("cloudtrail", region_name="us-east-1")
    end = datetime.now(timezone.utc)
    start = end - timedelta(minutes=args.minutes)
    out = {}
    for source in E.WATCHED_SOURCES:
        token = None
        while True:
            kw = dict(LookupAttributes=[{"AttributeKey": "EventSource", "AttributeValue": source}],
                      StartTime=start, EndTime=end, MaxResults=50)
            if token:
                kw["NextToken"] = token
            resp = ct.lookup_events(**kw)
            for item in resp.get("Events", []):
                rec = json.loads(item["CloudTrailEvent"])
                if rec.get("eventName") in E.WATCHED_EVENTS:
                    out[rec["eventID"]] = rec
            token = resp.get("NextToken")
            time.sleep(0.6)
            if not token:
                break
    events = sorted(out.values(), key=lambda r: r["eventTime"])
    dump_json(args.out, events)
    print("saved %d events to %s" % (len(events), args.out))


if __name__ == "__main__":
    main()
