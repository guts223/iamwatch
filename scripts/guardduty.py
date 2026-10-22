#!/usr/bin/env python3
"""Amazon GuardDuty as a real-world comparison for the attack experiments.

    python scripts/guardduty.py enable      # start GuardDuty in us-east-1 (30-day free trial for a new account)
    python scripts/guardduty.py collect     # save every finding to results/guardduty_findings.json
    python scripts/guardduty.py disable     # delete the detector (stops the charges)

GuardDuty reads CloudTrail on its own and publishes findings some minutes after the event.  Some of its IAM
findings are anomaly based, so they need a learning period: enable it at the START (run the benign load for a
while before the attack campaign) and collect at least 30-60 minutes after the last attack.
experiments/analyze_live.py then matches findings to attacks by time window and identity.
"""
import argparse
import json
import os
import sys
import time

import boto3
from botocore.exceptions import ClientError

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
REGION = "us-east-1"


def detector(gd, create=False):
    ids = gd.list_detectors()["DetectorIds"]
    if ids:
        return ids[0]
    if not create:
        sys.exit("GuardDuty is not enabled: run `python scripts/guardduty.py enable` first")
    return gd.create_detector(Enable=True, FindingPublishingFrequency="FIFTEEN_MINUTES")["DetectorId"]


def collect(gd, did, out):
    ids, kw = [], dict(DetectorId=did, MaxResults=50)
    while True:
        r = gd.list_findings(**kw)
        ids += r["FindingIds"]
        if not r.get("NextToken"):
            break
        kw["NextToken"] = r["NextToken"]
    found = []
    for i in range(0, len(ids), 50):
        found += gd.get_findings(DetectorId=did, FindingIds=ids[i:i + 50])["Findings"]
    rows = []
    for f in found:
        akd = (f.get("Resource") or {}).get("AccessKeyDetails") or {}
        svc = f.get("Service") or {}
        rows.append({"id": f["Id"], "type": f["Type"], "title": f.get("Title", ""), "severity": f.get("Severity"),
                     "created": f.get("CreatedAt"), "updated": f.get("UpdatedAt"),
                     "first_seen": svc.get("EventFirstSeen"), "last_seen": svc.get("EventLastSeen"),
                     "count": svc.get("Count"), "user_name": akd.get("UserName"), "user_type": akd.get("UserType"),
                     "principal_id": akd.get("PrincipalId"), "access_key_id": akd.get("AccessKeyId")})
    os.makedirs(os.path.dirname(out), exist_ok=True)
    json.dump(rows, open(out, "w"), indent=1, default=str)
    return rows


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("action", choices=["enable", "collect", "disable", "check"])
    ap.add_argument("--out", default=os.path.join(ROOT, "results", "guardduty_findings.json"))
    args = ap.parse_args()
    gd = boto3.client("guardduty", region_name=REGION)
    if args.action == "check":        # exit code 0 = GuardDuty is usable here, 1 = not (campaign.ps1 then skips it)
        try:
            ok = bool(gd.list_detectors()["DetectorIds"])
        except Exception as e:                                    # noqa: BLE001
            print("GuardDuty not available:", str(e)[:120])
            sys.exit(1)
        print("GuardDuty detector found" if ok else "GuardDuty enabled?  no detector")
        sys.exit(0 if ok else 1)
    if args.action == "enable":
        did = detector(gd, create=True)
        print("GuardDuty detector active:", did)
    elif args.action == "collect":
        rows = collect(gd, detector(gd), args.out)
        print("%d findings saved to %s" % (len(rows), args.out))
        for r in rows[:15]:
            print("  ", r["created"], r["type"], r["user_name"])
    else:
        gd.delete_detector(DetectorId=detector(gd))
        print("GuardDuty disabled")


if __name__ == "__main__":
    main()