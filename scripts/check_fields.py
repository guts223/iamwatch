#!/usr/bin/env python3
"""Verify that REAL CloudTrail records contain the fields iamwatch relies on.

    python scripts/fetch_events.py --minutes 90        # after running a few attacks
    python scripts/check_fields.py                     # reads data/events.json

Run this once after your first real attack runs.  Every MISSING line is an assumption of the
design that does not hold in your account - fix the telemetry dictionary in
src/iamwatch/evidence.py (hop_signature) before trusting detection results.
"""
import argparse
from collections import defaultdict

from _common import ROOT, load_json

# eventName -> list of (dotted path, required?)
EXPECT = {
    "AssumeRole": [("requestParameters.roleArn", True), ("responseElements.credentials.accessKeyId", True),
                   ("userIdentity.accessKeyId", False)],
    "AttachRolePolicy": [("requestParameters.roleName", True), ("requestParameters.policyArn", True)],
    "CreatePolicyVersion": [("requestParameters.policyArn", True), ("requestParameters.policyDocument", True),
                            ("requestParameters.setAsDefault", True),
                            ("responseElements.policyVersion.versionId", True)],
    "UpdateAssumeRolePolicy": [("requestParameters.roleName", True), ("requestParameters.policyDocument", True)],
    "CreateAccessKey": [("requestParameters.userName", True), ("responseElements.accessKey.accessKeyId", True)],
    "AddUserToGroup": [("requestParameters.userName", True), ("requestParameters.groupName", True)],
    "PutUserPolicy": [("requestParameters.userName", True), ("requestParameters.policyDocument", True)],
    "SetDefaultPolicyVersion": [("requestParameters.policyArn", True), ("requestParameters.versionId", True)],
    "CreateFunction20150331": [("requestParameters.role", True), ("eventSource", True)],
    "RunInstances": [("requestParameters.iamInstanceProfile", False)],
    "CreateStack": [("requestParameters.roleARN", False)],
    "CreateRole": [("requestParameters.assumeRolePolicyDocument", True), ("responseElements.role.arn", True)],
}


def get(d, path):
    for part in path.split("."):
        if not isinstance(d, dict) or part not in d:
            return None
        d = d[part]
    return d


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--events", default=ROOT + "/data/events.json")
    args = ap.parse_args()
    events = load_json(args.events)
    seen = defaultdict(list)
    for e in events:
        seen[e.get("eventName")].append(e)
    bad = 0
    for name, fields in EXPECT.items():
        evs = [e for e in seen.get(name, []) if not e.get("errorCode")]
        if not evs:
            print("%-26s (no successful events in the file - run the matching scenario)" % name)
            continue
        for path, required in fields:
            present = sum(1 for e in evs if get(e, path) is not None)
            status = "OK" if present == len(evs) else ("MISSING" if required else "optional/absent")
            if status == "MISSING":
                bad += 1
            print("%-26s %-48s %3d/%-3d %s" % (name, path, present, len(evs), status))
        if name == "AttachRolePolicy":
            roles = [e for e in evs if (e.get("userIdentity") or {}).get("type") == "AssumedRole"]
            for e in roles[:1]:
                ok = get(e, "userIdentity.sessionContext.sessionIssuer.arn") is not None
                print("%-26s %-48s %s" % (name, "userIdentity.sessionContext.sessionIssuer.arn (assumed role)",
                                          "OK" if ok else "MISSING"))
                bad += 0 if ok else 1
    print("\n%d required field(s) missing" % bad)


if __name__ == "__main__":
    main()
