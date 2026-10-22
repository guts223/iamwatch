#!/usr/bin/env python3
"""Posture scan: list every identity that can reach administrator access, and how.

    python scripts/scan.py                      # scan the live account
    python scripts/scan.py --snapshot data/snapshot.json
"""
import argparse
import time

import boto3

from _common import ROOT, dump_json, fmt_path, load_json
from iamwatch.awsio import get_authorization_details
from iamwatch.engine import Engine


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--snapshot")
    ap.add_argument("--k", type=int, default=5)
    ap.add_argument("--out", default=ROOT + "/results/posture.json")
    args = ap.parse_args()
    t0 = time.time()
    details = load_json(args.snapshot) if args.snapshot else get_authorization_details(
        boto3.client("iam", region_name="us-east-1"))
    t1 = time.time()
    eng = Engine.from_snapshot(details, k=args.k)
    t2 = time.time()
    rep = eng.posture()
    dump_json(args.out, rep)
    print("already administrator: %s" % ", ".join(rep["already_admin"]) or "-")
    print("\nescalation paths (identity -> ADMIN):")
    if not rep["escalation_paths"]:
        print("  none found within %d hops" % args.k)
    for r in rep["escalation_paths"]:
        print("  [%d hops] %s" % (r["hops"], r["principal"]))
        for p in r["paths"][:2]:
            print("       " + fmt_path(p))
    print("\nfetch %.2fs, graph build %.3fs  (full batch scan = %.2fs)" % (t1 - t0, t2 - t1, t2 - t0))


if __name__ == "__main__":
    main()
