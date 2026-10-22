#!/usr/bin/env python3
"""Download the full IAM state of the current AWS account to data/snapshot.json."""
import argparse

import boto3

from _common import ROOT, dump_json
from iamwatch.awsio import get_authorization_details


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default=ROOT + "/data/snapshot.json")
    args = ap.parse_args()
    iam = boto3.client("iam", region_name="us-east-1")
    details = get_authorization_details(iam)
    dump_json(args.out, details)
    print("saved %s  (%d users, %d roles, %d groups, %d policies)" % (
        args.out, len(details["UserDetailList"]), len(details["RoleDetailList"]),
        len(details["GroupDetailList"]), len(details["Policies"])))


if __name__ == "__main__":
    main()
