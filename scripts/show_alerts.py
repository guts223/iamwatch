#!/usr/bin/env python3
"""Print the alerts stored by the deployed stack (DynamoDB), newest last."""
import argparse
import json
import os

import boto3

from _common import ROOT


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--table", help="alerts table name (default: read build/outputs.json)")
    args = ap.parse_args()
    table = args.table or json.load(open(os.path.join(ROOT, "build", "outputs.json")))["AlertsTableName"]
    items = boto3.resource("dynamodb", region_name="us-east-1").Table(table).scan()["Items"]
    for it in sorted(items, key=lambda i: int(i["trigger_time_ms"])):
        print("%-7s %-14s lat=%6.1fs evidence %s/%s  %s" % (
            it["level"], it["origin"].rsplit("/", 1)[-1], int(it["latency_ms"]) / 1000.0,
            it["matched_count"], it["required_count"], it["path"]))
    print("\n%d alerts" % len(items))


if __name__ == "__main__":
    main()
