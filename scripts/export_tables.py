#!/usr/bin/env python3
"""Save everything the deployed stack recorded to files on YOUR laptop (do this before teardown).

    python scripts/export_tables.py            # -> results/export/events_table.json, alerts_table.json, reports/

AWS-side data deletes itself after 14 days (and everything disappears on teardown).  These files are the raw
evidence behind your tables: keep them, and publish them (sanitised) with the paper for reproducibility.
"""
import json
import os

import boto3

from _common import ROOT


def scan_all(table):
    items, resp = [], table.scan()
    items += resp["Items"]
    while "LastEvaluatedKey" in resp:
        resp = table.scan(ExclusiveStartKey=resp["LastEvaluatedKey"])
        items += resp["Items"]
    return items


def main():
    out = json.load(open(os.path.join(ROOT, "build", "outputs.json")))
    dest = os.path.join(ROOT, "results", "export")
    os.makedirs(os.path.join(dest, "reports"), exist_ok=True)
    ddb = boto3.resource("dynamodb", region_name="us-east-1")
    for key, name in (("EventsTableName", "events_table"), ("AlertsTableName", "alerts_table")):
        items = scan_all(ddb.Table(out[key]))
        with open(os.path.join(dest, name + ".json"), "w") as f:
            json.dump(items, f, default=str, indent=1)
        print("%-14s %5d items -> results/export/%s.json" % (name, len(items), name))
    s3 = boto3.client("s3", region_name="us-east-1")
    n = 0
    for page in s3.get_paginator("list_objects_v2").paginate(Bucket=out["StateBucketName"], Prefix="reports/"):
        for obj in page.get("Contents", []):
            s3.download_file(out["StateBucketName"], obj["Key"], os.path.join(dest, "reports", os.path.basename(obj["Key"])))
            n += 1
    print("%d report file(s) -> results/export/reports/" % n)
    print("\nREMINDER: these files contain account ids / user names - remove or replace them before publishing.")


if __name__ == "__main__":
    main()
