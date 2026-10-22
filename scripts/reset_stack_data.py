#!/usr/bin/env python3
"""Give the DEPLOYED stack a clean slate before a new experiment run (same AWS account, new results).

    python scripts/reset_stack_data.py

  * deletes the saved engine state in S3 (the engine re-reads the real IAM account at the next event)
  * empties the events table and the alerts table (old runs would pollute the new tables and counts)
  * writes a "not before" marker so the 5-minute gap-fill job does not re-import events that happened before now
  * empties the queues
Does NOT touch the IAM lab, your AWS credentials, build\\outputs.json or lab\\lab_credentials.json.
Run it when nothing is running; wait ~1 minute afterwards before starting attacks.
"""
import json
import os
import sys
import time

import boto3

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
REGION = "us-east-1"


def empty_table(ddb, name, key):
    t = ddb.Table(name)
    n = 0
    resp = t.scan(ProjectionExpression=key if key not in ("level",) else key)
    while True:
        with t.batch_writer() as bw:
            for it in resp["Items"]:
                bw.delete_item(Key={key: it[key]})
                n += 1
        if "LastEvaluatedKey" not in resp:
            break
        resp = t.scan(ProjectionExpression=key, ExclusiveStartKey=resp["LastEvaluatedKey"])
    return n


def main():
    out = json.load(open(os.path.join(ROOT, "build", "outputs.json")))
    s3 = boto3.client("s3", region_name=REGION)
    ddb = boto3.resource("dynamodb", region_name=REGION)
    sqs = boto3.client("sqs", region_name=REGION)
    s3.delete_object(Bucket=out["StateBucketName"], Key="state/engine.json")
    print("engine state deleted")
    print("events table: %d items deleted" % empty_table(ddb, out["EventsTableName"], "eventID"))
    print("alerts table: %d items deleted" % empty_table(ddb, out["AlertsTableName"], "alertId"))
    s3.put_object(Bucket=out["StateBucketName"], Key="state/gapfill_not_before", Body=str(time.time()).encode())
    print("gap-fill marker written")
    for k in ("QueueUrl", "DeadLetterQueueUrl"):
        if k in out:
            try:
                sqs.purge_queue(QueueUrl=out[k])
                print("purged", k)
            except Exception as e:                       # noqa: BLE001  (purge is limited to once a minute)
                print("could not purge %s: %s" % (k, e))
    print("done - wait 1 minute before running attacks")


if __name__ == "__main__":
    main()
