#!/usr/bin/env python3
"""Find out WHERE the pipeline is stuck.  Read-only: it changes nothing in AWS.

    python scripts/diagnose.py [--minutes 120] [--stack-name iamwatch]

It walks the chain in order and prints OK / PROBLEM for each link:
    CloudTrail recorded the attack -> trail exists -> EventBridge rule matched -> messages reached the queue
    -> Lambda ran without errors -> events were stored -> alerts were created
"""
import argparse
import time
from datetime import datetime, timedelta, timezone

import boto3

REGION = "us-east-1"
ATTACK_EVENTS = ["AssumeRole", "AttachRolePolicy", "CreatePolicyVersion", "UpdateAssumeRolePolicy",
                 "CreateFunction20150331", "CreateAccessKey"]


def section(title):
    print("\n== " + title)


def safe(fn, label):
    try:
        return fn()
    except Exception as e:                                   # noqa: BLE001
        print("   ! could not check %s: %s" % (label, str(e)[:200]))
        return None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--minutes", type=int, default=120)
    ap.add_argument("--stack-name", default="iamwatch")
    args = ap.parse_args()
    s = boto3.session.Session(region_name=REGION)
    now = datetime.now(timezone.utc)
    start = now - timedelta(minutes=args.minutes)
    verdict = []

    section("1. Stack")
    cfn = s.client("cloudformation")
    st = safe(lambda: cfn.describe_stacks(StackName=args.stack_name)["Stacks"][0], "stack")
    if not st:
        print("   PROBLEM: stack '%s' not found in %s" % (args.stack_name, REGION))
        return
    outs = {o["OutputKey"]: o["OutputValue"] for o in st.get("Outputs", [])}
    print("   status:", st["StackStatus"])
    status = st["StackStatus"]
    if status == "UPDATE_ROLLBACK_COMPLETE":
        print("   note: an earlier update failed and was rolled back. The stack keeps running the previous good "
              "version - this is normal and not a problem.")
    elif not status.endswith("_COMPLETE") or status in ("ROLLBACK_COMPLETE", "ROLLBACK_FAILED", "UPDATE_ROLLBACK_FAILED"):
        verdict.append("The stack is not healthy (%s). Fix the deployment first." % status)
    fn = args.stack_name + "-engine"
    rule_name = None

    section("2. Did AWS (CloudTrail) record your attack in the last %d minutes?" % args.minutes)
    ct = s.client("cloudtrail")
    seen = {}

    def lookup():
        for name in ATTACK_EVENTS:
            r = ct.lookup_events(LookupAttributes=[{"AttributeKey": "EventName", "AttributeValue": name}],
                                 StartTime=start, EndTime=now, MaxResults=50)
            seen[name] = len(r.get("Events", []))
            time.sleep(0.6)
    safe(lookup, "CloudTrail event history")
    for k, v in seen.items():
        print("   %-26s %d" % (k, v))
    recorded = sum(seen.values())
    if seen and recorded == 0:
        verdict.append("CloudTrail has no attack events in this window: the attack did not run, or you used a different region/account.")

    section("3. Is there a CloudTrail trail? (AWS requires one for management events to reach EventBridge)")
    trails = safe(lambda: ct.describe_trails(includeShadowTrails=False)["trailList"], "trails") or []
    for t in trails:
        status = safe(lambda: ct.get_trail_status(Name=t["TrailARN"]), "trail status") or {}
        print("   trail %s  home=%s multi-region=%s logging=%s" % (
            t["Name"], t.get("HomeRegion"), t.get("IsMultiRegionTrail"), status.get("IsLogging")))
    for t in trails:
        sel = safe(lambda: ct.get_event_selectors(TrailName=t["TrailARN"]), "event selectors") or {}
        for es in sel.get("EventSelectors", []):
            print("   trail records: %s management events" % es.get("ReadWriteType"))
            if t["Name"].endswith("-trail") and es.get("ReadWriteType") != "All":
                verdict.append("The trail records only %s events, but AssumeRole is a READ-ONLY event: it must record 'All'. "
                               "Redeploy with the updated template." % es.get("ReadWriteType"))
    if not trails:
        print("   PROBLEM: no trail found")
        verdict.append("No CloudTrail trail exists. Redeploy with the updated template (it creates one).")

    section("4. EventBridge rule")
    ev = s.client("events")
    rules = safe(lambda: ev.list_rules(NamePrefix=args.stack_name)["Rules"], "rules") or []
    for r in rules:
        print("   %-60s state=%s" % (r["Name"], r.get("State")))
        if "IamEventRule" in r["Name"]:
            rule_name = r["Name"]
            if r.get("State") != "ENABLED_WITH_ALL_CLOUDTRAIL_MANAGEMENT_EVENTS":
                verdict.append("The rule state is '%s'. It must be ENABLED_WITH_ALL_CLOUDTRAIL_MANAGEMENT_EVENTS: "
                               "redeploy with the updated template." % r.get("State"))
    cw = s.client("cloudwatch")
    if rule_name:
        def metric(name):
            r = cw.get_metric_statistics(Namespace="AWS/Events", MetricName=name,
                                         Dimensions=[{"Name": "RuleName", "Value": rule_name}],
                                         StartTime=start, EndTime=now, Period=3600, Statistics=["Sum"])
            return int(sum(p["Sum"] for p in r["Datapoints"]))
        trig = safe(lambda: metric("TriggeredRules"), "rule metrics")
        failed = safe(lambda: metric("FailedInvocations"), "rule metrics")
        print("   rule matched events: %s   failed deliveries to the queue: %s" % (trig, failed))
        if trig == 0 and recorded:
            verdict.append("CloudTrail recorded events but the rule matched NONE: events are not reaching EventBridge "
                           "(missing trail / rule state / wrong region). Redeploy with the updated template, then rerun the attack.")
        if failed:
            verdict.append("The rule matched events but could not deliver them to the queue (queue policy?).")

    section("5. Queues")
    sqs = s.client("sqs")
    for key in ("QueueUrl", "DeadLetterQueueUrl"):
        url = outs.get(key)
        if not url:
            continue
        a = safe(lambda: sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["All"])["Attributes"], "queue") or {}
        print("   %-20s waiting=%s in-flight=%s" % (key, a.get("ApproximateNumberOfMessages"),
                                                     a.get("ApproximateNumberOfMessagesNotVisible")))
        if key == "DeadLetterQueueUrl" and int(a.get("ApproximateNumberOfMessages", 0) or 0) > 0:
            verdict.append("Messages are in the dead-letter queue: the Lambda failed on them 5 times. See the Lambda errors below.")

    section("6. Lambda (%s)" % fn)
    lam = s.client("lambda")
    safe(lambda: print("   runtime=%s timeout=%ss" % (lambda c: (c["Runtime"], c["Timeout"]))(lam.get_function_configuration(FunctionName=fn))), "lambda config")
    for name in ("Invocations", "Errors", "Throttles"):
        v = safe(lambda: int(sum(p["Sum"] for p in cw.get_metric_statistics(
            Namespace="AWS/Lambda", MetricName=name, Dimensions=[{"Name": "FunctionName", "Value": fn}],
            StartTime=start, EndTime=now, Period=3600, Statistics=["Sum"])["Datapoints"])), "lambda metrics")
        print("   %-12s %s" % (name, v))
        if name == "Errors" and v:
            verdict.append("The Lambda reported %d errors. The log lines below show why." % v)
    logs = s.client("logs")

    def errs():
        r = logs.filter_log_events(logGroupName="/aws/lambda/" + fn, startTime=int(start.timestamp() * 1000),
                                   filterPattern="?ERROR ?Traceback ?Exception ?AccessDenied", limit=15)
        for e in r.get("events", [])[-12:]:
            print("   LOG:", e["message"].strip().replace("\n", " | ")[:230])
        return len(r.get("events", []))
    n = safe(errs, "Lambda log errors")
    if n == 0:
        print("   no error lines in the log")

    section("7. Stored data")
    ddb = s.client("dynamodb")
    counts = {}
    for key in ("EventsTableName", "AlertsTableName"):
        t = outs.get(key)
        counts[key] = safe(lambda: ddb.scan(TableName=t, Select="COUNT")["Count"], key)
        print("   %-18s %s items" % (key, counts[key]))
    s3 = s.client("s3")
    safe(lambda: print("   state file: %s bytes" % s3.head_object(Bucket=outs["StateBucketName"],
                                                                   Key="state/engine.json")["ContentLength"]), "state file")
    if recorded and counts.get("EventsTableName") == 0 and not verdict:
        verdict.append("Events were recorded but none reached the Lambda. Check sections 4-5 above.")
    if counts.get("EventsTableName") and counts.get("AlertsTableName") == 0 and not verdict:
        verdict.append("Events were processed but no alert was raised. Send me the output of "
                       "'python scripts/fetch_events.py' + 'python scripts/check_fields.py' so I can compare the real fields.")

    section("VERDICT")
    if not verdict:
        print("   no problem found in the chain. If alerts are still missing, wait a few more minutes and run show_alerts.py.")
    for v in verdict:
        print("   -", v)


if __name__ == "__main__":
    main()
