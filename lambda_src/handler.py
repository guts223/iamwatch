"""AWS Lambda entry point.

Triggered by an SQS FIFO queue that receives CloudTrail events from EventBridge.  The FIFO
queue uses one message group, so events are processed one batch at a time and in order.

Per invocation:
    1. load the engine state from S3 (or bootstrap it from IAM on first run)
    2. for each SQS record: de-duplicate (DynamoDB conditional write), feed the engine,
       store any alerts (DynamoDB) and notify (SNS)
    3. save the engine state back to S3 and refresh the posture report

A second trigger (EventBridge schedule, input {"action": "reconcile"}) re-downloads the whole
IAM state, rebuilds a fresh engine and writes a drift report (live graph vs. fresh graph).

A third trigger (schedule every 5 minutes, input {"action": "gapfill"}) re-reads recent IAM/STS
events from the CloudTrail event history (LookupEvents) and sends the ones the stack never received
into the SAME FIFO queue, so lost EventBridge deliveries are recovered and are still processed one
at a time and in order.  It never touches the engine state itself.
"""
import json
import logging
import os
import time
from decimal import Decimal

import boto3
from botocore.exceptions import ClientError

from iamwatch import events as E
from iamwatch.awsio import get_authorization_details, make_policy_fetcher
from iamwatch.engine import Engine
from iamwatch.model import name_of

log = logging.getLogger()
log.setLevel(logging.INFO)

STATE_BUCKET = os.environ.get("STATE_BUCKET", "")
STATE_KEY = os.environ.get("STATE_KEY", "state/engine.json")
EVENTS_TABLE = os.environ.get("EVENTS_TABLE", "")
ALERTS_TABLE = os.environ.get("ALERTS_TABLE", "")
TOPIC_ARN = os.environ.get("TOPIC_ARN", "")
K = int(os.environ.get("MAX_HOPS", "5"))
WINDOW = int(os.environ.get("WINDOW_SECONDS", "3600"))
LINKED_WINDOW = int(os.environ.get("LINKED_WINDOW_SECONDS", "43200"))
QUEUE_URL = os.environ.get("QUEUE_URL", "")
COOLDOWN = int(os.environ.get("COOLDOWN_SECONDS", "3600"))
ALLOWLIST = [a.strip() for a in os.environ.get("ALLOWLIST", "").split(",") if a.strip()]
NOTIFY_WATCH = os.environ.get("NOTIFY_WATCH", "false").lower() == "true"
TTL_DAYS = int(os.environ.get("TTL_DAYS", "14"))

_clients = {}
_cache = {"etag": None, "engine": None}


def client(name):
    if name not in _clients:
        _clients[name] = boto3.client(name)
    return _clients[name]


def table(name):
    return boto3.resource("dynamodb").Table(name)


def now_ms():
    return int(time.time() * 1000)


# --------------------------------------------------------------------------- state in S3
def new_engine():
    iam = client("iam")
    return dict(k=K, window=WINDOW, linked_window=LINKED_WINDOW, cooldown=COOLDOWN, allowlist=ALLOWLIST,
                fetcher=make_policy_fetcher(iam))


def load_engine():
    s3 = client("s3")
    try:
        head = s3.head_object(Bucket=STATE_BUCKET, Key=STATE_KEY)
    except ClientError as e:
        if e.response["Error"]["Code"] not in ("404", "NoSuchKey", "NotFound"):
            raise
        log.info("no state found: bootstrapping from a fresh IAM snapshot")
        engine = Engine.from_snapshot(get_authorization_details(client("iam")), **new_engine())
        _cache.update(etag=None, engine=engine)
        return engine
    etag = head["ETag"]
    if _cache["engine"] is not None and _cache["etag"] == etag:
        return _cache["engine"]
    body = s3.get_object(Bucket=STATE_BUCKET, Key=STATE_KEY)["Body"].read().decode("utf-8")
    engine = Engine.loads(body, fetcher=make_policy_fetcher(client("iam")))
    # settings from the environment always win over what was stored
    engine.k, engine.window, engine.cooldown = K, WINDOW, COOLDOWN
    engine.linked_window = LINKED_WINDOW
    engine.allowlist = set(ALLOWLIST)
    _cache.update(etag=etag, engine=engine)
    return engine


def save_engine(engine):
    s3 = client("s3")
    resp = s3.put_object(Bucket=STATE_BUCKET, Key=STATE_KEY, Body=engine.dumps().encode("utf-8"),
                         ContentType="application/json")
    _cache.update(etag=resp.get("ETag"), engine=engine)


def write_report(key, obj):
    client("s3").put_object(Bucket=STATE_BUCKET, Key=key, Body=json.dumps(obj, indent=1).encode("utf-8"),
                            ContentType="application/json")


# --------------------------------------------------------------------------- alerts
def describe_path(alert):
    parts = []
    for i, hop in enumerate(alert.get("path", [])):
        if i == 0:
            parts.append(name_of(hop["src"]) if hop["src"] != "ADMIN" else "ADMIN")
        parts.append("--%s--> %s" % (hop["technique"], name_of(hop["dst"]) if hop["dst"] != "ADMIN" else "ADMIN"))
    return " ".join(parts)


def store_and_notify(alert, received_ms):
    detected = now_ms()
    last_matched = max([e["time"] for e in alert.get("matched_events", [])] or [alert.get("trigger_time", 0)])
    item = {
        "alertId": "%d#%s#%s" % (int(alert.get("trigger_time", 0) * 1000), alert.get("fingerprint", "x"), alert["level"]),
        "level": alert["level"],
        "origin": alert.get("origin", ""),
        "fingerprint": alert.get("fingerprint", ""),
        "trigger_event": alert.get("trigger_event", ""),
        "trigger_time_ms": int(alert.get("trigger_time", 0) * 1000),
        "last_matched_time_ms": int(last_matched * 1000),
        "detected_ms": detected,
        "lambda_received_ms": received_ms,
        "latency_ms": detected - int(alert.get("trigger_time", 0) * 1000),
        "matched_count": alert.get("matched_count", 0),
        "required_count": alert.get("required_count", 0),
        "linked": bool(alert.get("linked", False)),
        "path": describe_path(alert) if alert.get("path") else alert.get("detail", ""),
        "alert_json": json.dumps(alert),
        "ttl": int(time.time()) + TTL_DAYS * 86400,
    }
    table(ALERTS_TABLE).put_item(Item=item)
    notify = alert["level"] in ("ACTIVE", "EVASION") or (alert["level"] == "WATCH" and NOTIFY_WATCH)
    if notify and TOPIC_ARN:
        who = alert.get("origin", "").rsplit("/", 1)[-1]
        subject = ("[iamwatch] %s %s" % (alert["level"], who))[:99]
        lines = ["Level: %s" % alert["level"], "Origin: %s" % alert.get("origin", ""),
                 "Path: %s" % item["path"],
                 "Matched events: %s" % ", ".join("%s@%s" % (e["name"], int(e["time"]))
                                                  for e in alert.get("matched_events", [])),
                 "Trigger event: %s" % alert.get("trigger_event", ""),
                 "Detection latency (ms since CloudTrail eventTime): %d" % item["latency_ms"]]
        client("sns").publish(TopicArn=TOPIC_ARN, Subject=subject, Message="\n".join(lines))
    return item


# --------------------------------------------------------------------------- one SQS record
def process_record(engine, record):
    received = now_ms()
    body = json.loads(record["body"])
    detail = body.get("detail", body)          # tolerate raw CloudTrail records
    event_id = detail.get("eventID", "")
    name = detail.get("eventName", "")
    sent = int((record.get("attributes") or {}).get("SentTimestamp", 0) or 0)
    ev_time = detail.get("eventTime", "")
    # ---- de-duplicate (EventBridge delivers at-least-once)
    via = body.get("via", "eventbridge")
    item = {"eventID": event_id, "eventName": name, "eventTime": ev_time, "via": via,
            "principal": ((detail.get("userIdentity") or {}).get("arn") or "")[:200],
            "sqs_sent_ms": sent, "lambda_received_ms": received,
            "ttl": int(time.time()) + TTL_DAYS * 86400,
            "raw": json.dumps(detail)[:300000]}
    try:
        table(EVENTS_TABLE).put_item(Item=item, ConditionExpression="attribute_not_exists(eventID)")
    except ClientError as e:
        if e.response["Error"]["Code"] == "ConditionalCheckFailedException":
            log.info("duplicate event %s ignored", event_id)
            return []
        raise
    alerts = []
    if name in E.EVASION_EVENTS and not detail.get("errorCode"):
        alerts.append({"level": "EVASION", "origin": ((detail.get("userIdentity") or {}).get("arn") or ""),
                       "trigger_event": event_id, "trigger_time": E._parse_time(ev_time),
                       "fingerprint": "evasion-" + event_id[:8], "path": [],
                       "detail": "%s by %s" % (name, (detail.get("userIdentity") or {}).get("arn", "?")),
                       "matched_events": []})
    else:
        alerts.extend(engine.process(detail, late=(via == "gapfill")))
    stats = dict(engine.last_stats)
    stored = [store_and_notify(a, received) for a in alerts]
    try:
        table(EVENTS_TABLE).update_item(
            Key={"eventID": event_id},
            UpdateExpression="SET #pm = :p, #st = :s",
            ExpressionAttributeNames={"#pm": "processed_ms", "#st": "engine_stats"},
            ExpressionAttributeValues={":p": now_ms(), ":s": json.dumps(stats)})
    except ClientError:
        log.exception("could not update processing timestamps")
    return stored


# --------------------------------------------------------------------------- reconcile
def reconcile():
    live = load_engine()
    fresh = Engine.from_snapshot(get_authorization_details(client("iam")), **new_engine())
    a, b = live.graph.edge_set(), fresh.graph.edge_set()
    report = {"time": int(time.time()), "live_edges": len(a), "fresh_edges": len(b),
              "missing_in_live": sorted(map(list, b - a)), "extra_in_live": sorted(map(list, a - b)),
              "drift": len(b - a) + len(a - b),
              "note": "events still queued or in flight at snapshot time can appear as transient drift"}
    write_report("reports/drift-%d.json" % report["time"], report)
    log.info("reconcile: drift=%d", report["drift"])
    return report


# --------------------------------------------------------------------------- gap fill
GAPFILL_SOURCES = ["iam.amazonaws.com", "sts.amazonaws.com", "lambda.amazonaws.com",
                   "ec2.amazonaws.com", "cloudformation.amazonaws.com"]


def gapfill(lookback_minutes=60, min_age_seconds=90):
    """Recover events that never reached the queue (EventBridge delivery is best effort).

    Reads the CloudTrail event history, keeps the event names the engine uses, skips events younger than
    `min_age_seconds` (still on their normal way) and events already in the events table, and sends the
    rest to the FIFO queue in time order.  Returns a small summary."""
    end = time.time() - min_age_seconds
    start = end - lookback_minutes * 60
    try:        # scripts/reset_stack_data.py writes a marker so that old, already-handled events are not recovered
        nb = float(client("s3").get_object(Bucket=STATE_BUCKET, Key="state/gapfill_not_before")["Body"].read().decode())
        start = max(start, nb)
    except (ClientError, ValueError):
        pass
    ct = client("cloudtrail")
    found = {}
    for src in GAPFILL_SOURCES:
        kw = dict(LookupAttributes=[{"AttributeKey": "EventSource", "AttributeValue": src}],
                  StartTime=start, EndTime=end, MaxResults=50)
        while True:
            resp = ct.lookup_events(**kw)
            for e in resp.get("Events", []):
                try:
                    detail = json.loads(e["CloudTrailEvent"])
                except (KeyError, ValueError):
                    continue
                if detail.get("eventName") in E.EVIDENCE_EVENTS or detail.get("eventName") in E.EVASION_EVENTS:
                    found[detail["eventID"]] = detail
            if not resp.get("NextToken"):
                break
            kw["NextToken"] = resp["NextToken"]
    ids = list(found)
    known = set()
    ddb = boto3.client("dynamodb")
    for i in range(0, len(ids), 100):
        chunk = ids[i:i + 100]
        resp = ddb.batch_get_item(RequestItems={EVENTS_TABLE: {"Keys": [{"eventID": {"S": x}} for x in chunk],
                                                               "ProjectionExpression": "eventID"}})
        known |= {r["eventID"]["S"] for r in resp["Responses"].get(EVENTS_TABLE, [])}
    missing = sorted((found[x] for x in ids if x not in known), key=lambda d: d.get("eventTime", ""))
    for d in missing:
        client("sqs").send_message(QueueUrl=QUEUE_URL, MessageGroupId="iamwatch",
                                   MessageDeduplicationId=d["eventID"],
                                   MessageBody=json.dumps({"detail-type": "AWS API Call via CloudTrail",
                                                           "source": "iamwatch.gapfill", "via": "gapfill",
                                                           "detail": d}))
    out = {"found": len(found), "already_known": len(known), "sent": len(missing),
           "names": sorted({d["eventName"] for d in missing})}
    log.info("gapfill: %s", out)
    return out


# --------------------------------------------------------------------------- entry point
def handler(event, context):
    if isinstance(event, dict) and event.get("action") == "reconcile":
        return reconcile()
    if isinstance(event, dict) and event.get("action") == "gapfill":
        return gapfill(int(event.get("lookback_minutes", 60)), int(event.get("min_age_seconds", 90)))
    engine = load_engine()
    failures = []
    processed = 0
    records = event.get("Records", [])
    for i, rec in enumerate(records):
        try:
            process_record(engine, rec)
            processed += 1
        except Exception:                               # noqa: BLE001
            log.exception("failed to process %s", rec.get("messageId"))
            # FIFO ordering: fail this record and every record after it
            failures = [{"itemIdentifier": r["messageId"]} for r in records[i:]]
            break
    if processed:
        save_engine(engine)
        if engine.graph_dirty:
            write_report("reports/posture.json", engine.posture())
            engine.graph_dirty = False
    return {"batchItemFailures": failures}
