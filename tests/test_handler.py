"""Run the real Lambda handler against mocked AWS (moto): S3 state, DynamoDB dedupe, SNS, bootstrap."""
import importlib
import json
import os
import sys

import boto3
import pytest
from moto import mock_aws

from iamwatch import labspec as L
from iamwatch import synth
from iamwatch.engine import Engine

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "lambda_src"))
ACCT = "123456789012"


@pytest.fixture
def aws(monkeypatch):
    monkeypatch.setenv("AWS_DEFAULT_REGION", "us-east-1")
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")
    with mock_aws():
        s3 = boto3.client("s3")
        s3.create_bucket(Bucket="state-bucket")
        ddb = boto3.client("dynamodb")
        for name, key in (("events", "eventID"), ("alerts", "alertId")):
            ddb.create_table(TableName=name, KeySchema=[{"AttributeName": key, "KeyType": "HASH"}],
                             AttributeDefinitions=[{"AttributeName": key, "AttributeType": "S"}],
                             BillingMode="PAY_PER_REQUEST")
        topic = boto3.client("sns").create_topic(Name="alerts")["TopicArn"]
        monkeypatch.setenv("STATE_BUCKET", "state-bucket")
        monkeypatch.setenv("EVENTS_TABLE", "events")
        monkeypatch.setenv("ALERTS_TABLE", "alerts")
        monkeypatch.setenv("TOPIC_ARN", topic)
        import handler
        importlib.reload(handler)
        handler._clients.clear()
        handler._cache.update(etag=None, engine=None)
        yield handler


def seed_state(handler):
    eng = Engine.from_snapshot(L.lab_authorization_details(ACCT))
    handler.save_engine(eng)
    handler._cache.update(etag=None, engine=None)


def sqs_event(details, sent=1_700_000_000_000):
    return {"Records": [{"messageId": "m%d" % i, "body": json.dumps({"detail-type": "AWS API Call via CloudTrail",
                                                                     "detail": d}),
                         "attributes": {"SentTimestamp": str(sent)}} for i, d in enumerate(details)]}


def alerts_in_table():
    return boto3.resource("dynamodb").Table("alerts").scan()["Items"]


def test_attack_produces_alert_and_state_is_saved(aws):
    seed_state(aws)
    evs = synth.scenario_events("s1", ACCT, 1_000_000)
    out = aws.handler(sqs_event(evs), None)
    assert out == {"batchItemFailures": []}
    items = alerts_in_table()
    assert {i["level"] for i in items} == {"WATCH", "ACTIVE"}
    active = [i for i in items if i["level"] == "ACTIVE"][0]
    assert "dev-user" in active["origin"] and "AttachRolePolicy" in active["path"]
    # state persisted with the new edge, posture report written
    s3 = boto3.client("s3")
    state = json.loads(s3.get_object(Bucket="state-bucket", Key="state/engine.json")["Body"].read())
    assert any(e[2] == "HasAdmin" and e[0] == "role:eks-worker-role" for e in state["graph"]["edges"])
    assert "Contents" in s3.list_objects_v2(Bucket="state-bucket", Prefix="reports/")


def test_duplicate_events_are_ignored(aws):
    seed_state(aws)
    evs = synth.scenario_events("s2", ACCT, 1_000_000)
    aws.handler(sqs_event(evs), None)
    n = len(alerts_in_table())
    aws.handler(sqs_event(evs), None)       # redelivery
    assert len(alerts_in_table()) == n


def test_unparseable_record_fails_it_and_everything_after(aws):
    seed_state(aws)
    good = synth.scenario_events("s5", ACCT, 1_000_000)[0]
    ev = {"Records": [{"messageId": "a", "body": "{not json", "attributes": {}},
                      {"messageId": "b", "body": json.dumps({"detail": good}), "attributes": {}}]}
    out = aws.handler(ev, None)
    assert [f["itemIdentifier"] for f in out["batchItemFailures"]] == ["a", "b"]


def test_evasion_event_alerts(aws):
    seed_state(aws)
    d = synth.make_event("StopLogging", synth.user_actor(ACCT, "ops-user", synth.KEYS["ops-user"]),
                         {"name": "trail"}, None, 1_000_000)
    d["eventSource"] = "cloudtrail.amazonaws.com"
    aws.handler(sqs_event([d]), None)
    assert [i["level"] for i in alerts_in_table()] == ["EVASION"]


def test_bootstrap_from_live_iam_when_no_state(aws):
    iam = boto3.client("iam")
    iam.create_user(UserName="alice")
    iam.create_role(RoleName="r", AssumeRolePolicyDocument=json.dumps(L.trust_user(ACCT, "alice")))
    iam.put_user_policy(UserName="alice", PolicyName="p", PolicyDocument=json.dumps(
        {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "sts:AssumeRole", "Resource": "*"}]}))
    pol = iam.create_policy(PolicyName="my-admin", PolicyDocument=json.dumps(L.ADMIN_DOC))["Policy"]["Arn"]
    iam.attach_role_policy(RoleName="r", PolicyArn=pol)
    out = aws.handler(sqs_event([synth.benign_events(ACCT, 1_000_000)[0]]), None)
    assert out == {"batchItemFailures": []}
    eng = aws.load_engine()
    assert "user:alice" in eng.state.nodes
    assert eng.graph.dist.get("user:alice") == 2          # alice -AssumeRole-> r -HasAdmin-> ADMIN
    assert eng.graph.dist.get("role:r") == 1


def test_reconcile_reports_zero_drift_for_consistent_state(aws):
    iam = boto3.client("iam")
    iam.create_user(UserName="alice")
    aws.handler(sqs_event([synth.benign_events(ACCT, 1_000_000)[0]]), None)   # bootstraps state
    rep = aws.handler({"action": "reconcile"}, None)
    assert rep["drift"] >= 0 and "missing_in_live" in rep


class FakeCloudTrail:
    """Returns the given raw CloudTrail records for every LookupEvents call (one page)."""
    def __init__(self, records):
        self.records = records

    def lookup_events(self, **kw):
        if kw["LookupAttributes"][0]["AttributeValue"] != "iam.amazonaws.com" and kw["LookupAttributes"][0]["AttributeValue"] != "sts.amazonaws.com":
            return {"Events": []}
        return {"Events": [{"CloudTrailEvent": json.dumps(r)} for r in self.records
                           if (r["eventSource"] == kw["LookupAttributes"][0]["AttributeValue"])]}


def test_gapfill_recovers_lost_events_and_the_attack_is_detected(aws, monkeypatch):
    """Drop the first hop of S1 on the normal path; gap-fill must find it in the event history, queue it,
    and the engine must then raise ACTIVE once both steps are known."""
    seed_state(aws)
    sqs = boto3.client("sqs")
    q = sqs.create_queue(QueueName="q.fifo", Attributes={"FifoQueue": "true", "ContentBasedDeduplication": "true"})["QueueUrl"]
    monkeypatch.setattr(aws, "QUEUE_URL", q)
    evs = synth.scenario_events("s1", ACCT, 1_000_000)
    for e in evs:
        e.setdefault("eventSource", "sts.amazonaws.com" if e["eventName"] == "AssumeRole" else "iam.amazonaws.com")
    aws.handler(sqs_event(evs[1:]), None)                      # AssumeRole was lost
    # without the AssumeRole the chain cannot be traced back to dev-user (the role itself is blamed)
    assert not any(i["level"] == "ACTIVE" and i["origin"].endswith("/dev-user") for i in alerts_in_table())
    aws._clients["cloudtrail"] = FakeCloudTrail(evs)
    out = aws.handler({"action": "gapfill", "lookback_minutes": 60, "min_age_seconds": 0}, None)
    assert out["sent"] == 1 and out["names"] == ["AssumeRole"] and out["already_known"] == 1
    msgs = sqs.receive_message(QueueUrl=q, MaxNumberOfMessages=10).get("Messages", [])
    assert len(msgs) == 1
    body = json.loads(msgs[0]["Body"])
    assert body["via"] == "gapfill"
    aws.handler({"Records": [{"messageId": "g1", "body": msgs[0]["Body"], "attributes": {"SentTimestamp": "1"}}]}, None)
    assert any(i["level"] == "ACTIVE" and i["origin"].endswith("/dev-user") for i in alerts_in_table())
    # a second gap-fill finds nothing new
    assert aws.handler({"action": "gapfill", "min_age_seconds": 0}, None)["sent"] == 0
