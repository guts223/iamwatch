"""Drive experiments/run_attacks.py against mocked AWS: the deployed stack is replaced by the real
Lambda handler fed with synthetic events at the moment the (patched) attack functions run."""
import csv
import importlib.util
import json
import os
import sys
import time

import boto3
from moto import mock_aws

ROOT = os.path.join(os.path.dirname(__file__), "..")
sys.path.insert(0, os.path.join(ROOT, "src"))
sys.path.insert(0, os.path.join(ROOT, "lambda_src"))
from iamwatch import labspec as L  # noqa: E402
from iamwatch import synth  # noqa: E402
from iamwatch.engine import Engine  # noqa: E402


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, os.path.join(ROOT, path))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_run_attacks_end_to_end(monkeypatch, tmp_path):
    monkeypatch.setenv("AWS_DEFAULT_REGION", "us-east-1")
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")
    with mock_aws():
        boto3.client("s3").create_bucket(Bucket="state-bucket")
        ddb = boto3.client("dynamodb")
        for name, key in (("events", "eventID"), ("alerts", "alertId")):
            ddb.create_table(TableName=name, KeySchema=[{"AttributeName": key, "KeyType": "HASH"}],
                             AttributeDefinitions=[{"AttributeName": key, "AttributeType": "S"}],
                             BillingMode="PAY_PER_REQUEST")
        topic = boto3.client("sns").create_topic(Name="alerts")["TopicArn"]
        for k, v in dict(STATE_BUCKET="state-bucket", EVENTS_TABLE="events", ALERTS_TABLE="alerts",
                         TOPIC_ARN=topic, COOLDOWN_SECONDS="0").items():
            monkeypatch.setenv(k, v)
        import handler
        import importlib as il
        il.reload(handler)
        handler._clients.clear()
        acct = boto3.client("sts").get_caller_identity()["Account"]
        handler.save_engine(Engine.from_snapshot(L.lab_authorization_details(acct), cooldown=0))
        handler._cache.update(etag=None, engine=None)

        def feed(details):
            sent = str(int(time.time() * 1000))
            handler.handler({"Records": [{"messageId": d["eventID"], "body": json.dumps({"detail": d}),
                                          "attributes": {"SentTimestamp": sent}} for d in details]}, None)

        ra = load("run_attacks", "experiments/run_attacks.py")
        ra.time.sleep = lambda s: None
        ra.lab.account = lambda: acct
        counter = [0]

        def fake_reset(a):
            counter[0] += 1
            feed(synth.benign_events(acct, int(time.time()) - 1)[:1] and
                 [synth.make_event("DeleteRole", synth.user_actor(acct, "admin-user", synth.KEYS["admin-user"]),
                                   {"roleName": "gone-%d" % counter[0]}, None, time.time())])

        def fake_run(kind, a):
            t0 = time.time()
            feed(synth.scenario_events(kind, acct, int(t0), key_suffix="t%d" % counter[0]))
            return {"scenario": kind, "attack_start_epoch": t0, "attack_end_epoch": time.time()}

        ra.lab.reset, ra.lab.run = fake_reset, fake_run
        (tmp_path / "build").mkdir()
        (tmp_path / "build" / "outputs.json").write_text(json.dumps(
            {"EventsTableName": "events", "AlertsTableName": "alerts"}))
        ra.ROOT = str(tmp_path)
        out = str(tmp_path / "results" / "attacks_real.csv")
        monkeypatch.setattr(sys, "argv", ["run_attacks.py", "--scenarios", "s1", "s2", "--reps", "2", "--out", out])
        ra.main()
        rows = list(csv.DictReader(open(out)))
        assert len(rows) == 4
        assert all(r["detected"] == "1" for r in rows), rows
        assert all(r["rules_detected"] == "1" for r in rows), rows
        assert json.load(open(tmp_path / "results" / "batch_scan.json"))["runtime_s"] >= 0
