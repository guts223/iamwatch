import importlib.util
import json
import os

import boto3
from moto import mock_aws

ROOT = os.path.join(os.path.dirname(__file__), "..")


def test_reset_stack_data_empties_everything(monkeypatch, tmp_path):
    monkeypatch.setenv("AWS_DEFAULT_REGION", "us-east-1")
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")
    with mock_aws():
        s3 = boto3.client("s3")
        s3.create_bucket(Bucket="state-bkt")
        s3.put_object(Bucket="state-bkt", Key="state/engine.json", Body=b"{}")
        ddb = boto3.client("dynamodb")
        for name, key in (("ev", "eventID"), ("al", "alertId")):
            ddb.create_table(TableName=name, KeySchema=[{"AttributeName": key, "KeyType": "HASH"}],
                             AttributeDefinitions=[{"AttributeName": key, "AttributeType": "S"}], BillingMode="PAY_PER_REQUEST")
            for i in range(60):
                ddb.put_item(TableName=name, Item={key: {"S": "x%d" % i}})
        sqs = boto3.client("sqs")
        q = sqs.create_queue(QueueName="q.fifo", Attributes={"FifoQueue": "true"})["QueueUrl"]
        spec = importlib.util.spec_from_file_location("rs", os.path.join(ROOT, "scripts", "reset_stack_data.py"))
        rs = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(rs)
        (tmp_path / "build").mkdir()
        (tmp_path / "build" / "outputs.json").write_text(json.dumps(
            {"StateBucketName": "state-bkt", "EventsTableName": "ev", "AlertsTableName": "al", "QueueUrl": q}))
        rs.ROOT = str(tmp_path)
        rs.main()
        assert ddb.scan(TableName="ev")["Count"] == 0 and ddb.scan(TableName="al")["Count"] == 0
        keys = [o["Key"] for o in s3.list_objects_v2(Bucket="state-bkt").get("Contents", [])]
        assert keys == ["state/gapfill_not_before"]
