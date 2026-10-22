"""The EventBridge rule in the CloudFormation template must watch exactly the events the engine uses."""
import os

import yaml

from iamwatch import events as E

TEMPLATE = os.path.join(os.path.dirname(__file__), "..", "infra", "template.yaml")


class Loader(yaml.SafeLoader):
    pass


Loader.add_multi_constructor("!", lambda loader, suffix, node: None)


def load():
    with open(TEMPLATE) as f:
        return yaml.load(f, Loader=Loader)


def test_rule_watches_exactly_engine_events():
    t = load()
    pattern = t["Resources"]["IamEventRule"]["Properties"]["EventPattern"]
    assert sorted(pattern["detail"]["eventName"]) == E.WATCHED_EVENTS
    assert sorted(pattern["detail"]["eventSource"]) == sorted(E.WATCHED_SOURCES)


def test_rule_sends_to_fifo_with_message_group():
    t = load()
    target = t["Resources"]["IamEventRule"]["Properties"]["Targets"][0]
    assert target["SqsParameters"]["MessageGroupId"]
    assert t["Resources"]["EventQueue"]["Properties"]["FifoQueue"] is True
    assert t["Resources"]["EventQueue"]["Properties"]["VisibilityTimeout"] >= 6 * t["Resources"]["EngineFunction"]["Properties"]["Timeout"]


def test_all_event_sources_exist_for_every_engine_event():
    # every event name we use has a plausible source in the rule
    assert "iam.amazonaws.com" in E.WATCHED_SOURCES and "sts.amazonaws.com" in E.WATCHED_SOURCES


def test_trail_exists_and_rule_matches_management_events():
    """AWS only forwards management events to EventBridge rules when a trail exists and the rule
    state allows CloudTrail management events (found on the first real run)."""
    t = load()
    res = t["Resources"]
    assert res["Trail"]["Type"] == "AWS::CloudTrail::Trail"
    assert res["Trail"]["Properties"]["IncludeGlobalServiceEvents"] is True
    assert res["Trail"]["Properties"]["IsLogging"] is True
    # AssumeRole is a READ-ONLY management event: a write-only trail would never record it
    assert res["Trail"]["Properties"]["EventSelectors"][0]["ReadWriteType"] == "All"
    assert res["IamEventRule"]["Properties"]["State"] == "ENABLED_WITH_ALL_CLOUDTRAIL_MANAGEMENT_EVENTS"
    assert "TrailBucketName" in t["Outputs"]
