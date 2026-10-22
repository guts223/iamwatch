"""Run the real lab scripts (setup, attacks, reset) against mocked AWS and check that the
lab account they create has exactly the escalation paths the engine expects."""
import importlib.util
import json
import os
import sys

import boto3
import pytest
from moto import mock_aws

ROOT = os.path.join(os.path.dirname(__file__), "..")
sys.path.insert(0, os.path.join(ROOT, "src"))

from iamwatch import labspec as L
from iamwatch.awsio import get_authorization_details
from iamwatch.engine import Engine


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, os.path.join(ROOT, path))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture
def lab(monkeypatch, tmp_path):
    monkeypatch.setenv("AWS_DEFAULT_REGION", "us-east-1")
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")
    monkeypatch.setenv("MOTO_IAM_LOAD_MANAGED_POLICIES", "true")
    with mock_aws():
        setup = load("setup_lab", "lab/setup_lab.py")
        attacks = load("attacks", "lab/attacks.py")
        setup.CRED_FILE = attacks.CRED_FILE = str(tmp_path / "creds.json")
        setup.time.sleep = lambda s: None
        attacks.time.sleep = lambda s: None
        iam = boto3.client("iam")
        acct = boto3.client("sts").get_caller_identity()["Account"]
        setup.create(iam, acct)
        yield setup, attacks, iam, acct


def test_lab_account_has_expected_posture(lab):
    setup, attacks, iam, acct = lab
    eng = Engine.from_snapshot(get_authorization_details(iam))
    paths = {r["principal"]: r["hops"] for r in eng.posture()["escalation_paths"]}
    expected = {"user:dev-user": 2, "user:ci-user": 1, "user:ops-user": 2, "user:deploy-user": 2,
                "user:helpdesk-user": 2}
    for k, v in expected.items():
        assert paths.get(k) == v, (k, paths)
    assert "role:readonly-role" not in paths
    # the in-memory spec and the account created by the script agree
    mem = Engine.from_snapshot(L.full_authorization_details(acct))
    names = L.USERS + L.ROLES + L.USERS_X + L.ROLES_X + L.GROUPS_X
    live_edges = {e[:4] for e in eng.graph.edge_set() if e[0].split(":")[1] in names}
    mem_edges = {e[:4] for e in mem.graph.edge_set()}
    assert live_edges == mem_edges
    for k in ("user:chain-user", "user:joiner-user", "user:selfput-user", "user:rollback-user"):
        assert k in paths, (k, sorted(paths))
    assert "user:normal-user" not in paths and "role:app-lambda-role" not in paths


@pytest.mark.parametrize("kind", ["s1", "s2", "s3", "s4", "s5", "x1", "x2", "x3", "x4"])
def test_attack_then_reset_roundtrip(lab, kind):
    setup, attacks, iam, acct = lab
    before = Engine.from_snapshot(get_authorization_details(iam)).graph.edge_set()
    rec = attacks.run(kind, acct)
    assert rec["scenario"] == kind
    after_attack = Engine.from_snapshot(get_authorization_details(iam))
    if kind in ("s1", "s2", "x2", "x3", "x4"):
        origin = {"s1": "role:eks-worker-role", "s2": "user:ci-user", "x2": "user:joiner-user",
                  "x3": "user:selfput-user", "x4": "user:rollback-user"}[kind]
        assert after_attack.graph.dist[origin] == 1
        assert any(e[2] == "HasAdmin" and e[0] == origin for e in after_attack.graph.edge_set())
    attacks.reset(acct)
    after_reset = Engine.from_snapshot(get_authorization_details(iam)).graph.edge_set()
    assert after_reset == before


def test_benign_runs(lab):
    setup, attacks, iam, acct = lab
    attacks.benign(acct)


def test_benign_load_operations_run_and_raise_no_active_alert(lab, monkeypatch):
    """Every benign operation executes against the (mock) account, and replaying their CloudTrail-like
    footprint never completes an escalation path."""
    setup, attacks, iam, acct = lab
    sys.path.insert(0, os.path.join(ROOT, "lab"))
    bl = load("benign_load", "lab/benign_load.py")
    bl.A.CRED_FILE = attacks.CRED_FILE
    bl.time.sleep = lambda s: None
    bl.A.time.sleep = lambda s: None
    for i, (name, fn) in enumerate(sorted(bl.OPS.items())):
        fn(acct, 1000 + i)           # raises if the operation itself is broken
    # nothing left behind that would change the posture
    eng = Engine.from_snapshot(get_authorization_details(iam))
    paths = {r["principal"] for r in eng.posture()["escalation_paths"]}
    assert not any(p.startswith(("user:benign", "role:benign")) for p in paths)
