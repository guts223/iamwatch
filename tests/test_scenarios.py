"""The five attack scenarios + benign activity, on the in-memory lab account."""
import pytest

from iamwatch import labspec as L
from iamwatch import synth
from iamwatch.engine import Engine
from iamwatch.model import ADMIN

ACCT = "123456789012"


def make_engine(**kw):
    return Engine.from_snapshot(L.lab_authorization_details(ACCT), **kw)


def test_latent_paths_in_posture_report():
    eng = make_engine()
    rep = eng.posture()
    paths = {r["principal"]: r for r in rep["escalation_paths"]}
    for u in ["dev-user", "ci-user", "ops-user", "deploy-user", "helpdesk-user"]:
        assert "user:" + u in paths, u
    assert paths["user:dev-user"]["hops"] == 2
    assert paths["user:ci-user"]["hops"] == 1
    assert "user:admin-user" in rep["already_admin"]
    assert "role:admin-role" in rep["already_admin"]
    # readonly role must not be flagged
    assert "role:readonly-role" not in paths


def run_scenario(kind):
    eng = make_engine()
    alerts = []
    for d in synth.scenario_events(kind, ACCT, 1_000_000):
        alerts += eng.process(d)
    return eng, alerts


@pytest.mark.parametrize("kind", L.SCENARIOS)
def test_each_scenario_raises_active_alert(kind):
    eng, alerts = run_scenario(kind)
    active = [a for a in alerts if a["level"] == "ACTIVE"]
    assert active, (kind, alerts)
    assert active[-1]["origin"].endswith("/" + L.SCENARIO_ORIGIN[kind])
    assert active[-1]["matched_count"] == active[-1]["required_count"] >= 1
    ok, diffs = eng.check_equivalence()
    assert ok, diffs


def test_s1_first_hop_is_only_a_watch_then_active():
    eng = make_engine()
    evs = synth.scenario_events("s1", ACCT, 1_000_000)
    a1 = eng.process(evs[0])
    assert [a["level"] for a in a1] == ["WATCH"]
    a2 = eng.process(evs[1])
    assert [a["level"] for a in a2] == ["ACTIVE"]
    assert a2[0]["linked"] is True            # linked through the AssumeRole session key
    assert len(a2[0]["matched_events"]) == 2


def test_s1_makes_role_admin_in_graph():
    eng, _ = run_scenario("s1")
    assert eng.graph.dist["role:eks-worker-role"] == 1
    assert any(k[1] == "HasAdmin" for k in eng.graph.out["role:eks-worker-role"])


def test_benign_activity_is_quiet():
    eng = make_engine()
    alerts = []
    for d in synth.benign_events(ACCT, 1_000_000):
        alerts += eng.process(d)
    assert alerts == []
    ok, diffs = eng.check_equivalence()
    assert ok, diffs


def test_unrelated_user_assuming_role_does_not_alert_as_active():
    eng = make_engine()
    d = synth.make_event("AssumeRole", synth.user_actor(ACCT, "dev-user", synth.KEYS["dev-user"]),
                         {"roleArn": L.role_arn(ACCT, "readonly-role"), "roleSessionName": "x"},
                         {"credentials": {"accessKeyId": "ASIARO0000000001"}}, 1_000_000)
    assert [a for a in eng.process(d) if a["level"] == "ACTIVE"] == []


def test_allowlist_suppresses_alerts():
    eng = make_engine(allowlist=["dev-user"])
    alerts = []
    for d in synth.scenario_events("s1", ACCT, 1_000_000):
        alerts += eng.process(d)
    assert alerts == []


def test_cooldown_deduplicates():
    eng = make_engine()
    alerts = []
    for i in range(3):
        for d in synth.scenario_events("s2", ACCT, 1_000_000 + i * 60, key_suffix=str(i)):
            alerts += eng.process(d)
    assert len([a for a in alerts if a["level"] == "ACTIVE"]) <= 2


def test_window_too_short_gives_only_watch():
    eng = make_engine(window=10)         # hop gap is 30 s
    alerts = []
    for d in synth.scenario_events("s1", ACCT, 1_000_000):
        alerts += eng.process(d)
    assert alerts and all(a["level"] == "WATCH" for a in alerts)


def test_serialisation_roundtrip():
    eng, _ = run_scenario("s3")
    eng2 = Engine.loads(eng.dumps())
    assert eng2.graph.edge_set() == eng.graph.edge_set()
    assert eng2.graph.dist == eng.graph.dist
    assert eng2.state.to_dict() == eng.state.to_dict()
    assert len(eng2.ledger.events) == len(eng.ledger.events)


def test_failed_calls_are_ignored():
    eng = make_engine()
    d = synth.make_event("CreateAccessKey", synth.user_actor(ACCT, "helpdesk-user", synth.KEYS["helpdesk-user"]),
                         {"userName": "admin-user"}, None, 1_000_000, error="AccessDenied")
    assert eng.process(d) == []
    assert eng.last_stats.get("ignored")


def test_admin_doing_admin_things_raises_no_alert():
    """The admin who creates lab access keys must not produce alerts (found during first real run)."""
    import copy
    d = copy.deepcopy(L.lab_authorization_details(ACCT))
    d["UserDetailList"].append({"UserName": "me-admin", "Arn": L.user_arn(ACCT, "me-admin"), "GroupList": [],
                                "AttachedManagedPolicies": [{"PolicyName": "AdministratorAccess",
                                                             "PolicyArn": L.ADMIN_POLICY_ARN}],
                                "UserPolicyList": []})
    eng = Engine.from_snapshot(d)
    admin = synth.user_actor(ACCT, "me-admin", "AKIAMEADMIN0000001")
    alerts = []
    for i, u in enumerate(["dev-user", "ci-user", "ops-user", "deploy-user", "helpdesk-user"]):
        alerts += eng.process(synth.make_event(
            "CreateAccessKey", admin, {"userName": u},
            {"accessKey": {"accessKeyId": "AKIALAB%d" % i, "userName": u}}, 1_000_000 + i * 3))
    assert alerts == []


def test_no_redundant_watch_for_already_admin_targets():
    """deploy-user -> PassRole -> (already admin) lambda-target-role must not also produce a 1/2 WATCH
    via the redundant 'AttachRolePolicy on itself' hop (seen on the first real run)."""
    eng, alerts = run_scenario("s4")
    assert [a["level"] for a in alerts] == ["ACTIVE"]
    eng, alerts = run_scenario("s5")
    assert [a["level"] for a in alerts] == ["ACTIVE"]


def test_late_assume_role_event_still_gives_attributed_alert():
    """Events can arrive out of order: AttachRolePolicy first, the AssumeRole that preceded it later."""
    eng = make_engine()
    evs = synth.scenario_events("s1", ACCT, 1_000_000)
    first = eng.process(evs[1])                    # attach arrives first -> attributed to the role for now
    assert first and first[0]["level"] == "ACTIVE" and first[0]["origin"].endswith("/eks-worker-role")
    later = eng.process(evs[0])                    # assume-role arrives late -> chain to dev-user is recovered
    assert any(a["level"] == "ACTIVE" and a["origin"].endswith("/dev-user") for a in later)
