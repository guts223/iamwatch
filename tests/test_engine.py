def test_repeated_attack_is_detected_again():
    """Regression: a second identical attack (after a reset) must raise ACTIVE again."""
    from iamwatch import labspec as L, synth
    from iamwatch.engine import Engine
    acct = "123456789012"
    eng = Engine.from_snapshot(L.lab_authorization_details(acct), cooldown=60)
    for i in range(3):
        al = []
        for d in synth.scenario_events("s1", acct, 1_000_000 + i * 7200, key_suffix="r%d" % i):
            al += eng.process(d)
        assert any(a["level"] == "ACTIVE" for a in al), "run %d missed" % i
        eng.process(synth.make_event("DetachRolePolicy", synth.user_actor(acct, "admin-user", "AKIAX"),
                    {"roleName": "eks-worker-role", "policyArn": L.ADMIN_POLICY_ARN}, None, 1_000_000 + i * 7200 + 100))


def test_slow_credential_chain_needs_linked_window():
    """S1 with 2 h between the steps: missed with a 1 h window, detected with a 12 h linked window."""
    from iamwatch import labspec as L, synth
    from iamwatch.engine import Engine
    acct = "123456789012"
    res = {}
    for name, kw in (("fixed", {}), ("linked", {"linked_window": 43200})):
        eng = Engine.from_snapshot(L.lab_authorization_details(acct), cooldown=1, **kw)
        evs = synth.scenario_events("s1", acct, 1_000_000)
        evs[1]["eventTime"] = synth.iso(1_000_000 + 7200)
        al = []
        for d in evs:
            al += eng.process(d)
        res[name] = {a["level"] for a in al}
    assert "ACTIVE" not in res["fixed"] and "ACTIVE" in res["linked"], res


def test_linked_window_does_not_link_unrelated_events():
    """A different identity's AttachRolePolicy 2 h later is not chained to dev-user's AssumeRole."""
    from iamwatch import labspec as L, synth
    from iamwatch.engine import Engine
    acct = "123456789012"
    eng = Engine.from_snapshot(L.lab_authorization_details(acct), cooldown=1, linked_window=43200)
    evs = synth.scenario_events("s1", acct, 1_000_000)
    evs[1]["eventTime"] = synth.iso(1_000_000 + 7200)
    evs[1]["userIdentity"] = synth.user_actor(acct, "admin-user", "AKIAUNRELATED00001")   # not the session key
    al = []
    for d in evs:
        al += eng.process(d)
    assert not any(a["level"] == "ACTIVE" and a["origin"].endswith("/dev-user") for a in al)


def test_late_event_adds_evidence_but_does_not_change_state():
    from iamwatch import labspec as L, synth
    from iamwatch.engine import Engine
    acct = "123456789012"
    eng = Engine.from_snapshot(L.lab_authorization_details(acct), cooldown=1)
    evs = synth.scenario_events("s1", acct, 1_000_000)
    al = eng.process(evs[0], late=True) + eng.process(evs[1], late=True)
    assert any(a["level"] == "ACTIVE" and a["origin"].endswith("/dev-user") for a in al)
    ok, _ = eng.check_equivalence()
    assert ok
    assert not any(e[2] == "HasAdmin" and e[0] == "role:eks-worker-role" for e in eng.graph.edge_set())   # state untouched


def test_back_to_back_attacks_never_realert_on_old_chain():
    """Regression (found in the 8 h campaign): with cooldown=1 and reps 16 s apart, the first event
    (AssumeRole) of rep k re-matched the COMPLETE chain of rep k-1 and fired a stale ACTIVE.
    Every ACTIVE must contain its own trigger event, so there is exactly one per attack."""
    from iamwatch import labspec as L, synth
    from iamwatch.engine import Engine
    acct = "123456789012"
    for fam in ("s1", "s3"):
        eng = Engine.from_snapshot(L.lab_authorization_details(acct), cooldown=1, linked_window=43200)
        n_active = 0
        for i in range(5):
            t0 = 1_000_000 + i * 100
            for d in synth.scenario_events(fam, acct, t0, key_suffix="r%d" % i):
                for a in eng.process(d):
                    if a["level"] == "ACTIVE":
                        n_active += 1
                        assert a["trigger_event"] in {e["id"] for e in a["matched_events"]}
                        assert min(e["time"] for e in a["matched_events"]) >= t0 - 1, (fam, i)
        assert n_active == 5, (fam, n_active)