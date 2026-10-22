import random

import pytest

from iamwatch import simlab as S
from iamwatch.baselines import StaleEngine, StatelessRules
from iamwatch.engine import Engine


@pytest.mark.parametrize("kind", S.ALL)
def test_engine_detects_every_family(kind):
    eng = Engine.from_snapshot(S.build_details(random.Random(3), 15))
    alerts = []
    for d in S.attack_events(kind, 1_000_000):
        alerts += eng.process(d)
    active = [a for a in alerts if a["level"] == "ACTIVE"]
    assert active and active[-1]["origin"].endswith("/" + S.ORIGIN[kind])
    assert eng.check_equivalence()[0]


@pytest.mark.parametrize("kind", S.COVERED)
def test_stateless_rules_cover_s_family(kind):
    r = StatelessRules()
    assert [h for d in S.attack_events(kind, 1_000_000) for h in r.process(d)]


@pytest.mark.parametrize("kind", S.UNCOVERED)
def test_stateless_rules_miss_x_family(kind):
    r = StatelessRules()
    assert not [h for d in S.attack_events(kind, 1_000_000) for h in r.process(d)]


def test_benign_workload_no_active_alerts_but_noisy_rules():
    rng = random.Random(9)
    eng = Engine.from_snapshot(S.build_details(random.Random(1), 15))
    rules = StatelessRules()
    events = sorted(S.benign_workload(rng, 1_000_000, 60), key=lambda d: d["eventTime"])
    engine_active = sum(1 for d in events for a in eng.process(d) if a["level"] == "ACTIVE")
    rule_hits = sum(len(rules.process(d)) for d in events)
    assert engine_active == 0
    assert rule_hits > 0
    assert eng.check_equivalence()[0]


@pytest.mark.parametrize("interval", [300, 1800])
def test_batch_engine_detects_only_at_scan_boundary(interval):
    se = StaleEngine(S.build_details(random.Random(1), 5), interval=interval, phase=17)
    t0 = 1_000_000
    alerts = []
    for d in S.attack_events("s2", t0):
        alerts += se.process(d)
    assert alerts == []                         # nothing visible before the scan
    alerts += se.finish(2 * interval)
    assert alerts and alerts[0]["visible_at"] - t0 <= interval
