"""Differential test of the exact incremental distance algorithm against a full rebuild,
on random graphs with random edge insertions, deletions and node removals."""
import random

import pytest

from iamwatch.graph import Graph
from iamwatch.model import ADMIN


def random_graph(rng, n, deg, k):
    g = Graph(k)
    nodes = ["n%d" % i for i in range(n)]
    for u in nodes:
        out = {}
        for _ in range(rng.randint(0, deg)):
            v = rng.choice(nodes)
            if v != u:
                out[(v, rng.choice(["A", "B"]), "")] = False
        if rng.random() < 0.08:
            out[(ADMIN, "HasAdmin", "")] = False
        g.set_out(u, out)
    g.rebuild_dist()
    return g, nodes


@pytest.mark.parametrize("seed", range(40))
@pytest.mark.parametrize("k", [1, 3, 5])
def test_incremental_equals_rebuild(seed, k):
    rng = random.Random(seed * 100 + k)
    g, nodes = random_graph(rng, rng.randint(5, 60), 3, k)
    for step in range(60):
        changed = set()
        for _ in range(rng.randint(1, 3)):                 # batches of simultaneous changes
            u = rng.choice(nodes)
            cur = dict(g.out.get(u, {}))
            op = rng.choice(["add", "del", "admin", "clear", "unadmin"])
            if op == "add":
                v = rng.choice(nodes)
                if v != u:
                    cur[(v, "A", "")] = False
            elif op == "del" and cur:
                cur.pop(rng.choice(list(cur)))
            elif op == "admin":
                cur[(ADMIN, "HasAdmin", "")] = False
            elif op == "unadmin":
                cur.pop((ADMIN, "HasAdmin", ""), None)
            elif op == "clear":
                cur = {}
            if g.set_out(u, cur):
                changed.add(u)
        g.update_dist(changed)
        got = dict(g.dist)
        g.rebuild_dist()
        assert got == g.dist, (seed, k, step)


def test_ball_algorithm_still_correct():
    rng = random.Random(5)
    g, nodes = random_graph(rng, 40, 3, 4)
    for _ in range(50):
        u = rng.choice(nodes)
        cur = dict(g.out.get(u, {}))
        cur[(rng.choice(nodes), "A", "")] = False
        cur.pop((u, "A", ""), None)
        g.set_out(u, cur)
        g.update_dist_ball({u})
        got = dict(g.dist)
        g.rebuild_dist()
        assert got == g.dist


def test_noop_change_touches_little():
    g = Graph(5)
    g.set_out("a", {("b", "A", ""): False})
    g.set_out("b", {(ADMIN, "HasAdmin", ""): False})
    for i in range(50):
        g.set_out("x%d" % i, {("a", "A", ""): False})
    g.rebuild_dist()
    g.set_out("a", {("b", "A", ""): False, ("b", "B", ""): False})   # parallel edge: no distance change
    improved, worsened, touched = g.update_dist({"a"})
    assert not improved and not worsened and touched <= 2
