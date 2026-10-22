"""The detection engine.

    engine = Engine.from_snapshot(authorization_details)      # once
    alerts = engine.process(cloudtrail_record)                # for every event, in order
    engine.posture()                                          # dangerous-but-unused paths
    engine.check_equivalence()                                # incremental == rebuild-from-scratch?

Classification (risk x evidence):
    path to ADMIN exists, no matching activity   -> posture finding (engine.posture())
    path exists, part of it was executed         -> WATCH   (investigate)
    path exists, all of it executed in order     -> ACTIVE  (page someone)
"""
import hashlib
import json
import time as _time

from . import events as E
from . import rules as R
from .evidence import Ledger, match_path
from .graph import Graph, INF
from .model import ADMIN, IamState, state_from_authorization_details, kind_of, name_of


class Engine:
    def __init__(self, k=5, window=3600, cooldown=3600, allowlist=(), fetcher=None, max_paths=60, linked_window=None):
        self.k = k
        self.window = window
        self.linked_window = linked_window      # None = same as window (original behaviour)
        self.cooldown = cooldown
        self.allowlist = set(a for a in allowlist if a)
        self.fetcher = fetcher
        self.max_paths = max_paths
        self.state = IamState()
        self.graph = Graph(k)
        self.ledger = Ledger()
        self.alerts_seen = {}     # (fingerprint, level) -> event time of last emission
        self.last_stats = {}
        self.graph_dirty = False

    # ------------------------------------------------------------------ construction
    @classmethod
    def from_snapshot(cls, details, **kw):
        eng = cls(**kw)
        eng.state = state_from_authorization_details(details)
        eng.rebuild()
        return eng

    @classmethod
    def from_state(cls, state, **kw):
        eng = cls(**kw)
        eng.state = state
        eng.rebuild()
        return eng

    def rebuild(self):
        """Compute the whole graph and distance table from scratch (the oracle)."""
        g = Graph(self.k)
        st = self.state
        for n in st.nodes:
            g.set_out(n, R.edges_from(st, n))
        g.rebuild_dist()
        self.graph = g
        self.graph_dirty = True

    # ------------------------------------------------------------------ incremental update
    def _apply_impact(self, impact):
        st, g = self.state, self.graph
        changed = set()
        recomputed = 0
        for n in impact.removed:
            changed |= g.remove_node(n)
        outs = set(impact.out) | set(impact.added)
        ins = set(impact.in_targets) | set(impact.added)
        ctx_cache = {}

        def ctx(p):
            c = ctx_cache.get(p)
            if c is None:
                c = ctx_cache[p] = R.PermCtx(st, p)
            return c

        for n in outs:
            if n in st.nodes:
                recomputed += 1
                if g.set_out(n, R.edges_from(st, n, ctx(n))):
                    changed.add(n)
        for t in ins:
            if t not in st.nodes:
                continue
            for p in st.nodes:
                if p == t or p.startswith("group:") or p in outs:
                    continue          # groups never act; nodes in `outs` were fully recomputed above
                recomputed += 1
                pair = R.edges_between(st, ctx(p), p, t)
                if g.set_pair(p, t, pair):
                    changed.add(p)
        changed = {n for n in changed if n in st.nodes}
        for n in impact.removed:
            g.dist.pop(n, None)
        improved, worsened, affected = g.update_dist(changed)
        return {"changed": len(changed), "affected": affected, "recomputed_nodes": recomputed,
                "improved": sorted(improved), "worsened": sorted(worsened)}

    # ------------------------------------------------------------------ main entry point
    def process(self, detail, now=None, late=False):
        """Process one CloudTrail record (the `detail` of an EventBridge event).

        Returns a list of alert dicts (possibly empty).  Failed calls (errorCode) are ignored.

        late=True marks an event recovered by the gap-fill job: it arrives out of order, so it is added to the
        evidence ledger and evaluated against the current graph, but it does NOT change the IAM state (an old
        event applied now could undo a newer change).  The 6-hourly reconcile report shows any resulting drift.
        """
        t0 = _time.perf_counter()
        ev, req, resp = E.normalize(detail)
        self.last_stats = {"event": ev.name, "event_id": ev.id}
        if ev.error or ev.name not in E.EVIDENCE_EVENTS:
            self.last_stats["ignored"] = True
            return []
        if ev.id in self.ledger.seen_ids:
            self.last_stats["duplicate"] = True
            return []
        # The event is logged first and matched against the graph as it was BEFORE the change
        # (the technique that was just executed is an edge of that graph - after it succeeds the
        # edge may disappear, e.g. a user who joined an admin group can no longer "join" it) and
        # again AFTER the change (later hops of a chain live in the updated graph).
        self.ledger.add(ev)
        cands = []
        if ev.name in E.STATE_EVENTS and not late:
            cands.append(self._best_candidate(ev))
            impact = E.apply_state_event(self.state, ev, req, resp, self.fetcher)
            if impact:
                self.last_stats.update(self._apply_impact(impact))
                self.graph_dirty = True
        t1 = _time.perf_counter()
        cands.append(self._best_candidate(ev))
        alerts = self._emit(self._pick(cands), ev)
        t2 = _time.perf_counter()
        self.last_stats["t_update_ms"] = round((t1 - t0) * 1000, 3)
        self.last_stats["t_evaluate_ms"] = round((t2 - t1) * 1000, 3)
        return alerts

    # ------------------------------------------------------------------ evidence + classification
    def _allowlisted(self, arn):
        if not arn:
            return False
        if arn in self.allowlist:
            return True
        return arn.rsplit("/", 1)[-1] in self.allowlist

    def _best_candidate(self, ev):
        """Best (key, level, path, match) for the chain that `ev` belongs to, or None."""
        st, g = self.state, self.graph
        cache = {}
        origin_arn = self.ledger.root_principal(ev, cache)
        origin = st.node_by_arn(origin_arn) if origin_arn else None
        if origin is None or origin.startswith("group:") or g.dist.get(origin, INF) > self.k:
            return None
        if self._allowlisted(origin_arn) or self._allowlisted(ev.actor_arn):
            return None
        if any(key[1] == "HasAdmin" for key in g.out.get(origin, {})):
            return None           # already administrator: there is nothing left to escalate to
        best = None
        for path in g.paths_from(origin, self.max_paths):
            last = path[-1]
            if last[2] != "HasAdmin" and any(k[1] == "HasAdmin" for k in g.out.get(last[0], {})):
                continue          # last hop escalates a principal that is already admin: redundant with HasAdmin
            m = match_path(self.ledger, st, origin_arn, path, self.window, cache, self.linked_window)
            if not m or m["matched"] == 0:
                continue
            limit = max(self.window, self.linked_window or 0) if m["linked"] else self.window
            if ev.time - m["events"][-1].time > limit:
                continue          # the matched evidence is too old relative to this event
            if ev.id not in {e.id for e in m["events"]}:
                continue          # `ev` is not part of this chain: re-reporting an old chain would be a stale alert
            level = "ACTIVE" if m["matched"] == m["required"] else "WATCH"
            key = (level == "ACTIVE", m["matched"], -m["required"], -len(path))
            if best is None or key > best[0]:
                best = (key, level, path, m, origin_arn)
        return best

    @staticmethod
    def _pick(cands):
        cands = [c for c in cands if c is not None]
        return max(cands, key=lambda c: c[0]) if cands else None

    def _emit(self, cand, ev):
        if cand is None:
            return []
        _, level, path, m, origin_arn = cand
        origin = self.state.node_by_arn(origin_arn) or origin_arn
        fp = hashlib.sha1(("|".join([origin] + [h[1] + ":" + h[2] + ":" + h[3] for h in path]))
                          .encode()).hexdigest()[:16]
        last = self.alerts_seen.get((fp, level))
        if last is not None and ev.time - last < self.cooldown:
            return []
        self.alerts_seen[(fp, level)] = ev.time
        return [{
            "fingerprint": fp, "level": level, "origin": origin_arn, "trigger_event": ev.id,
            "trigger_time": ev.time,
            "path": [{"src": h[0], "dst": h[1], "technique": h[2], "target": h[3], "conditional": h[4]}
                     for h in path],
            "matched_count": m["matched"], "required_count": m["required"], "linked": m["linked"],
            "matched_events": [{"id": e.id, "name": e.name, "time": e.time, "actor": e.actor_arn}
                               for e in m["events"]],
            "window_seconds": self.window,
        }]

    def _evaluate(self, ev):
        """Evaluate one event against the CURRENT graph only (used by the batch baseline)."""
        return self._emit(self._pick([self._best_candidate(ev)]), ev)

    # ------------------------------------------------------------------ reports
    def posture(self):
        """Dangerous-but-unexplained paths: principals that can reach ADMIN without being admin."""
        out = []
        admins = []
        for n in sorted(self.state.principals()):
            d = self.graph.dist.get(n, INF)
            if d > self.k:
                continue
            has_admin = any(key[1] == "HasAdmin" for key in self.graph.out.get(n, {}))
            if has_admin:
                admins.append(n)
                continue
            paths = self.graph.paths_from(n, 3)
            out.append({"principal": n, "hops": d,
                        "paths": [[{"src": h[0], "dst": h[1], "technique": h[2], "target": h[3],
                                    "conditional": h[4]} for h in p] for p in paths]})
        out.sort(key=lambda r: (r["hops"], r["principal"]))
        return {"already_admin": admins, "escalation_paths": out}

    # ------------------------------------------------------------------ correctness oracle
    def check_equivalence(self):
        """Compare the incrementally maintained graph with one rebuilt from scratch."""
        fresh = Engine.from_state(self.state.clone(), k=self.k)
        a, b = self.graph.edge_set(), fresh.graph.edge_set()
        diffs = {"missing_in_live": sorted(map(list, b - a)), "extra_in_live": sorted(map(list, a - b)),
                 "dist_mismatch": sorted(n for n in set(self.graph.dist) | set(fresh.graph.dist)
                                         if self.graph.dist.get(n, INF) != fresh.graph.dist.get(n, INF))}
        ok = not (diffs["missing_in_live"] or diffs["extra_in_live"] or diffs["dist_mismatch"])
        return ok, diffs

    # ------------------------------------------------------------------ (de)serialisation
    def to_dict(self):
        return {"cfg": {"k": self.k, "window": self.window, "cooldown": self.cooldown,
                        "allowlist": sorted(self.allowlist), "max_paths": self.max_paths,
                        "linked_window": self.linked_window},
                "state": self.state.to_dict(), "graph": self.graph.to_dict(),
                "ledger": self.ledger.to_dict(),
                "alerts_seen": [[fp, lv, t] for (fp, lv), t in self.alerts_seen.items()]}

    @classmethod
    def from_dict(cls, d, fetcher=None):
        c = d["cfg"]
        eng = cls(k=c["k"], window=c["window"], cooldown=c["cooldown"], allowlist=c["allowlist"],
                  fetcher=fetcher, max_paths=c.get("max_paths", 60), linked_window=c.get("linked_window"))
        eng.state = IamState.from_dict(d["state"])
        eng.graph = Graph.from_dict(d["graph"])
        eng.ledger = Ledger.from_dict(d["ledger"])
        eng.alerts_seen = {(fp, lv): t for fp, lv, t in d.get("alerts_seen", [])}
        return eng

    def dumps(self):
        return json.dumps(self.to_dict(), separators=(",", ":"))

    @classmethod
    def loads(cls, text, fetcher=None):
        return cls.from_dict(json.loads(text), fetcher)