"""Baselines the engine is compared against.

1. StatelessRules - the kind of detection rules a SIEM engineer writes with no IAM inventory:
       R1  AssumeRole(X) then Attach/PutRolePolicy on role X by that session   (<= 15 min)
       R2  CreatePolicyVersion with setAsDefault=true
       R3  UpdateAssumeRolePolicy(X) then AssumeRole(X) by the same actor      (<= 15 min)
       R4  Lambda CreateFunction / EC2 RunInstances / CloudFormation CreateStack passing a role
       R5  CreateAccessKey for a different user than the caller
   They fire at the moment the last event arrives (no model-staleness), cannot attribute the chain
   to a stolen origin key, and are noisy because they do not know which roles/users are powerful.

2. StaleEngine - the SAME detection logic as Engine, but run the way a periodic batch scanner works:
   events are logged immediately, yet the IAM model is only refreshed (and the logs only
   correlated) every `interval` seconds.  This isolates the effect of event-driven updates.
"""
from . import events as E
from .engine import Engine


class StatelessRules:
    def __init__(self, pair_window=900):
        self.pair_window = pair_window
        self.recent = []        # normalised events seen so far

    def process(self, detail):
        ev, req, resp = E.normalize(detail)
        if ev.error:
            return []
        hits = []
        n = ev.name
        if n == "CreatePolicyVersion" and E._truthy(req.get("setAsDefault")):
            hits.append("R2")
        if n in ("CreateFunction20150331", "RunInstances", "CreateStack") and (
                ev.params.get("role") or ev.params.get("roleARN") or ev.params.get("iamInstanceProfile")):
            hits.append("R4")
        if n == "CreateAccessKey":
            target = ev.params.get("userName")
            if target and not (ev.actor_arn or "").endswith("/" + target):
                hits.append("R5")
        if n in ("AttachRolePolicy", "PutRolePolicy"):
            for prev in reversed(self.recent):
                if ev.time - prev.time > self.pair_window:
                    break
                if (prev.name == "AssumeRole" and prev.child_key and prev.child_key == ev.access_key
                        and (prev.params.get("roleArn") or "").endswith("/" + str(ev.params.get("roleName")))):
                    hits.append("R1")
                    break
        if n == "AssumeRole":
            for prev in reversed(self.recent):
                if ev.time - prev.time > self.pair_window:
                    break
                if (prev.name == "UpdateAssumeRolePolicy" and prev.actor_arn == ev.actor_arn
                        and (ev.params.get("roleArn") or "").endswith("/" + str(prev.params.get("roleName")))):
                    hits.append("R3")
                    break
        self.recent.append(ev)
        self.recent = self.recent[-500:]
        return [{"rule": h, "time": ev.time, "event": ev.id, "actor": ev.actor_arn} for h in hits]


class StaleEngine:
    """Batch-style operation of the engine: model refreshed and logs correlated every `interval` s."""

    def __init__(self, details, interval, phase=0.0, **engine_kw):
        self.engine = Engine.from_snapshot(details, **engine_kw)
        self.interval = float(interval)
        self.next_boundary = None
        self.phase = phase
        self.pending = []          # (Ev, req, resp) state events not yet applied to the model
        self.unevaluated = []      # Ev logged but not yet correlated

    def _boundary_after(self, t):
        import math
        n = math.floor((t - self.phase) / self.interval) + 1
        return self.phase + n * self.interval

    def _flush(self, at):
        eng = self.engine
        alerts = []
        before = {ev.id: eng._best_candidate(ev) for ev in self.unevaluated}    # model of the previous scan
        for ev, req, resp in self.pending:
            impact = E.apply_state_event(eng.state, ev, req, resp, eng.fetcher)
            if impact:
                eng._apply_impact(impact)
        self.pending = []
        for ev in self.unevaluated:
            for a in eng._emit(eng._pick([before[ev.id], eng._best_candidate(ev)]), ev):
                a["visible_at"] = at
                alerts.append(a)
        self.unevaluated = []
        return alerts

    def process(self, detail):
        """Feed one event (in time order).  Returns alerts that became visible at scan boundaries
        occurring at or before this event's time."""
        ev, req, resp = E.normalize(detail)
        alerts = []
        if self.next_boundary is None:
            self.next_boundary = self._boundary_after(ev.time)
        while ev.time >= self.next_boundary:
            alerts += self._flush(self.next_boundary)
            self.next_boundary += self.interval
        if ev.error or ev.name not in E.EVIDENCE_EVENTS:
            return alerts
        self.engine.ledger.add(ev)                 # logs are visible immediately...
        self.unevaluated.append(ev)                # ...but correlated only at the next scan
        if ev.name in E.STATE_EVENTS:
            self.pending.append((ev, req, resp))   # ...and the model only refreshed at the next scan
        return alerts

    def finish(self, horizon):
        """Run the remaining scans until `horizon` seconds after the last event."""
        alerts = []
        end = (self.next_boundary or 0) + horizon
        while self.next_boundary is not None and self.next_boundary <= end:
            alerts += self._flush(self.next_boundary)
            self.next_boundary += self.interval
            if not self.pending and not self.unevaluated:
                break
        return alerts
