"""Evidence: did someone actually walk a dangerous path?

Three pieces:

1. Ledger  - recent events plus an index of "session links":
       AssumeRole.responseElements.credentials.accessKeyId   -> the temporary session's key id
       CreateAccessKey.responseElements.accessKey.accessKeyId -> the new key's id
   Any later event carrying that access key id belongs to the same chain, so we can walk back
   from an event to the root identity (the stolen key) that started the chain.

2. Telemetry dictionary (`hop_signature`) - for every graph edge technique, which CloudTrail
   event(s) show it being *used*.  This includes the PassRole problem: iam:PassRole is a
   permission and is never logged, so the PassRole edges are matched through the service call
   that consumes it (lambda CreateFunction `role`, ec2 RunInstances `iamInstanceProfile`,
   cloudformation CreateStack `roleARN`).

3. match_path - given a path of hops, find an in-order sequence of events (all inside a time
   window, all in the chain that started at `origin`) that executes the non-terminal hops.
"""
from .events import Ev

# technique -> request parameter names that identify the target of the call
SELF_ATTACH = {
    "AttachRolePolicy": "roleName", "PutRolePolicy": "roleName",
    "AttachUserPolicy": "userName", "PutUserPolicy": "userName",
    "AttachGroupPolicy": "groupName", "PutGroupPolicy": "groupName",
}


class Ledger:
    def __init__(self, max_age=24 * 3600, max_events=5000):
        self.max_age = max_age
        self.max_events = max_events
        self.events = []          # Ev, arrival order
        self.by_child_key = {}    # access key id -> Ev that created it
        self.seen_ids = set()

    def add(self, ev):
        if ev.id in self.seen_ids:
            return False
        self.seen_ids.add(ev.id)
        self.events.append(ev)
        if ev.child_key:
            self.by_child_key[ev.child_key] = ev
        self._prune(ev.time)
        return True

    def _prune(self, now):
        if len(self.events) <= 200 and not self.max_age:
            return
        keep = [e for e in self.events if now - e.time <= self.max_age]
        if len(keep) > self.max_events:
            keep = keep[-self.max_events:]
        if len(keep) != len(self.events):
            self.events = keep
            ids = {e.id for e in keep}
            self.seen_ids = ids
            self.by_child_key = {k: e for k, e in self.by_child_key.items() if e.id in ids}

    def root_event(self, ev):
        cur, seen = ev, set()
        while cur.access_key and cur.access_key in self.by_child_key and cur.id not in seen:
            seen.add(cur.id)
            nxt = self.by_child_key[cur.access_key]
            if nxt.id == cur.id:
                break
            cur = nxt
        return cur

    def root_principal(self, ev, cache=None):
        if cache is not None and ev.id in cache:
            return cache[ev.id]
        r = self.root_event(ev).actor_arn
        if cache is not None:
            cache[ev.id] = r
        return r

    def to_dict(self):
        return {"max_age": self.max_age, "max_events": self.max_events,
                "events": [e.to_dict() for e in self.events]}

    @classmethod
    def from_dict(cls, d):
        led = cls(d.get("max_age", 24 * 3600), d.get("max_events", 5000))
        for e in d.get("events", []):
            led.add(Ev.from_dict(e))
        return led


# ---------------------------------------------------------------------------
# Telemetry dictionary
# ---------------------------------------------------------------------------
def _profile_name(value):
    """requestParameters.iamInstanceProfile may be {'arn':..}, {'name':..} or a string."""
    if isinstance(value, dict):
        value = value.get("arn") or value.get("name") or ""
    return str(value).rsplit("/", 1)[-1]


def hop_signature(state, hop):
    """Return a list of (event_names, predicate) that, in order, show `hop` being executed.

    Returns [] for the terminal HasAdmin hop (using admin power needs no special event).
    """
    src, dst, tech, target, _cond = hop
    if tech == "HasAdmin":
        return []
    sname = state.name(src)
    if tech == "AssumeRole":
        arn = state.arn(dst)
        return [({"AssumeRole"}, lambda e, arn=arn: e.params.get("roleArn") == arn)]
    if tech in SELF_ATTACH:
        key = SELF_ATTACH[tech]
        tname = state.name(target) if target in state.nodes else target
        return [({tech}, lambda e, key=key, tname=tname: e.params.get(key) == tname)]
    if tech in ("CreatePolicyVersion", "SetDefaultPolicyVersion"):
        return [({tech}, lambda e, t=target: e.params.get("policyArn") == t)]
    if tech == "UpdateAssumeRolePolicy":
        rname, arn = state.name(dst), state.arn(dst)
        return [({"UpdateAssumeRolePolicy"}, lambda e, r=rname: e.params.get("roleName") == r),
                ({"AssumeRole"}, lambda e, arn=arn: e.params.get("roleArn") == arn)]
    if tech == "CreateAccessKey":
        uname = state.name(dst)
        return [({"CreateAccessKey"}, lambda e, u=uname: e.params.get("userName") == u)]
    if tech == "UpdateLoginProfile":
        uname = state.name(dst)
        return [({"CreateLoginProfile", "UpdateLoginProfile"}, lambda e, u=uname: e.params.get("userName") == u)]
    if tech == "AddUserToGroup":
        gname = state.name(dst)
        return [({"AddUserToGroup"}, lambda e, g=gname, u=sname: e.params.get("groupName") == g
                 and e.params.get("userName") == u)]
    if tech == "PassRole:lambda":
        arn = state.arn(dst)
        return [({"CreateFunction20150331"}, lambda e, arn=arn: e.params.get("role") == arn)]
    if tech == "PassRole:cloudformation":
        arn = state.arn(dst)
        return [({"CreateStack"}, lambda e, arn=arn: e.params.get("roleARN") == arn)]
    if tech == "PassRole:ec2":
        rname = state.name(dst)

        def pred(e, rname=rname, state=state):
            pn = _profile_name(e.params.get("iamInstanceProfile"))
            return rname in state.profiles.get(pn, {}).get("roles", [])
        return [({"RunInstances"}, pred)]
    return []


def _in_window(ledger, e, chain, start, window, linked_window):
    gap = e.time - start.time
    if gap <= window:
        return True
    if gap > linked_window or not e.access_key:
        return False
    issuer = ledger.by_child_key.get(e.access_key)
    return issuer is not None and any(issuer.id == c.id for c in chain)


def match_path(ledger, state, origin_arn, hops, window, root_cache=None, linked_window=None):
    """Match the non-terminal hops of a path against the ledger.

    Returns None if the path has nothing to match (e.g. the principal is already admin), else
    {"matched": m, "required": M, "events": [Ev...], "linked": bool}.

    `window` limits the time between the first and last matched event.  `linked_window` (>= window)
    is a longer limit that applies only to a step performed with a credential that an earlier step of
    the same chain issued (an AssumeRole session key or a new access key): such a step is tied to the
    chain by the credential itself, so waiting longer than `window` does not make it unrelated.
    """
    linked_window = max(window, linked_window or 0)
    sigs = []
    for hop in hops:
        for names, pred in hop_signature(state, hop):
            sigs.append((state.arn(hop[0]), names, pred))
    if not sigs:
        return None
    root_cache = root_cache if root_cache is not None else {}
    cands = []
    for src_arn, names, pred in sigs:
        lst = [e for e in ledger.events
               if e.name in names and e.actor_arn == src_arn and pred(e)
               and ledger.root_principal(e, root_cache) == origin_arn]
        lst.sort(key=lambda e: e.time)
        cands.append(lst)
    best = {"matched": 0, "required": len(sigs), "events": [], "linked": False}
    # newest start first: a repeated attack must be matched with its own fresh evidence, not with an
    # older identical chain that already fell out of the window
    for start in reversed(cands[0]):
        chain = [start]
        for lst in cands[1:]:
            nxt = next((e for e in lst if e.time >= chain[-1].time and e.id != chain[-1].id
                        and _in_window(ledger, e, chain, start, window, linked_window)), None)
            if nxt is None:
                break
            chain.append(nxt)
        if len(chain) > best["matched"] or (len(chain) == best["matched"] and chain
                                            and chain[-1].time > best["events"][-1].time):
            best = {"matched": len(chain), "required": len(sigs), "events": chain, "linked": False}
        if len(chain) == len(sigs):
            break
    best["linked"] = any(e.access_key in ledger.by_child_key for e in best["events"])
    return best
