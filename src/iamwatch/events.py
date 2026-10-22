"""CloudTrail record -> normalised event, and event -> IAM state change.

`apply_state_event` mutates an IamState and returns an Impact telling the engine which
graph nodes must be recomputed.  Handlers are idempotent (re-applying an event that is
already reflected in the state changes nothing), which matters because the engine is
bootstrapped from a snapshot that may already include some queued events.
"""
import json
from datetime import datetime, timezone

from . import policy as P
from . import model as M
from .model import node_id

# ---------------------------------------------------------------------------
# Which CloudTrail events matter.  The EventBridge rule in infra/template.yaml must list
# exactly these names (tests/test_infra.py checks that).
# ---------------------------------------------------------------------------
STATE_EVENTS = {
    "CreateUser", "DeleteUser", "CreateRole", "DeleteRole", "CreateGroup", "DeleteGroup",
    "AttachUserPolicy", "DetachUserPolicy", "AttachRolePolicy", "DetachRolePolicy",
    "AttachGroupPolicy", "DetachGroupPolicy",
    "PutUserPolicy", "DeleteUserPolicy", "PutRolePolicy", "DeleteRolePolicy",
    "PutGroupPolicy", "DeleteGroupPolicy",
    "CreatePolicy", "DeletePolicy", "CreatePolicyVersion", "SetDefaultPolicyVersion",
    "DeletePolicyVersion", "UpdateAssumeRolePolicy",
    "AddUserToGroup", "RemoveUserFromGroup",
    "PutUserPermissionsBoundary", "DeleteUserPermissionsBoundary",
    "PutRolePermissionsBoundary", "DeleteRolePermissionsBoundary",
    "CreateInstanceProfile", "DeleteInstanceProfile",
    "AddRoleToInstanceProfile", "RemoveRoleFromInstanceProfile",
}
ACTIVITY_EVENTS = {
    "AssumeRole", "CreateAccessKey", "CreateLoginProfile", "UpdateLoginProfile",
    "CreateFunction20150331", "RunInstances", "CreateStack",
}
EVIDENCE_EVENTS = STATE_EVENTS | ACTIVITY_EVENTS
# Defence-evasion events: logged and alerted on by the Lambda handler, no graph effect.
EVASION_EVENTS = {"StopLogging", "DeleteTrail", "UpdateTrail", "PutEventSelectors",
                  "DeleteRule", "DisableRule", "RemoveTargets"}
WATCHED_EVENTS = sorted(EVIDENCE_EVENTS | EVASION_EVENTS)
WATCHED_SOURCES = ["iam.amazonaws.com", "sts.amazonaws.com", "lambda.amazonaws.com",
                   "ec2.amazonaws.com", "cloudformation.amazonaws.com",
                   "cloudtrail.amazonaws.com", "events.amazonaws.com"]

# params we keep in the evidence ledger (policy documents are dropped: they are large)
KEEP_PARAMS = {"roleName", "userName", "groupName", "policyArn", "roleArn", "role", "roleARN",
               "policyName", "versionId", "instanceProfileName", "iamInstanceProfile",
               "setAsDefault", "functionName", "stackName", "name"}


def _parse_time(s):
    if isinstance(s, (int, float)):
        return float(s)
    s = s.replace("Z", "+00:00")
    try:
        return datetime.fromisoformat(s).astimezone(timezone.utc).timestamp()
    except ValueError:
        return datetime.strptime(s[:19], "%Y-%m-%dT%H:%M:%S").replace(tzinfo=timezone.utc).timestamp()


class Ev:
    """A normalised CloudTrail event."""
    __slots__ = ("id", "time", "name", "source", "actor_arn", "actor_type", "access_key",
                 "params", "child_key", "error", "ip")

    def __init__(self, id, time, name, source, actor_arn, actor_type, access_key,
                 params, child_key, error=None, ip=None):
        self.id, self.time, self.name, self.source = id, time, name, source
        self.actor_arn, self.actor_type, self.access_key = actor_arn, actor_type, access_key
        self.params, self.child_key, self.error, self.ip = params, child_key, error, ip

    def to_dict(self):
        return {"id": self.id, "time": self.time, "name": self.name, "source": self.source,
                "actor_arn": self.actor_arn, "actor_type": self.actor_type,
                "access_key": self.access_key, "params": self.params,
                "child_key": self.child_key, "ip": self.ip}

    @classmethod
    def from_dict(cls, d):
        return cls(d["id"], d["time"], d["name"], d["source"], d["actor_arn"], d["actor_type"],
                   d["access_key"], d["params"], d.get("child_key"), None, d.get("ip"))


def normalize(detail):
    """Build an Ev from the `detail` of an EventBridge CloudTrail event (a CloudTrail record)."""
    ui = detail.get("userIdentity") or {}
    typ = ui.get("type")
    if typ == "AssumedRole":
        actor = (ui.get("sessionContext") or {}).get("sessionIssuer", {}).get("arn")
    else:
        actor = ui.get("arn")
    req = detail.get("requestParameters") or {}
    resp = detail.get("responseElements") or {}
    child = None
    if isinstance(resp, dict):
        child = (resp.get("credentials") or {}).get("accessKeyId") \
            or (resp.get("accessKey") or {}).get("accessKeyId")
    params = {k: v for k, v in req.items() if k in KEEP_PARAMS} if isinstance(req, dict) else {}
    return Ev(
        id=detail.get("eventID") or detail.get("eventId") or "",
        time=_parse_time(detail.get("eventTime")),
        name=detail.get("eventName", ""),
        source=detail.get("eventSource", ""),
        actor_arn=actor,
        actor_type=typ,
        access_key=ui.get("accessKeyId"),
        params=params,
        child_key=child,
        error=detail.get("errorCode"),
        ip=detail.get("sourceIPAddress"),
    ), req, resp


class Impact:
    """Which graph nodes the engine must recompute after a state change."""

    def __init__(self, out=(), in_targets=(), added=(), removed=()):
        self.out = set(out)                 # recompute ALL out-edges of these nodes
        self.in_targets = set(in_targets)   # recompute pair-edges INTO these nodes, from every principal
        self.added = set(added)
        self.removed = set(removed)

    def __bool__(self):
        return bool(self.out or self.in_targets or self.added or self.removed)


def _truthy(v):
    return v is True or (isinstance(v, str) and v.lower() == "true")


def _arn(state, kind, name, resp, key):
    a = (resp.get(key) or {}).get("arn") if isinstance(resp, dict) else None
    if a:
        return a
    return "arn:aws:iam::%s:%s/%s" % (state.account_id, kind, name)


def _ensure_policy(state, arn, fetcher):
    """Make sure the state knows policy `arn`; fetch it if needed.

    Returns True when the state changed in a way that affects OTHER principals that already
    reference this policy (it was unknown/absent and is now known).
    """
    if arn in state.policies and not state.policies[arn].get("unknown"):
        return False
    if M.ensure_builtin(state, arn):
        return True
    fetched = fetcher(arn) if fetcher else None
    if fetched:
        state.set_policy(arn, fetched["versions"], fetched["default"])
        return True
    if arn not in state.policies:
        state.set_policy(arn, {}, None, unknown=True)
    return False


def _principal_from_params(state, params, kinds=("user", "role", "group")):
    for kind in kinds:
        key = kind + "Name"
        if params.get(key):
            n = node_id(kind, params[key])
            return n if n in state.nodes else None
    return None


def _fan(state, node):
    """Nodes whose effective permissions change when `node`'s own policies change."""
    out = {node}
    if node.startswith("group:"):
        out |= {u for u in state.members.get(node, ()) if u in state.nodes}
    return out


def apply_state_event(state, ev, req, resp, fetcher=None):
    """Apply a state-changing IAM event to `state`. Returns an Impact (possibly empty)."""
    name = ev.name
    p = req if isinstance(req, dict) else {}
    acct = state.account_id

    # ---- creation / deletion of principals
    if name in ("CreateUser", "CreateRole", "CreateGroup"):
        kind = name[len("Create"):].lower()
        pname = p.get(kind + "Name")
        if not pname:
            return Impact()
        n = node_id(kind, pname)
        if n in state.nodes:
            return Impact()
        arn = _arn(state, kind, pname, resp, kind)
        boundary = p.get("permissionsBoundary") if kind != "group" else None
        trust = p.get("assumeRolePolicyDocument") if kind == "role" else None
        state.add_principal(kind, pname, arn, trust=trust, boundary=boundary)
        return Impact(added=[n])
    if name in ("DeleteUser", "DeleteRole", "DeleteGroup"):
        kind = name[len("Delete"):].lower()
        n = node_id(kind, p.get(kind + "Name", ""))
        if n not in state.nodes:
            return Impact()
        affected = _fan(state, n) - {n} if kind == "group" else set()
        state.remove_principal(n)
        return Impact(out=affected, removed=[n])

    # ---- managed policy attach / detach
    for kind in ("User", "Role", "Group"):
        if name == "Attach%sPolicy" % kind or name == "Detach%sPolicy" % kind:
            n = node_id(kind.lower(), p.get(kind.lower() + "Name", ""))
            arn = p.get("policyArn")
            if n not in state.nodes or not arn:
                return Impact()
            extra = set()
            if name.startswith("Attach"):
                if _ensure_policy(state, arn, fetcher):
                    extra = state.policy_fanout(arn)      # others already using this policy
                state.attach_policy(n, arn)
            else:
                state.detach_policy(n, arn)
            return Impact(out=_fan(state, n) | extra)
        if name == "Put%sPolicy" % kind or name == "Delete%sPolicy" % kind:
            n = node_id(kind.lower(), p.get(kind.lower() + "Name", ""))
            if n not in state.nodes:
                return Impact()
            if name.startswith("Put"):
                state.put_inline(n, p.get("policyName", "inline"), p.get("policyDocument"))
            else:
                state.delete_inline(n, p.get("policyName", "inline"))
            return Impact(out=_fan(state, n))

    # ---- managed policy lifecycle
    if name == "CreatePolicy":
        arn = (resp.get("policy") or {}).get("arn") if isinstance(resp, dict) else None
        if not arn:
            arn = "arn:aws:iam::%s:policy/%s" % (acct, p.get("policyName", "unnamed"))
        vid = ((resp.get("policy") or {}).get("defaultVersionId") if isinstance(resp, dict) else None) or "v1"
        state.set_policy(arn, {vid: p.get("policyDocument")}, vid)
        return Impact(out=state.policy_fanout(arn))
    if name == "DeletePolicy":
        arn = p.get("policyArn")
        if arn not in state.policies:
            return Impact()
        affected = state.policy_fanout(arn)
        del state.policies[arn]
        return Impact(out=affected)
    if name == "CreatePolicyVersion":
        arn = p.get("policyArn")
        if not arn:
            return Impact()
        _ensure_policy(state, arn, fetcher)
        pol = state.policies[arn]
        vid = ((resp.get("policyVersion") or {}).get("versionId") if isinstance(resp, dict) else None) \
            or "v%d" % (len(pol["versions"]) + 1)
        pol["versions"][vid] = P.load_doc(p.get("policyDocument"))
        pol["unknown"] = False
        if _truthy(p.get("setAsDefault")) or pol["default"] is None:
            pol["default"] = vid
        return Impact(out=state.policy_fanout(arn))
    if name == "SetDefaultPolicyVersion":
        arn, vid = p.get("policyArn"), p.get("versionId")
        pol = state.policies.get(arn)
        if not pol or vid not in pol["versions"]:
            return Impact()
        pol["default"] = vid
        return Impact(out=state.policy_fanout(arn))
    if name == "DeletePolicyVersion":
        arn, vid = p.get("policyArn"), p.get("versionId")
        pol = state.policies.get(arn)
        if not pol or vid not in pol["versions"] or pol["default"] == vid:
            return Impact()
        del pol["versions"][vid]
        return Impact(out=state.policy_fanout(arn))

    # ---- trust policy, groups, boundaries, instance profiles
    if name == "UpdateAssumeRolePolicy":
        n = node_id("role", p.get("roleName", ""))
        if n not in state.nodes:
            return Impact()
        state.set_trust(n, p.get("policyDocument"))
        return Impact(in_targets=[n])
    if name in ("AddUserToGroup", "RemoveUserFromGroup"):
        u, g = node_id("user", p.get("userName", "")), node_id("group", p.get("groupName", ""))
        if u not in state.nodes or g not in state.nodes:
            return Impact()
        (state.add_member if name == "AddUserToGroup" else state.remove_member)(u, g)
        return Impact(out=[u])
    if name in ("PutUserPermissionsBoundary", "PutRolePermissionsBoundary",
                "DeleteUserPermissionsBoundary", "DeleteRolePermissionsBoundary"):
        kind = "user" if "User" in name else "role"
        n = node_id(kind, p.get(kind + "Name", ""))
        if n not in state.nodes:
            return Impact()
        if name.startswith("Put"):
            arn = p.get("permissionsBoundary")
            newly = _ensure_policy(state, arn, fetcher)
            state.set_boundary(n, arn)
            if newly:
                return Impact(out=state.policy_fanout(arn) | {n})
        else:
            state.set_boundary(n, None)
        return Impact(out=[n])
    if name == "CreateInstanceProfile":
        pn = p.get("instanceProfileName")
        if pn:
            arn = (resp.get("instanceProfile") or {}).get("arn") if isinstance(resp, dict) else None
            state.add_profile(pn, arn or "arn:aws:iam::%s:instance-profile/%s" % (acct, pn))
        return Impact()
    if name == "DeleteInstanceProfile":
        prof = state.profiles.pop(p.get("instanceProfileName"), None)
        if not prof:
            return Impact()
        return Impact(in_targets=[node_id("role", r) for r in prof["roles"] if node_id("role", r) in state.nodes])
    if name in ("AddRoleToInstanceProfile", "RemoveRoleFromInstanceProfile"):
        pn, rn = p.get("instanceProfileName"), p.get("roleName")
        prof = state.profiles.get(pn)
        n = node_id("role", rn or "")
        if prof is None or n not in state.nodes:
            return Impact()
        if name.startswith("Add"):
            if rn in prof["roles"]:
                return Impact()
            prof["roles"].append(rn)
        else:
            if rn not in prof["roles"]:
                return Impact()
            prof["roles"].remove(rn)
        return Impact(in_targets=[n])
    return Impact()
