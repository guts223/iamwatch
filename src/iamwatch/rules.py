"""The technique catalog: how IAM state becomes graph edges.

An edge  SRC -> DST  labelled (tech, target)  means: "SRC can obtain the privileges of DST".
The virtual node ADMIN means full administrator access.

Edges split into two kinds, which is what makes incremental updates cheap and testable:

  * SELF edges (SRC -> ADMIN) depend only on SRC's own effective permissions
        HasAdmin                      SRC already has admin-equivalent permissions
        AttachRolePolicy / AttachUserPolicy / AttachGroupPolicy
        PutRolePolicy / PutUserPolicy / PutGroupPolicy
        CreatePolicyVersion / SetDefaultPolicyVersion

  * PAIR edges (SRC -> DST) depend on SRC's permissions and on DST's own attributes
        AssumeRole                    (identity policy + DST trust policy)
        UpdateAssumeRolePolicy        (SRC can edit DST's trust policy, then assume it)
        CreateAccessKey               (SRC can mint keys for user DST)
        UpdateLoginProfile            (SRC can set a console password for user DST)
        AddUserToGroup                (SRC can join group DST)
        PassRole:lambda|ec2|cloudformation  (SRC can run code as role DST through a service)

Edge value is a bool: True means "conditional" (an IAM Condition we could not evaluate).
"""
from . import policy as P
from .model import ADMIN, node_id

# service name -> (service principal in the role's trust policy, [actions SRC also needs], dummy resource arn)
PASSROLE_SERVICES = {
    "lambda": ("lambda.amazonaws.com",
               [("lambda:CreateFunction", "arn:aws:lambda:us-east-1:{acct}:function:canary"),
                ("lambda:InvokeFunction", "arn:aws:lambda:us-east-1:{acct}:function:canary")]),
    "ec2": ("ec2.amazonaws.com",
            [("ec2:RunInstances", "arn:aws:ec2:us-east-1:{acct}:instance/i-0canary")]),
    "cloudformation": ("cloudformation.amazonaws.com",
                       [("cloudformation:CreateStack",
                         "arn:aws:cloudformation:us-east-1:{acct}:stack/canary/00000000-0000-0000-0000-000000000000")]),
}


class PermCtx:
    """Pre-computed effective permissions of one principal (cheap to reuse across many targets)."""

    def __init__(self, state, node):
        self.state = state
        self.node = node
        self.stmts = state.identity_statements(node)
        self.boundary = state.boundary_statements(node)

    def level(self, action, resource):
        denied, lvl = P.evaluate(self.stmts, action, resource)
        if denied or lvl == P.NONE:
            return P.NONE
        if self.boundary is not None:
            bd, bl = P.evaluate(self.boundary, action, resource)
            if bd:
                return P.NONE
            lvl = min(lvl, bl)
        return lvl

    def admin_level(self):
        return P.admin_level(self.stmts, self.state.account_id, self.boundary)


def _add(out, key, lvl):
    if lvl != P.NONE:
        out[key] = (lvl == P.CONDITIONAL)


def _trust_principals(stmt):
    princ = stmt.get("Principal")
    if princ == "*":
        return ["*"], []
    if not isinstance(princ, dict):
        return [], []
    return P.as_list(princ.get("AWS")), P.as_list(princ.get("Service"))


def assume_level(state, ctx, src, role):
    """Can `src` assume `role`?  Same-account semantics:
       * trust policy names src's ARN directly      -> allowed (identity policy not required)
       * trust policy names the account root / '*'  -> identity policy must also allow sts:AssumeRole
    """
    trust = state.nodes[role]["trust"]
    src_arn = state.arn(src)
    acct = state.account_id
    direct, via_account = P.NONE, P.NONE
    for s in P.statements(trust):
        if s.get("Effect") != "Allow" or not P.action_matches(s, "sts:AssumeRole"):
            continue
        lvl = P.CONDITIONAL if s.get("Condition") else P.FULL
        aws, _ = _trust_principals(s)
        for a in aws:
            if a == src_arn:
                direct = max(direct, lvl)
            elif a in ("*", acct) or a == "arn:aws:iam::%s:root" % acct:
                via_account = max(via_account, lvl)
    identity = ctx.level("sts:AssumeRole", state.arn(role))
    return max(direct, min(via_account, identity))


def trusts_service(state, role, service_principal):
    for s in P.statements(state.nodes[role]["trust"]):
        if s.get("Effect") != "Allow" or not P.action_matches(s, "sts:AssumeRole"):
            continue
        _, services = _trust_principals(s)
        if service_principal in services:
            return True
    return False


def edges_self(state, ctx, src):
    """SELF edges: {(ADMIN, tech, target): cond}"""
    out = {}
    kind = state.kind(src)
    if kind == "group":
        _add(out, (ADMIN, "HasAdmin", ""), ctx.admin_level())
        return out
    # NOTE: self-escalation edges are kept even for principals that already are admin.  After an
    # attack succeeds the principal IS admin, and the edge of the technique that was just executed
    # must remain in the graph so the evidence stage can still match the event against it.
    _add(out, (ADMIN, "HasAdmin", ""), ctx.admin_level())
    arn = state.arn(src)
    if kind == "role":
        _add(out, (ADMIN, "AttachRolePolicy", src), ctx.level("iam:AttachRolePolicy", arn))
        _add(out, (ADMIN, "PutRolePolicy", src), ctx.level("iam:PutRolePolicy", arn))
    else:
        _add(out, (ADMIN, "AttachUserPolicy", src), ctx.level("iam:AttachUserPolicy", arn))
        _add(out, (ADMIN, "PutUserPolicy", src), ctx.level("iam:PutUserPolicy", arn))
        for g in state.nodes[src].get("groups", []):
            gn = node_id("group", g)
            if gn in state.nodes:
                garn = state.arn(gn)
                _add(out, (ADMIN, "AttachGroupPolicy", gn), ctx.level("iam:AttachGroupPolicy", garn))
                _add(out, (ADMIN, "PutGroupPolicy", gn), ctx.level("iam:PutGroupPolicy", garn))
    acct = state.account_id
    for parn in set(state.effective_policy_arns(src)):
        pol = state.policies.get(parn)
        if not pol or pol.get("unknown") or P.arn_is_aws_managed(parn):
            continue
        _add(out, (ADMIN, "CreatePolicyVersion", parn), ctx.level("iam:CreatePolicyVersion", parn))
        lvl = ctx.level("iam:SetDefaultPolicyVersion", parn)
        if lvl != P.NONE:
            for vid, doc in pol["versions"].items():
                if vid != pol["default"] and P.doc_is_admin(doc, acct):
                    _add(out, (ADMIN, "SetDefaultPolicyVersion", parn), lvl)
                    break
    return out


def edges_between(state, ctx, src, dst):
    """PAIR edges src -> dst: {(dst, tech, target): cond}.  Requires src != dst."""
    out = {}
    if src == dst:
        return out
    kind_dst = state.kind(dst)
    dst_arn = state.arn(dst)
    acct = state.account_id
    if kind_dst == "role":
        _add(out, (dst, "AssumeRole", ""), assume_level(state, ctx, src, dst))
        _add(out, (dst, "UpdateAssumeRolePolicy", ""), ctx.level("iam:UpdateAssumeRolePolicy", dst_arn))
        pr = ctx.level("iam:PassRole", dst_arn)
        if pr != P.NONE:
            for svc, (principal, needs) in PASSROLE_SERVICES.items():
                if not trusts_service(state, dst, principal):
                    continue
                if svc == "ec2" and not state.role_profiles(state.name(dst)):
                    continue
                lvl = pr
                for action, res in needs:
                    lvl = min(lvl, ctx.level(action, res.format(acct=acct)))
                _add(out, (dst, "PassRole:" + svc, ""), lvl)
    elif kind_dst == "user":
        _add(out, (dst, "CreateAccessKey", ""), ctx.level("iam:CreateAccessKey", dst_arn))
        lvl = max(ctx.level("iam:CreateLoginProfile", dst_arn), ctx.level("iam:UpdateLoginProfile", dst_arn))
        _add(out, (dst, "UpdateLoginProfile", ""), lvl)
    elif kind_dst == "group" and state.kind(src) == "user":
        if state.name(dst) not in state.nodes[src].get("groups", []):
            _add(out, (dst, "AddUserToGroup", ""), ctx.level("iam:AddUserToGroup", dst_arn))
    return out


def edges_from(state, src, ctx=None):
    """All out-edges of `src`: {(dst, tech, target): cond}."""
    ctx = ctx or PermCtx(state, src)
    out = dict(edges_self(state, ctx, src))
    if state.kind(src) == "group":
        return out           # groups never act; they only carry permissions to members
    for dst in state.nodes:
        if dst != src:
            out.update(edges_between(state, ctx, src, dst))
    return out
