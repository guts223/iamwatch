"""Simulation account used by experiments/simulate.py (no AWS needed).

The lab account of labspec.py (scenarios s1-s5, which the simple stateless rules DO cover)
extended with four attack families that stateless rules without an IAM inventory do NOT cover,
plus benign principals that make noisy rules fire, plus random noise principals.

  x1  3-hop AssumeRole chain  chain-user -> stage-role -> prod-admin-role   (every step looks routine)
  x2  AddUserToGroup into an administrators group
  x3  PutUserPolicy on yourself (inline admin policy)
  x4  SetDefaultPolicyVersion rollback to an old admin version
"""
import copy
import json

from . import labspec as L
from . import synth

ACCT = "123456789012"
COVERED = ["s1", "s2", "s3", "s4", "s5"]
UNCOVERED = ["x1", "x2", "x3", "x4"]
ALL = COVERED + UNCOVERED
ORIGIN = dict(L.SCENARIO_ORIGIN, x1="chain-user", x2="joiner-user", x3="selfput-user", x4="rollback-user")
TITLE = dict(L.SCENARIO_TITLE, x1="3-hop AssumeRole chain to an admin role", x2="AddUserToGroup into an admin group",
             x3="PutUserPolicy on yourself", x4="SetDefaultPolicyVersion rollback to an admin version")

ROLLBACK_ARN = L.rollback_policy_arn(ACCT)
LOW_DOC = L.LOW_DOC


def _user(name, inline=None, managed=None, groups=None):
    return {"UserName": name, "Arn": L.user_arn(ACCT, name), "GroupList": groups or [],
            "AttachedManagedPolicies": [{"PolicyName": a.rsplit("/", 1)[-1], "PolicyArn": a} for a in (managed or [])],
            "UserPolicyList": [{"PolicyName": k, "PolicyDocument": v} for k, v in (inline or {}).items()]}


def _role(name, trust, inline=None, managed=None):
    return {"RoleName": name, "Arn": L.role_arn(ACCT, name), "AssumeRolePolicyDocument": trust,
            "AttachedManagedPolicies": [{"PolicyName": a.rsplit("/", 1)[-1], "PolicyArn": a} for a in (managed or [])],
            "RolePolicyList": [{"PolicyName": k, "PolicyDocument": v} for k, v in (inline or {}).items()],
            "InstanceProfileList": []}


def stmt(action, resource):
    return {"Effect": "Allow", "Action": action, "Resource": resource}


def doc(*s):
    return {"Version": "2012-10-17", "Statement": list(s)}


def build_details(rng=None, n_noise=0):
    d = copy.deepcopy(L.full_authorization_details(ACCT))
    # noise: random low-privilege users and roles, some with assume-role trusts to low-priv roles
    if rng is not None:
        for i in range(n_noise):
            name = "noise-u%d" % i
            d["UserDetailList"].append(_user(name, {"p": doc(stmt(["s3:GetObject", "s3:ListBucket"], "*"))}))
        for i in range(n_noise):
            tgt = "noise-u%d" % rng.randrange(max(n_noise, 1))
            d["RoleDetailList"].append(_role("noise-r%d" % i, L.trust_user(ACCT, tgt), {"p": LOW_DOC}))
    return d


def attack_events(kind, t0, gap=30, key_suffix=""):
    """CloudTrail events of scenario `kind`; hop gap is configurable."""
    if kind in L.SCENARIOS:
        evs = synth.scenario_events(kind, ACCT, t0, key_suffix)
        if len(evs) == 2 and gap != 30:                       # re-time the second hop
            evs[1]["eventTime"] = synth.iso(t0 + gap)
        return evs
    ks = key_suffix
    adm = lambda name, key=None: synth.user_actor(ACCT, name, key or synth.KEYS.get(name, "AKIA" + name.upper()[:12].ljust(12, "0")))
    if kind == "x1":
        s1, s2 = "ASIASTAGE" + ks.ljust(8, "0"), "ASIAPROD" + ks.ljust(8, "0")
        return [
            synth.make_event("AssumeRole", adm("chain-user"),
                             {"roleArn": L.role_arn(ACCT, "stage-role"), "roleSessionName": "a"},
                             {"credentials": {"accessKeyId": s1}}, t0),
            synth.make_event("AssumeRole", synth.role_actor(ACCT, "stage-role", s1, "a"),
                             {"roleArn": L.role_arn(ACCT, "prod-admin-role"), "roleSessionName": "b"},
                             {"credentials": {"accessKeyId": s2}}, t0 + gap)]
    if kind == "x2":
        return [synth.make_event("AddUserToGroup", adm("joiner-user"),
                                 {"userName": "joiner-user", "groupName": "admins-group"}, None, t0)]
    if kind == "x3":
        return [synth.make_event("PutUserPolicy", adm("selfput-user"),
                                 {"userName": "selfput-user", "policyName": "x", "policyDocument": L.dumps(L.ADMIN_DOC)},
                                 None, t0)]
    if kind == "x4":
        return [synth.make_event("SetDefaultPolicyVersion", adm("rollback-user"),
                                 {"policyArn": ROLLBACK_ARN, "versionId": "v1"}, None, t0)]
    raise ValueError(kind)


def enabling_events(details, origin, t):
    """Strip the capability that makes `origin` dangerous; return (details, events that grant it back)."""
    d = copy.deepcopy(details)
    evs = []
    admin = synth.user_actor(ACCT, "admin-user", synth.KEYS["admin-user"])
    for u in d["UserDetailList"]:
        if u["UserName"] != origin:
            continue
        for ip in u["UserPolicyList"]:
            evs.append(synth.make_event("PutUserPolicy", admin, {"userName": origin, "policyName": ip["PolicyName"],
                                                                 "policyDocument": json.dumps(ip["PolicyDocument"])},
                                        None, t))
        for ap in u["AttachedManagedPolicies"]:
            evs.append(synth.make_event("AttachUserPolicy", admin, {"userName": origin, "policyArn": ap["PolicyArn"]},
                                        None, t))
        u["UserPolicyList"], u["AttachedManagedPolicies"] = [], []
    return d, evs


def benign_workload(rng, t0, n=40):
    """Harmless activity incl. events that noisy stateless rules (R4, R5) flag."""
    out, t = [], t0
    admin = synth.user_actor(ACCT, "admin-user", synth.KEYS["admin-user"])
    for i in range(n):
        t += rng.randint(20, 400)
        kind = rng.choice(["role-cycle", "dev-readonly", "lambda-deploy", "helpdesk-key", "assume-stage"])
        if kind == "role-cycle":
            nm = "tmp-%d" % i
            out += [synth.make_event("CreateRole", admin, {"roleName": nm, "assumeRolePolicyDocument":
                                                           L.dumps(L.trust_service("ec2.amazonaws.com"))},
                                     {"role": {"arn": L.role_arn(ACCT, nm)}}, t),
                    synth.make_event("AttachRolePolicy", admin, {"roleName": nm, "policyArn": L.READONLY_POLICY_ARN},
                                     None, t + 2),
                    synth.make_event("DetachRolePolicy", admin, {"roleName": nm, "policyArn": L.READONLY_POLICY_ARN},
                                     None, t + 4),
                    synth.make_event("DeleteRole", admin, {"roleName": nm}, None, t + 6)]
        elif kind == "dev-readonly":
            out.append(synth.make_event("AssumeRole", synth.user_actor(ACCT, "dev-user", synth.KEYS["dev-user"]),
                                        {"roleArn": L.role_arn(ACCT, "readonly-role"), "roleSessionName": "d"},
                                        {"credentials": {"accessKeyId": "ASIAREAD%08d" % i}}, t))
        elif kind == "lambda-deploy":
            out.append(synth.make_event("CreateFunction20150331",
                                        synth.user_actor(ACCT, "ci-deployer", "AKIACIDEPLOYER001"),
                                        {"functionName": "app-%d" % i, "role": L.role_arn(ACCT, "app-lambda-role")},
                                        {"functionName": "app-%d" % i}, t))
        elif kind == "helpdesk-key":
            out.append(synth.make_event("CreateAccessKey", synth.user_actor(ACCT, "helpdesk2", "AKIAHELPDESK2001"),
                                        {"userName": "normal-user"},
                                        {"accessKey": {"accessKeyId": "AKIANORMAL%07d" % i}}, t))
        else:
            out.append(synth.make_event("AssumeRole", synth.user_actor(ACCT, "chain-user", synth.KEYS.get("chain-user", "AKIACHAINUSER0001")),
                                        {"roleArn": L.role_arn(ACCT, "stage-role"), "roleSessionName": "routine"},
                                        {"credentials": {"accessKeyId": "ASIASTG%09d" % i}}, t))
    return out
