"""Randomised correctness test: after ANY sequence of IAM events, the incrementally
maintained graph (edges + hop distances) must equal one rebuilt from scratch."""
import json
import random

import pytest

from iamwatch import synth
from iamwatch.engine import Engine
from iamwatch.model import IamState, node_id

ACCT = "123456789012"
ACTIONS = ["iam:AttachRolePolicy", "iam:PutRolePolicy", "iam:AttachUserPolicy", "iam:PutUserPolicy",
           "iam:AttachGroupPolicy", "iam:CreatePolicyVersion", "iam:SetDefaultPolicyVersion",
           "iam:UpdateAssumeRolePolicy", "iam:CreateAccessKey", "iam:AddUserToGroup", "iam:PassRole",
           "sts:AssumeRole", "lambda:CreateFunction", "lambda:InvokeFunction", "ec2:RunInstances",
           "cloudformation:CreateStack", "iam:*", "s3:GetObject", "sts:*", "iam:Create*"]
SERVICES = ["lambda.amazonaws.com", "ec2.amazonaws.com", "cloudformation.amazonaws.com"]


class Gen:
    def __init__(self, seed, n_users=5, n_roles=6, n_groups=2, n_policies=3):
        self.r = random.Random(seed)
        self.t = 1_000_000.0
        self.users = ["u%d" % i for i in range(n_users)]
        self.roles = ["r%d" % i for i in range(n_roles)]
        self.groups = ["g%d" % i for i in range(n_groups)]
        self.policies = ["arn:aws:iam::%s:policy/p%d" % (ACCT, i) for i in range(n_policies)]
        self.aws_pols = ["arn:aws:iam::aws:policy/AdministratorAccess",
                         "arn:aws:iam::aws:policy/ReadOnlyAccess",
                         "arn:aws:iam::aws:policy/PowerUserAccess"]
        self.profiles = ["ip0", "ip1"]

    def arn(self, kind, name):
        return "arn:aws:iam::%s:%s/%s" % (ACCT, kind, name)

    def resource(self):
        r = self.r
        choice = r.random()
        if choice < 0.35:
            return "*"
        if choice < 0.5:
            return "arn:aws:iam::%s:role/*" % ACCT
        if choice < 0.6:
            return "arn:aws:iam::%s:user/*" % ACCT
        kind = r.choice(["user", "role", "group", "policy"])
        pool = {"user": self.users, "role": self.roles, "group": self.groups}.get(kind)
        if kind == "policy":
            return r.choice(self.policies)
        return self.arn(kind, r.choice(pool))

    def doc(self):
        r = self.r
        stmts = []
        for _ in range(r.randint(1, 3)):
            s = {"Effect": "Deny" if r.random() < 0.08 else "Allow",
                 "Action": r.sample(ACTIONS, r.randint(1, 3)), "Resource": self.resource()}
            if r.random() < 0.1:
                s["Condition"] = {"Bool": {"aws:MultiFactorAuthPresent": "true"}}
            stmts.append(s)
        if r.random() < 0.08:
            stmts.append({"Effect": "Allow", "Action": "*", "Resource": "*"})
        return {"Version": "2012-10-17", "Statement": stmts}

    def trust(self):
        r = self.r
        principals = []
        for _ in range(r.randint(0, 2)):
            principals.append(r.choice([self.arn("user", r.choice(self.users)),
                                        self.arn("role", r.choice(self.roles)),
                                        "arn:aws:iam::%s:root" % ACCT]))
        stmts = []
        if principals:
            stmts.append({"Effect": "Allow", "Principal": {"AWS": principals}, "Action": "sts:AssumeRole",
                          **({"Condition": {"StringEquals": {"sts:ExternalId": "x"}}} if r.random() < 0.1 else {})})
        if r.random() < 0.5:
            stmts.append({"Effect": "Allow", "Principal": {"Service": r.choice(SERVICES)},
                          "Action": "sts:AssumeRole"})
        return {"Version": "2012-10-17", "Statement": stmts}

    def initial_details(self):
        r = self.r
        users, roles, groups, pols = [], [], [], []
        for g in self.groups:
            groups.append({"GroupName": g, "Arn": self.arn("group", g),
                           "AttachedManagedPolicies": [{"PolicyArn": a} for a in r.sample(self.policies + self.aws_pols, r.randint(0, 2))],
                           "GroupPolicyList": [{"PolicyName": "i", "PolicyDocument": self.doc()}] if r.random() < 0.4 else []})
        for u in self.users:
            users.append({"UserName": u, "Arn": self.arn("user", u),
                          "GroupList": r.sample(self.groups, r.randint(0, 2)),
                          "AttachedManagedPolicies": [{"PolicyArn": a} for a in r.sample(self.policies + self.aws_pols, r.randint(0, 2))],
                          "UserPolicyList": [{"PolicyName": "i%d" % i, "PolicyDocument": self.doc()}
                                             for i in range(r.randint(0, 2))]})
        for ro in self.roles:
            roles.append({"RoleName": ro, "Arn": self.arn("role", ro), "AssumeRolePolicyDocument": self.trust(),
                          "AttachedManagedPolicies": [{"PolicyArn": a} for a in r.sample(self.policies + self.aws_pols, r.randint(0, 2))],
                          "RolePolicyList": [{"PolicyName": "i%d" % i, "PolicyDocument": self.doc()}
                                             for i in range(r.randint(0, 2))],
                          "InstanceProfileList": [{"InstanceProfileName": "ip0", "Arn": self.arn("instance-profile", "ip0")}]
                          if r.random() < 0.3 else []})
        for a in self.policies:
            pols.append({"PolicyName": a.rsplit("/", 1)[-1], "Arn": a, "AttachmentCount": 1, "DefaultVersionId": "v1",
                         "PolicyVersionList": [{"VersionId": "v1", "Document": self.doc(), "IsDefaultVersion": True},
                                               {"VersionId": "v2", "Document": self.doc(), "IsDefaultVersion": False}]})
        return {"UserDetailList": users, "RoleDetailList": roles, "GroupDetailList": groups, "Policies": pols}

    def event(self):
        """A random state-changing event."""
        r = self.r
        self.t += r.randint(1, 20)
        actor = synth.user_actor(ACCT, "u0", "AKIAU0")
        kind = r.choice(["Attach", "Detach", "Put", "DeleteInline", "NewVersion", "SetDefault", "Trust",
                         "AddMember", "RemMember", "CreatePrincipal", "DeletePrincipal", "Profile",
                         "Boundary", "DelVersion"])
        mk = lambda name, params, resp=None: synth.make_event(name, actor, params, resp, self.t)
        who = r.choice(["User", "Role", "Group"])
        wname = {"User": self.users, "Role": self.roles, "Group": self.groups}[who]
        if kind == "Attach":
            return mk("Attach%sPolicy" % who, {who.lower() + "Name": r.choice(wname),
                                              "policyArn": r.choice(self.policies + self.aws_pols)})
        if kind == "Detach":
            return mk("Detach%sPolicy" % who, {who.lower() + "Name": r.choice(wname),
                                              "policyArn": r.choice(self.policies + self.aws_pols)})
        if kind == "Put":
            return mk("Put%sPolicy" % who, {who.lower() + "Name": r.choice(wname),
                                           "policyName": "i%d" % r.randint(0, 2),
                                           "policyDocument": json.dumps(self.doc())})
        if kind == "DeleteInline":
            return mk("Delete%sPolicy" % who, {who.lower() + "Name": r.choice(wname),
                                              "policyName": "i%d" % r.randint(0, 2)})
        if kind == "NewVersion":
            return mk("CreatePolicyVersion", {"policyArn": r.choice(self.policies),
                                             "policyDocument": json.dumps(self.doc()),
                                             "setAsDefault": r.random() < 0.5},
                      {"policyVersion": {"versionId": "v%d" % r.randint(3, 9)}})
        if kind == "SetDefault":
            return mk("SetDefaultPolicyVersion", {"policyArn": r.choice(self.policies),
                                                 "versionId": r.choice(["v1", "v2", "v3", "v4"])})
        if kind == "DelVersion":
            return mk("DeletePolicyVersion", {"policyArn": r.choice(self.policies),
                                             "versionId": r.choice(["v1", "v2", "v3", "v4"])})
        if kind == "Trust":
            return mk("UpdateAssumeRolePolicy", {"roleName": r.choice(self.roles),
                                                "policyDocument": json.dumps(self.trust())})
        if kind in ("AddMember", "RemMember"):
            return mk("AddUserToGroup" if kind == "AddMember" else "RemoveUserFromGroup",
                      {"userName": r.choice(self.users), "groupName": r.choice(self.groups)})
        if kind == "CreatePrincipal":
            k = r.choice(["User", "Role", "Group"])
            nm = {"User": "u", "Role": "r", "Group": "g"}[k] + str(r.randint(0, 9))
            params = {k.lower() + "Name": nm}
            if k == "Role":
                params["assumeRolePolicyDocument"] = json.dumps(self.trust())
            return mk("Create" + k, params, {k.lower(): {"arn": self.arn(k.lower(), nm)}})
        if kind == "DeletePrincipal":
            k = r.choice(["User", "Role", "Group"])
            nm = {"User": "u", "Role": "r", "Group": "g"}[k] + str(r.randint(0, 9))
            return mk("Delete" + k, {k.lower() + "Name": nm})
        if kind == "Profile":
            op = r.choice(["Create", "Add", "Remove", "Delete"])
            if op == "Create":
                return mk("CreateInstanceProfile", {"instanceProfileName": r.choice(self.profiles)})
            if op == "Delete":
                return mk("DeleteInstanceProfile", {"instanceProfileName": r.choice(self.profiles)})
            return mk(op + "RoleToInstanceProfile" if op == "Add" else "RemoveRoleFromInstanceProfile",
                      {"instanceProfileName": r.choice(self.profiles), "roleName": r.choice(self.roles)})
        if kind == "Boundary":
            k = r.choice(["User", "Role"])
            nm = r.choice(self.users if k == "User" else self.roles)
            if r.random() < 0.5:
                return mk("Put%sPermissionsBoundary" % k, {k.lower() + "Name": nm,
                                                          "permissionsBoundary": r.choice(self.policies + self.aws_pols)})
            return mk("Delete%sPermissionsBoundary" % k, {k.lower() + "Name": nm})


@pytest.mark.parametrize("seed", range(60))
def test_incremental_equals_rebuild(seed):
    g = Gen(seed)
    eng = Engine.from_snapshot(g.initial_details(), k=5)
    ok, diffs = eng.check_equivalence()
    assert ok, diffs
    for i in range(40):
        eng.process(g.event())
        if i % 5 == 4 or i == 39:
            ok, diffs = eng.check_equivalence()
            assert ok, (seed, i, diffs)


@pytest.mark.parametrize("k", [1, 2, 3, 6])
def test_equivalence_for_other_k(k):
    for seed in range(10):
        g = Gen(1000 + seed)
        eng = Engine.from_snapshot(g.initial_details(), k=k)
        for i in range(30):
            eng.process(g.event())
        ok, diffs = eng.check_equivalence()
        assert ok, (k, seed, diffs)
