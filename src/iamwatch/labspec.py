"""The lab IAM account used for the five attack scenarios.

The same specification is used by
  * lab/setup_lab.py            -> creates these identities in your real AWS lab account
  * tests/ and experiments/     -> builds an equivalent in-memory snapshot (no AWS needed)

Scenarios (each is a documented IAM privilege-escalation technique):
  s1  dev-user    -> assume eks-worker-role, then attach AdministratorAccess to that role
  s2  ci-user     -> iam:CreatePolicyVersion on its own policy (set an admin version as default)
  s3  ops-user    -> iam:UpdateAssumeRolePolicy on admin-role (add itself to the trust), then assume it
  s4  deploy-user -> iam:PassRole + lambda:CreateFunction with an admin role (lambda-target-role)
  s5  helpdesk-user -> iam:CreateAccessKey for admin-user
"""
import json

ADMIN_POLICY_ARN = "arn:aws:iam::aws:policy/AdministratorAccess"
READONLY_POLICY_ARN = "arn:aws:iam::aws:policy/ReadOnlyAccess"
ADMIN_DOC = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}
READONLY_DOC = {"Version": "2012-10-17", "Statement": [
    {"Effect": "Allow", "Action": ["*:Get*", "*:List*", "*:Describe*"], "Resource": "*"}]}

USERS = ["dev-user", "ci-user", "ops-user", "deploy-user", "helpdesk-user", "admin-user"]
ROLES = ["eks-worker-role", "admin-role", "lambda-target-role", "readonly-role"]
# identities added for the four extra attack families and for realistic benign activity
USERS_X = ["chain-user", "joiner-user", "selfput-user", "rollback-user", "normal-user", "ci-deployer", "helpdesk2"]
ROLES_X = ["stage-role", "prod-admin-role", "app-lambda-role"]
GROUPS_X = ["admins-group"]
KEY_USERS_ALL = ["dev-user", "ci-user", "ops-user", "deploy-user", "helpdesk-user",
                 "chain-user", "joiner-user", "selfput-user", "rollback-user", "ci-deployer", "helpdesk2"]
CI_POLICY_NAME = "iamwatch-lab-ci-policy"
SCENARIOS = ["s1", "s2", "s3", "s4", "s5"]          # covered by simple single-event rules
EXTRA_SCENARIOS = ["x1", "x2", "x3", "x4"]          # multi-step / state-based: NOT covered by those rules
LIVE_SCENARIOS = SCENARIOS + EXTRA_SCENARIOS
SCENARIO_ORIGIN = {"s1": "dev-user", "s2": "ci-user", "s3": "ops-user", "s4": "deploy-user",
                   "s5": "helpdesk-user", "x1": "chain-user", "x2": "joiner-user", "x3": "selfput-user",
                   "x4": "rollback-user"}
ROLLBACK_POLICY_NAME = "iamwatch-lab-rollback-policy"
SCENARIO_TITLE = {
    "x1": "3-hop AssumeRole chain to an admin role",
    "x2": "AddUserToGroup into an admin group",
    "x3": "PutUserPolicy on yourself (inline admin policy)",
    "x4": "SetDefaultPolicyVersion rollback to an admin version",
    "s1": "AssumeRole then AttachRolePolicy on the assumed role",
    "s2": "CreatePolicyVersion (set admin version as default)",
    "s3": "UpdateAssumeRolePolicy then AssumeRole of an admin role",
    "s4": "PassRole + Lambda CreateFunction with an admin role",
    "s5": "CreateAccessKey for an admin user",
}


def user_arn(acct, name):
    return "arn:aws:iam::%s:user/%s" % (acct, name)


def role_arn(acct, name):
    return "arn:aws:iam::%s:role/%s" % (acct, name)


def ci_policy_arn(acct):
    return "arn:aws:iam::%s:policy/%s" % (acct, CI_POLICY_NAME)


def _stmt(action, resource, effect="Allow"):
    return {"Effect": effect, "Action": action, "Resource": resource}


def _doc(*stmts):
    return {"Version": "2012-10-17", "Statement": list(stmts)}


def trust_user(acct, user):
    return {"Version": "2012-10-17", "Statement": [
        {"Effect": "Allow", "Principal": {"AWS": user_arn(acct, user)}, "Action": "sts:AssumeRole"}]}


def trust_root(acct):
    return {"Version": "2012-10-17", "Statement": [
        {"Effect": "Allow", "Principal": {"AWS": "arn:aws:iam::%s:root" % acct}, "Action": "sts:AssumeRole"}]}


def trust_service(service):
    return {"Version": "2012-10-17", "Statement": [
        {"Effect": "Allow", "Principal": {"Service": service}, "Action": "sts:AssumeRole"}]}


def lab_spec(acct):
    """Returns dict with users / roles / customer policy definitions for account `acct`."""
    eks = role_arn(acct, "eks-worker-role")
    adm = role_arn(acct, "admin-role")
    lam = role_arn(acct, "lambda-target-role")
    ro = role_arn(acct, "readonly-role")
    ci_arn = ci_policy_arn(acct)
    users = {
        "dev-user": {"inline": {"assume-eks": _doc(_stmt("sts:AssumeRole", [eks, ro]))}, "managed": []},
        "ci-user": {"inline": {}, "managed": [ci_arn]},
        "ops-user": {"inline": {"edit-admin-trust": _doc(_stmt("iam:UpdateAssumeRolePolicy", adm))},
                     "managed": []},
        "deploy-user": {"inline": {"deploy-lambda": _doc(
            _stmt("iam:PassRole", lam), _stmt(["lambda:CreateFunction", "lambda:InvokeFunction"], "*"))},
            "managed": []},
        "helpdesk-user": {"inline": {"reset-keys": _doc(_stmt("iam:CreateAccessKey", user_arn(acct, "admin-user")))},
                          "managed": []},
        "admin-user": {"inline": {}, "managed": [ADMIN_POLICY_ARN]},
    }
    roles = {
        "eks-worker-role": {"trust": trust_user(acct, "dev-user"),
                            "inline": {"self-attach": _doc(_stmt("iam:AttachRolePolicy", eks),
                                                           _stmt("s3:ListAllMyBuckets", "*"))},
                            "managed": []},
        "admin-role": {"trust": trust_root(acct), "inline": {}, "managed": [ADMIN_POLICY_ARN]},
        "lambda-target-role": {"trust": trust_service("lambda.amazonaws.com"), "inline": {},
                               "managed": [ADMIN_POLICY_ARN]},
        "readonly-role": {"trust": trust_user(acct, "dev-user"), "inline": {},
                          "managed": [READONLY_POLICY_ARN]},
    }
    ci_doc = _doc(_stmt("iam:CreatePolicyVersion", ci_arn), _stmt("s3:ListAllMyBuckets", "*"))
    return {"users": users, "roles": roles, "ci_policy": {"arn": ci_arn, "doc": ci_doc}}


def rollback_policy_arn(acct):
    return "arn:aws:iam::%s:policy/%s" % (acct, ROLLBACK_POLICY_NAME)


LOW_DOC = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "s3:ListAllMyBuckets", "Resource": "*"}]}


def group_arn(acct, name):
    return "arn:aws:iam::%s:group/%s" % (acct, name)


def full_spec(acct):
    """The five original lab identities + the four extra attack families + benign principals.

    Used by lab/setup_lab.py (real account) and by the simulator, so both describe the same account.
    Role order matters when creating: stage-role must exist before prod-admin-role trusts it.
    """
    spec = lab_spec(acct)
    rb = rollback_policy_arn(acct)
    adm_grp = group_arn(acct, "admins-group")
    spec["users"].update({
        "chain-user": {"inline": {}, "managed": []},
        "joiner-user": {"inline": {"join": _doc(_stmt("iam:AddUserToGroup", adm_grp))}, "managed": []},
        "selfput-user": {"inline": {"self-put": _doc(_stmt("iam:PutUserPolicy", user_arn(acct, "selfput-user")))},
                         "managed": []},
        "rollback-user": {"inline": {"flip": _doc(_stmt("iam:SetDefaultPolicyVersion", rb))}, "managed": [rb]},
        "normal-user": {"inline": {}, "managed": []},
        "ci-deployer": {"inline": {"deploy": _doc(_stmt("iam:PassRole", role_arn(acct, "app-lambda-role")),
                                                  _stmt(["lambda:CreateFunction", "lambda:InvokeFunction"], "*"))},
                        "managed": []},
        "helpdesk2": {"inline": {"keys": _doc(_stmt("iam:CreateAccessKey", user_arn(acct, "normal-user")))},
                      "managed": []},
    })
    spec["roles"].update({
        "stage-role": {"trust": trust_user(acct, "chain-user"), "inline": {"low": LOW_DOC}, "managed": []},
        "prod-admin-role": {"trust": {"Version": "2012-10-17", "Statement": [
            {"Effect": "Allow", "Principal": {"AWS": role_arn(acct, "stage-role")}, "Action": "sts:AssumeRole"}]},
            "inline": {}, "managed": [ADMIN_POLICY_ARN]},
        "app-lambda-role": {"trust": trust_service("lambda.amazonaws.com"), "inline": {},
                            "managed": [READONLY_POLICY_ARN]},
    })
    spec["groups"] = {"admins-group": {"managed": [ADMIN_POLICY_ARN]}}
    # v1 = admin document (not default), v2 = harmless document (default); scenario x4 flips the default back to v1
    spec["rollback_policy"] = {"arn": rb, "versions": [("v1", ADMIN_DOC, False), ("v2", LOW_DOC, True)]}
    return spec


def full_authorization_details(acct="123456789012"):
    """In-memory equivalent of iam:GetAccountAuthorizationDetails for full_spec()."""
    spec = full_spec(acct)
    d = lab_authorization_details(acct)           # original nine principals + three policies
    have_u = {u["UserName"] for u in d["UserDetailList"]}
    have_r = {r["RoleName"] for r in d["RoleDetailList"]}
    for name, u in spec["users"].items():
        if name in have_u:
            continue
        d["UserDetailList"].append({
            "UserName": name, "Arn": user_arn(acct, name), "GroupList": [], "AttachedManagedPolicies": [
                {"PolicyName": a.rsplit("/", 1)[-1], "PolicyArn": a} for a in u["managed"]],
            "UserPolicyList": [{"PolicyName": pn, "PolicyDocument": doc} for pn, doc in u["inline"].items()]})
    for name, r in spec["roles"].items():
        if name in have_r:
            continue
        d["RoleDetailList"].append({
            "RoleName": name, "Arn": role_arn(acct, name), "AssumeRolePolicyDocument": r["trust"],
            "AttachedManagedPolicies": [{"PolicyName": a.rsplit("/", 1)[-1], "PolicyArn": a} for a in r["managed"]],
            "RolePolicyList": [{"PolicyName": pn, "PolicyDocument": doc} for pn, doc in r["inline"].items()],
            "InstanceProfileList": []})
    for name, g in spec["groups"].items():
        d["GroupDetailList"].append({
            "GroupName": name, "Arn": group_arn(acct, name), "GroupPolicyList": [],
            "AttachedManagedPolicies": [{"PolicyName": a.rsplit("/", 1)[-1], "PolicyArn": a} for a in g["managed"]]})
    rb = spec["rollback_policy"]
    d["Policies"].append({
        "PolicyName": ROLLBACK_POLICY_NAME, "Arn": rb["arn"], "AttachmentCount": 1, "DefaultVersionId": "v2",
        "PolicyVersionList": [{"VersionId": v, "Document": doc, "IsDefaultVersion": dflt}
                              for v, doc, dflt in sorted(rb["versions"], reverse=True)]})
    return d


def lab_authorization_details(acct="123456789012"):
    """An in-memory equivalent of iam:GetAccountAuthorizationDetails for the lab account."""
    spec = lab_spec(acct)
    users, roles = [], []
    for name, u in spec["users"].items():
        users.append({
            "UserName": name, "Arn": user_arn(acct, name), "GroupList": [], "AttachedManagedPolicies": [
                {"PolicyName": a.rsplit("/", 1)[-1], "PolicyArn": a} for a in u["managed"]],
            "UserPolicyList": [{"PolicyName": pn, "PolicyDocument": d} for pn, d in u["inline"].items()]})
    for name, r in spec["roles"].items():
        roles.append({
            "RoleName": name, "Arn": role_arn(acct, name), "AssumeRolePolicyDocument": r["trust"],
            "AttachedManagedPolicies": [{"PolicyName": a.rsplit("/", 1)[-1], "PolicyArn": a} for a in r["managed"]],
            "RolePolicyList": [{"PolicyName": pn, "PolicyDocument": d} for pn, d in r["inline"].items()],
            "InstanceProfileList": []})
    policies = [
        {"PolicyName": "AdministratorAccess", "Arn": ADMIN_POLICY_ARN, "AttachmentCount": 3,
         "DefaultVersionId": "v1", "PolicyVersionList": [{"VersionId": "v1", "Document": ADMIN_DOC,
                                                          "IsDefaultVersion": True}]},
        {"PolicyName": "ReadOnlyAccess", "Arn": READONLY_POLICY_ARN, "AttachmentCount": 1,
         "DefaultVersionId": "v1", "PolicyVersionList": [{"VersionId": "v1", "Document": READONLY_DOC,
                                                          "IsDefaultVersion": True}]},
        {"PolicyName": CI_POLICY_NAME, "Arn": spec["ci_policy"]["arn"], "AttachmentCount": 1,
         "DefaultVersionId": "v1", "PolicyVersionList": [{"VersionId": "v1", "Document": spec["ci_policy"]["doc"],
                                                          "IsDefaultVersion": True}]},
    ]
    return {"UserDetailList": users, "RoleDetailList": roles, "GroupDetailList": [], "Policies": policies}


def dumps(doc):
    return json.dumps(doc, separators=(",", ":"))
