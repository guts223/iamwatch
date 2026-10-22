"""Builders for CloudTrail-shaped events (tests, offline simulation, replay demos).

These produce the same JSON structure as the `detail` field of an EventBridge
"AWS API Call via CloudTrail" event, restricted to the fields iamwatch reads.
"""
import itertools
import json
from datetime import datetime, timezone

from . import labspec as L

_counter = itertools.count(1)


def iso(t):
    return datetime.fromtimestamp(t, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def user_actor(acct, name, key):
    return {"type": "IAMUser", "principalId": "AIDA" + name.upper()[:12], "arn": L.user_arn(acct, name),
            "accountId": acct, "accessKeyId": key, "userName": name}


def role_actor(acct, role, key, session="session"):
    return {"type": "AssumedRole", "principalId": "AROA%s:%s" % (role.upper()[:10], session),
            "arn": "arn:aws:sts::%s:assumed-role/%s/%s" % (acct, role, session), "accountId": acct,
            "accessKeyId": key,
            "sessionContext": {"sessionIssuer": {"type": "Role", "arn": L.role_arn(acct, role),
                                                 "accountId": acct, "userName": role}}}


SOURCES = {"AssumeRole": "sts.amazonaws.com", "CreateFunction20150331": "lambda.amazonaws.com",
           "RunInstances": "ec2.amazonaws.com", "CreateStack": "cloudformation.amazonaws.com"}


def make_event(name, actor, params=None, resp=None, t=0.0, eid=None, error=None):
    return {
        "eventVersion": "1.08", "eventTime": iso(t), "eventSource": SOURCES.get(name, "iam.amazonaws.com"),
        "eventName": name, "awsRegion": "us-east-1", "sourceIPAddress": "203.0.113.9",
        "userAgent": "aws-cli/2.15", "userIdentity": actor, "requestParameters": params,
        "responseElements": resp, "eventID": eid or "evt-%08d" % next(_counter),
        "readOnly": False, "eventType": "AwsApiCall", "managementEvent": True,
        **({"errorCode": error} if error else {}),
    }


# fixed access keys of the lab users (simulation only; real keys come from lab_credentials.json)
KEYS = {"dev-user": "AKIADEVUSER000001", "ci-user": "AKIACIUSER0000001", "ops-user": "AKIAOPSUSER000001",
        "deploy-user": "AKIADEPLOY0000001", "helpdesk-user": "AKIAHELPDESK00001", "admin-user": "AKIAADMINUSER0001"}


def scenario_events(kind, acct, t0, key_suffix=""):
    """The CloudTrail events a real run of scenario `kind` produces (hop gap = 30 s)."""
    ks = key_suffix
    if kind == "s1":
        sess = "ASIAEKS" + ks + "00000001"
        return [
            make_event("AssumeRole", user_actor(acct, "dev-user", KEYS["dev-user"]),
                       {"roleArn": L.role_arn(acct, "eks-worker-role"), "roleSessionName": "attack"},
                       {"credentials": {"accessKeyId": sess, "expiration": "x"}}, t0),
            make_event("AttachRolePolicy", role_actor(acct, "eks-worker-role", sess, "attack"),
                       {"roleName": "eks-worker-role", "policyArn": L.ADMIN_POLICY_ARN}, None, t0 + 30),
        ]
    if kind == "s2":
        return [make_event(
            "CreatePolicyVersion", user_actor(acct, "ci-user", KEYS["ci-user"]),
            {"policyArn": L.ci_policy_arn(acct), "policyDocument": L.dumps(L.ADMIN_DOC), "setAsDefault": True},
            {"policyVersion": {"versionId": "v2", "isDefaultVersion": True}}, t0)]
    if kind == "s3":
        sess = "ASIAADM" + ks + "00000001"
        trust = {"Version": "2012-10-17", "Statement": [
            {"Effect": "Allow", "Principal": {"AWS": [L.user_arn(acct, "ops-user"),
                                                      "arn:aws:iam::%s:root" % acct]},
             "Action": "sts:AssumeRole"}]}
        actor = user_actor(acct, "ops-user", KEYS["ops-user"])
        return [
            make_event("UpdateAssumeRolePolicy", actor,
                       {"roleName": "admin-role", "policyDocument": L.dumps(trust)}, None, t0),
            make_event("AssumeRole", actor, {"roleArn": L.role_arn(acct, "admin-role"),
                                             "roleSessionName": "attack"},
                       {"credentials": {"accessKeyId": sess, "expiration": "x"}}, t0 + 30),
        ]
    if kind == "s4":
        return [make_event(
            "CreateFunction20150331", user_actor(acct, "deploy-user", KEYS["deploy-user"]),
            {"functionName": "evil-fn", "role": L.role_arn(acct, "lambda-target-role"),
             "runtime": "python3.12", "handler": "index.handler"},
            {"functionName": "evil-fn"}, t0)]
    if kind == "s5":
        return [make_event(
            "CreateAccessKey", user_actor(acct, "helpdesk-user", KEYS["helpdesk-user"]),
            {"userName": "admin-user"},
            {"accessKey": {"accessKeyId": "AKIANEWKEY" + ks.ljust(7, "0"), "userName": "admin-user",
                           "status": "Active"}}, t0)]
    raise ValueError(kind)


def benign_events(acct, t0):
    """Harmless activity that should NOT produce an ACTIVE alert."""
    adm = user_actor(acct, "admin-user", KEYS["admin-user"])
    return [
        make_event("CreateRole", adm, {"roleName": "tmp-benign-role", "assumeRolePolicyDocument":
                                       L.dumps(L.trust_service("ec2.amazonaws.com"))},
                   {"role": {"arn": L.role_arn(acct, "tmp-benign-role")}}, t0),
        make_event("AttachRolePolicy", adm, {"roleName": "tmp-benign-role", "policyArn": L.READONLY_POLICY_ARN},
                   None, t0 + 5),
        make_event("DetachRolePolicy", adm, {"roleName": "tmp-benign-role", "policyArn": L.READONLY_POLICY_ARN},
                   None, t0 + 10),
        make_event("DeleteRole", adm, {"roleName": "tmp-benign-role"}, None, t0 + 15),
    ]
