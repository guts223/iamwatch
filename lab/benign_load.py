#!/usr/bin/env python3
"""Generate REAL benign IAM/STS activity in the lab account for the false-alert experiment.

    python lab/benign_load.py --minutes 60            # about 1 operation every 8-12 s
    python lab/benign_load.py --ops 40 --pause 2      # short smoke test

Operations (random mix) - none of them completes an escalation path:
  role-cycle    admin creates a throw-away role, attaches ReadOnlyAccess, detaches, deletes
  dev-readonly  dev-user assumes the read-only role
  lambda-deploy ci-deployer creates (and the admin deletes) a Lambda function with the read-only app role
  helpdesk-key  helpdesk2 creates an access key for normal-user, admin deletes it
  assume-stage  chain-user assumes stage-role (the first hop of attack x1, but no second hop)
  user-cycle    admin creates a user, adds an inline read-only policy, deletes both
Every operation is written to results/benign_ops.csv with its time, so experiments/benign_eval.py can
count the alerts raised while this was running.  Uses your admin credentials plus lab/lab_credentials.json.
"""
import argparse
import csv
import io
import json
import os
import random
import sys
import time
import zipfile

import boto3
from botocore.exceptions import ClientError

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "src"))
sys.path.insert(0, os.path.join(ROOT, "lab"))
from iamwatch import labspec as L  # noqa: E402
import attacks as A  # noqa: E402

REGION = "us-east-1"


def quiet(fn, *a, **kw):
    try:
        return fn(*a, **kw)
    except ClientError:
        return None


def op_role_cycle(acct, i):
    iam = boto3.client("iam", region_name=REGION)
    nm = "benign-tmp-%d" % i
    quiet(iam.create_role, RoleName=nm, AssumeRolePolicyDocument=json.dumps(L.trust_service("ec2.amazonaws.com")))
    quiet(iam.attach_role_policy, RoleName=nm, PolicyArn=L.READONLY_POLICY_ARN)
    time.sleep(1)
    quiet(iam.detach_role_policy, RoleName=nm, PolicyArn=L.READONLY_POLICY_ARN)
    quiet(iam.delete_role, RoleName=nm)


def op_dev_readonly(acct, i):
    A.retry(lambda: A.user_session("dev-user").client("sts").assume_role(
        RoleArn=L.role_arn(acct, "readonly-role"), RoleSessionName="dev-daily-%d" % i))


def op_lambda_deploy(acct, i):
    lam = A.user_session("ci-deployer").client("lambda")
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("index.py", "def handler(e, c):\n    return 'ok'\n")
    nm = "benign-fn-%d" % i
    A.retry(lambda: lam.create_function(FunctionName=nm, Runtime="python3.12", Role=L.role_arn(acct, "app-lambda-role"),
                                        Handler="index.handler", Code={"ZipFile": buf.getvalue()}))
    quiet(boto3.client("lambda", region_name=REGION).delete_function, FunctionName=nm)


def op_helpdesk_key(acct, i):
    iam = A.user_session("helpdesk2").client("iam")
    k = A.retry(lambda: iam.create_access_key(UserName="normal-user"))["AccessKey"]
    quiet(boto3.client("iam", region_name=REGION).delete_access_key, UserName="normal-user", AccessKeyId=k["AccessKeyId"])


def op_assume_stage(acct, i):
    A.retry(lambda: A.user_session("chain-user").client("sts").assume_role(
        RoleArn=L.role_arn(acct, "stage-role"), RoleSessionName="routine-%d" % i))


def op_user_cycle(acct, i):
    iam = boto3.client("iam", region_name=REGION)
    nm = "benign-user-%d" % i
    quiet(iam.create_user, UserName=nm)
    quiet(iam.put_user_policy, UserName=nm, PolicyName="ro", PolicyDocument=json.dumps(L.READONLY_DOC))
    time.sleep(1)
    quiet(iam.delete_user_policy, UserName=nm, PolicyName="ro")
    quiet(iam.delete_user, UserName=nm)


OPS = {"role-cycle": op_role_cycle, "dev-readonly": op_dev_readonly, "lambda-deploy": op_lambda_deploy,
       "helpdesk-key": op_helpdesk_key, "assume-stage": op_assume_stage, "user-cycle": op_user_cycle}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--minutes", type=float, default=0, help="run for this long")
    ap.add_argument("--ops", type=int, default=0, help="or run exactly this many operations")
    ap.add_argument("--pause", type=float, default=10, help="mean seconds between operations")
    ap.add_argument("--seed", type=int, default=7)
    ap.add_argument("--out", default=os.path.join(ROOT, "results", "benign_ops.csv"))
    args = ap.parse_args()
    if not args.minutes and not args.ops:
        sys.exit("give --minutes or --ops")
    rng = random.Random(args.seed)
    acct = A.account()
    os.makedirs(os.path.dirname(args.out), exist_ok=True)
    new = not os.path.exists(args.out)
    t_end = time.time() + args.minutes * 60
    n = 0
    with open(args.out, "a", newline="") as fh:
        w = csv.writer(fh)
        if new:
            w.writerow(["op", "start", "end", "ok"])
        while (args.ops and n < args.ops) or (args.minutes and time.time() < t_end):
            name = rng.choice(sorted(OPS))
            t0 = time.time()
            ok = 1
            try:
                OPS[name](acct, int(t0 * 1000) % 10 ** 9)
            except Exception as e:                                  # noqa: BLE001  (a failed op is just logged)
                ok = 0
                print("   op failed:", name, e)
            w.writerow([name, "%.3f" % t0, "%.3f" % time.time(), ok])
            fh.flush()
            n += 1
            if n % 10 == 0:
                print("%d operations done" % n)
            time.sleep(max(0.5, rng.gauss(args.pause, args.pause / 4)))
    print("benign load finished: %d operations -> %s" % (n, args.out))


if __name__ == "__main__":
    main()
