#!/usr/bin/env python3
"""Deploy (or update) the whole iamwatch stack in us-east-1 with ONE command.

    python scripts/deploy.py --email you@example.com [--allowlist terraform-role,ci-bot]

What it does:
  1. builds build/engine.zip  (the iamwatch package + lambda_src/handler.py)
  2. creates a private S3 bucket for the zip (once) and uploads it
  3. creates/updates the CloudFormation stack infra/template.yaml
  4. prints the stack outputs and writes them to build/outputs.json
"""
import argparse
import hashlib
import json
import os
import sys
import zipfile

import boto3
from botocore.exceptions import ClientError, WaiterError

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
REGION = "us-east-1"        # IAM is a global service whose CloudTrail events appear in us-east-1


def build_zip():
    out_dir = os.path.join(ROOT, "build")
    os.makedirs(out_dir, exist_ok=True)
    path = os.path.join(out_dir, "engine.zip")
    pkg = os.path.join(ROOT, "src", "iamwatch")
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as z:
        for base, _dirs, files in os.walk(pkg):
            if "__pycache__" in base:
                continue
            for f in sorted(files):
                if f.endswith(".py"):
                    full = os.path.join(base, f)
                    z.write(full, os.path.join("iamwatch", os.path.relpath(full, pkg)))
        z.write(os.path.join(ROOT, "lambda_src", "handler.py"), "handler.py")
    digest = hashlib.sha256(open(path, "rb").read()).hexdigest()[:12]
    return path, "engine-%s.zip" % digest


def ensure_bucket(s3, name):
    try:
        s3.head_bucket(Bucket=name)
        return
    except ClientError as e:
        if e.response["Error"]["Code"] not in ("404", "NoSuchBucket", "NotFound"):
            raise
    s3.create_bucket(Bucket=name)       # us-east-1 needs no LocationConstraint
    s3.put_public_access_block(Bucket=name, PublicAccessBlockConfiguration={
        "BlockPublicAcls": True, "IgnorePublicAcls": True, "BlockPublicPolicy": True, "RestrictPublicBuckets": True})
    s3.put_bucket_encryption(Bucket=name, ServerSideEncryptionConfiguration={
        "Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}]})


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--email", required=True, help="address that receives ACTIVE alerts")
    ap.add_argument("--stack-name", default="iamwatch")
    ap.add_argument("--allowlist", default="", help="comma-separated principals that never alert")
    ap.add_argument("--max-hops", default="5")
    ap.add_argument("--window-seconds", default="3600")
    ap.add_argument("--linked-window-seconds", default="43200",
                    help="longer window for steps that use a credential issued by an earlier step (default 12 h)")
    ap.add_argument("--gapfill-minutes", default="60", help="look-back of the 5-minute gap-fill job")
    ap.add_argument("--notify-watch", default="false", choices=["true", "false"])
    ap.add_argument("--cooldown", default="3600", help="seconds to suppress repeated identical alerts "
                    "(use 1 while running repeated experiments)")
    args = ap.parse_args()
    import re
    if (not re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", args.email) or "your-real" in args.email.lower()
            or args.email.upper().startswith("YOUR_")):
        sys.exit("--email must be your REAL e-mail address (like name@gmail.com), not a placeholder.")

    session = boto3.session.Session(region_name=REGION)
    sts, s3, cfn = session.client("sts"), session.client("s3"), session.client("cloudformation")
    account = sts.get_caller_identity()["Account"]
    print("account %s, region %s" % (account, REGION))

    zip_path, key = build_zip()
    bucket = "iamwatch-artifacts-%s-%s" % (account, REGION)
    ensure_bucket(s3, bucket)
    s3.upload_file(zip_path, bucket, key)
    print("uploaded s3://%s/%s" % (bucket, key))

    with open(os.path.join(ROOT, "infra", "template.yaml")) as f:
        body = f.read()
    params = [
        ("CodeBucket", bucket), ("CodeKey", key), ("AlertEmail", args.email), ("Allowlist", args.allowlist),
        ("MaxHops", args.max_hops), ("WindowSeconds", args.window_seconds), ("NotifyWatch", args.notify_watch),
        ("CooldownSeconds", args.cooldown), ("LinkedWindowSeconds", args.linked_window_seconds),
        ("GapfillMinutes", args.gapfill_minutes),
    ]
    cfn_params = [{"ParameterKey": k, "ParameterValue": v} for k, v in params]
    exists = True
    try:
        cfn.describe_stacks(StackName=args.stack_name)
    except ClientError:
        exists = False
    try:
        if exists:
            cfn.update_stack(StackName=args.stack_name, TemplateBody=body, Parameters=cfn_params,
                             Capabilities=["CAPABILITY_IAM"])
            waiter = cfn.get_waiter("stack_update_complete")
            print("updating stack ... (about 2-3 minutes)")
        else:
            cfn.create_stack(StackName=args.stack_name, TemplateBody=body, Parameters=cfn_params,
                             Capabilities=["CAPABILITY_IAM"], OnFailure="ROLLBACK")
            waiter = cfn.get_waiter("stack_create_complete")
            print("creating stack ... (about 2-3 minutes)")
        waiter.wait(StackName=args.stack_name, WaiterConfig={"Delay": 5, "MaxAttempts": 120})
    except ClientError as e:
        if "No updates are to be performed" in str(e):
            print("stack already up to date")
        else:
            raise
    except WaiterError:
        print("\nDEPLOYMENT FAILED. Recent stack events:")
        for ev in cfn.describe_stack_events(StackName=args.stack_name)["StackEvents"][:12]:
            if "FAILED" in ev["ResourceStatus"]:
                print(" -", ev["LogicalResourceId"], ev["ResourceStatus"], ev.get("ResourceStatusReason", ""))
        sys.exit(1)

    outs = {o["OutputKey"]: o["OutputValue"] for o in
            cfn.describe_stacks(StackName=args.stack_name)["Stacks"][0].get("Outputs", [])}
    with open(os.path.join(ROOT, "build", "outputs.json"), "w") as f:
        json.dump(outs, f, indent=2)
    print("\nDeployed. Outputs:")
    for k, v in outs.items():
        print("  %-22s %s" % (k, v))
    print("\nNEXT: open the e-mail from AWS Notifications and click 'Confirm subscription'.")


if __name__ == "__main__":
    main()
