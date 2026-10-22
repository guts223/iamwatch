#!/usr/bin/env python3
"""Delete everything deploy.py created (stack, state bucket contents, artifact bucket)."""
import argparse

import boto3
from botocore.exceptions import ClientError

REGION = "us-east-1"


def empty_bucket(s3, bucket):
    paginator = s3.get_paginator("list_object_versions")
    for page in paginator.paginate(Bucket=bucket):
        objs = [{"Key": o["Key"], "VersionId": o["VersionId"]}
                for o in page.get("Versions", []) + page.get("DeleteMarkers", [])]
        if objs:
            s3.delete_objects(Bucket=bucket, Delete={"Objects": objs})


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--stack-name", default="iamwatch")
    args = ap.parse_args()
    session = boto3.session.Session(region_name=REGION)
    cfn, s3 = session.client("cloudformation"), session.client("s3")
    account = session.client("sts").get_caller_identity()["Account"]
    try:
        outs = {o["OutputKey"]: o["OutputValue"] for o in
                cfn.describe_stacks(StackName=args.stack_name)["Stacks"][0].get("Outputs", [])}
        for key in ("StateBucketName", "TrailBucketName"):
            if outs.get(key):
                empty_bucket(s3, outs[key])
        cfn.delete_stack(StackName=args.stack_name)
        print("deleting stack ...")
        cfn.get_waiter("stack_delete_complete").wait(StackName=args.stack_name)
    except ClientError as e:
        print("stack not found / already deleted:", e.response["Error"]["Message"])
    artifacts = "iamwatch-artifacts-%s-%s" % (account, REGION)
    try:
        empty_bucket(s3, artifacts)
        s3.delete_bucket(Bucket=artifacts)
        print("deleted", artifacts)
    except ClientError:
        pass
    print("done. (Lab IAM users/roles are removed with: python lab/setup_lab.py --destroy)")


if __name__ == "__main__":
    main()
