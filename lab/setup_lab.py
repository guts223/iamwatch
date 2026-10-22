#!/usr/bin/env python3
"""Create (or destroy) the deliberately vulnerable lab identities in YOUR lab AWS account.

    python lab/setup_lab.py            # create users, roles, policy, access keys
    python lab/setup_lab.py --destroy  # remove everything again

SAFETY: this creates identities that can escalate to administrator on purpose.
Only run it in a dedicated lab account that holds no real data, and destroy it when finished.
Access keys of the lab users are written to lab/lab_credentials.json (git-ignored).
"""
import argparse
import json
import os
import sys
import time

import boto3
from botocore.exceptions import ClientError

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "src"))
from iamwatch import labspec as L  # noqa: E402

CRED_FILE = os.path.join(ROOT, "lab", "lab_credentials.json")
KEY_USERS = L.KEY_USERS_ALL


def quiet(fn, *a, **kw):
    try:
        return fn(*a, **kw)
    except ClientError as e:
        if e.response["Error"]["Code"] in ("EntityAlreadyExists", "NoSuchEntity", "ResourceNotFoundException"):
            return None
        raise


def retry_iam(fn, tries=20, delay=4, **kw):
    """IAM is eventually consistent: a role created a moment ago may not be visible yet when another role's trust
    policy names it ("Invalid principal in policy").  Retry that error; an existing entity is not an error."""
    for i in range(tries):
        try:
            return fn(**kw)
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code == "EntityAlreadyExists":
                return None
            if code in ("MalformedPolicyDocument", "MalformedPolicyDocumentException") and i < tries - 1:
                time.sleep(delay)
                continue
            raise


def create_rollback_policy(iam, spec):
    """v1 = admin document, then v2 = harmless document set as default (scenario x4 flips back to v1)."""
    rb = spec["rollback_policy"]
    if quiet(iam.get_policy, PolicyArn=rb["arn"]) is None:
        iam.create_policy(PolicyName=L.ROLLBACK_POLICY_NAME, PolicyDocument=json.dumps(L.ADMIN_DOC))
        iam.create_policy_version(PolicyArn=rb["arn"], PolicyDocument=json.dumps(L.LOW_DOC), SetAsDefault=True)
    else:
        versions = {v["VersionId"]: v for v in iam.list_policy_versions(PolicyArn=rb["arn"])["Versions"]}
        if "v2" in versions:
            iam.set_default_policy_version(PolicyArn=rb["arn"], VersionId="v2")


def create(iam, acct):
    spec = L.full_spec(acct)
    ci = spec["ci_policy"]
    quiet(iam.create_policy, PolicyName=L.CI_POLICY_NAME, PolicyDocument=json.dumps(ci["doc"]))
    create_rollback_policy(iam, spec)
    for name, g in spec["groups"].items():
        quiet(iam.create_group, GroupName=name)
        for arn in g["managed"]:
            iam.attach_group_policy(GroupName=name, PolicyArn=arn)
        print("group ", name)
    for name, u in spec["users"].items():
        quiet(iam.create_user, UserName=name)
        for pn, doc in u["inline"].items():
            iam.put_user_policy(UserName=name, PolicyName=pn, PolicyDocument=json.dumps(doc))
        for arn in u["managed"]:
            iam.attach_user_policy(UserName=name, PolicyArn=arn)
        print("user  ", name)
    for name, r in spec["roles"].items():
        retry_iam(iam.create_role, RoleName=name, AssumeRolePolicyDocument=json.dumps(r["trust"]))
        retry_iam(iam.update_assume_role_policy, RoleName=name, PolicyDocument=json.dumps(r["trust"]))
        for pn, doc in r["inline"].items():
            iam.put_role_policy(RoleName=name, PolicyName=pn, PolicyDocument=json.dumps(doc))
        for arn in r["managed"]:
            iam.attach_role_policy(RoleName=name, PolicyArn=arn)
        print("role  ", name)
    creds = {}
    if os.path.exists(CRED_FILE):
        creds = json.load(open(CRED_FILE))
    for name in KEY_USERS:
        have = iam.list_access_keys(UserName=name)["AccessKeyMetadata"]
        if name in creds and any(k["AccessKeyId"] == creds[name]["AccessKeyId"] for k in have):
            continue
        for k in have:
            iam.delete_access_key(UserName=name, AccessKeyId=k["AccessKeyId"])
        k = iam.create_access_key(UserName=name)["AccessKey"]
        creds[name] = {"AccessKeyId": k["AccessKeyId"], "SecretAccessKey": k["SecretAccessKey"]}
        print("key   ", name, k["AccessKeyId"])
    with open(CRED_FILE, "w") as f:
        json.dump(creds, f, indent=2)
    os.chmod(CRED_FILE, 0o600)
    print("\nwaiting 15 s for IAM to propagate ...")
    time.sleep(15)
    print("lab ready. credentials saved to", CRED_FILE)


def destroy(iam, acct):
    spec = L.full_spec(acct)
    for name in spec["users"]:
        for g in (quiet(iam.list_groups_for_user, UserName=name) or {}).get("Groups", []):
            iam.remove_user_from_group(GroupName=g["GroupName"], UserName=name)
        for k in (quiet(iam.list_access_keys, UserName=name) or {}).get("AccessKeyMetadata", []):
            iam.delete_access_key(UserName=name, AccessKeyId=k["AccessKeyId"])
        for pn in (quiet(iam.list_user_policies, UserName=name) or {}).get("PolicyNames", []):
            iam.delete_user_policy(UserName=name, PolicyName=pn)
        for p in (quiet(iam.list_attached_user_policies, UserName=name) or {}).get("AttachedPolicies", []):
            iam.detach_user_policy(UserName=name, PolicyArn=p["PolicyArn"])
        quiet(iam.delete_user, UserName=name)
        print("deleted user", name)
    for name in spec["roles"]:
        for pn in (quiet(iam.list_role_policies, RoleName=name) or {}).get("PolicyNames", []):
            iam.delete_role_policy(RoleName=name, PolicyName=pn)
        for p in (quiet(iam.list_attached_role_policies, RoleName=name) or {}).get("AttachedPolicies", []):
            iam.detach_role_policy(RoleName=name, PolicyArn=p["PolicyArn"])
        quiet(iam.delete_role, RoleName=name)
        print("deleted role", name)
    for name, g in spec["groups"].items():
        for p in (quiet(iam.list_attached_group_policies, GroupName=name) or {}).get("AttachedPolicies", []):
            iam.detach_group_policy(GroupName=name, PolicyArn=p["PolicyArn"])
        quiet(iam.delete_group, GroupName=name)
        print("deleted group", name)
    for arn in (L.ci_policy_arn(acct), L.rollback_policy_arn(acct)):
        pol = quiet(iam.list_policy_versions, PolicyArn=arn)
        if pol:
            for v in pol["Versions"]:
                if not v["IsDefaultVersion"]:
                    iam.delete_policy_version(PolicyArn=arn, VersionId=v["VersionId"])
            quiet(iam.delete_policy, PolicyArn=arn)
    lam = boto3.client("lambda", region_name="us-east-1")
    quiet(lam.delete_function, FunctionName="iamwatch-lab-fn")
    if os.path.exists(CRED_FILE):
        os.remove(CRED_FILE)
    print("lab destroyed")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--destroy", action="store_true")
    args = ap.parse_args()
    session = boto3.session.Session(region_name="us-east-1")
    acct = session.client("sts").get_caller_identity()["Account"]
    print("lab account:", acct)
    iam = session.client("iam")
    (destroy if args.destroy else create)(iam, acct)


if __name__ == "__main__":
    main()