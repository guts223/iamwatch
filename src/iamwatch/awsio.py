"""Thin boto3 helpers shared by the Lambda handler and the command-line scripts."""


def get_authorization_details(iam):
    """Merge all pages of iam:GetAccountAuthorizationDetails into one dict."""
    merged = {"UserDetailList": [], "GroupDetailList": [], "RoleDetailList": [], "Policies": []}
    paginator = iam.get_paginator("get_account_authorization_details")
    for page in paginator.paginate():
        for key in merged:
            merged[key].extend(page.get(key, []))
    return merged


def make_policy_fetcher(iam):
    """Return fetcher(arn) -> {"versions": {vid: doc}, "default": vid} or None on failure."""
    def fetch(arn):
        try:
            pol = iam.get_policy(PolicyArn=arn)["Policy"]
            versions = {}
            for v in iam.list_policy_versions(PolicyArn=arn)["Versions"]:
                doc = iam.get_policy_version(PolicyArn=arn, VersionId=v["VersionId"])["PolicyVersion"]["Document"]
                versions[v["VersionId"]] = doc
            return {"versions": versions, "default": pol["DefaultVersionId"]}
        except Exception:        # noqa: BLE001 - missing policy / no permission: treat as unknown
            return None
    return fetch
