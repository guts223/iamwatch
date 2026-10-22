#!/usr/bin/env python3
"""Engine-level scaling (policy-evaluation layer), on synthetic IAM accounts (no AWS needed).

For accounts with N principals this compares
    full rebuild   re-deriving every edge from the policies  (what a batch scanner repeats each scan,
                   and it must also re-download the IAM state through the API first)
    one event      Engine.process() on a single IAM change (affected principals only)

    python experiments/engine_scaling.py --sizes 50 100 200 400 --events 40

State in the paper: synthetic accounts, edge-derivation cost only (API download time not included),
single process on one machine.
"""
import argparse
import csv
import json
import os
import random
import statistics
import sys
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "src"))
from iamwatch import labspec as L  # noqa: E402
from iamwatch import synth  # noqa: E402
from iamwatch.engine import Engine  # noqa: E402

ACCT = "123456789012"


def synthetic_details(n, rng):
    users = ["u%d" % i for i in range(n // 2)]
    roles = ["r%d" % i for i in range(n - n // 2)]
    groups = ["g%d" % i for i in range(max(2, n // 20))]
    pols = ["arn:aws:iam::%s:policy/p%d" % (ACCT, i) for i in range(max(2, n // 10))]
    low = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": ["s3:GetObject", "s3:ListBucket"],
                                                    "Resource": "*"}]}
    U, R, G, PL = [], [], [], []
    for g in groups:
        G.append({"GroupName": g, "Arn": "arn:aws:iam::%s:group/%s" % (ACCT, g),
                  "AttachedManagedPolicies": [{"PolicyArn": rng.choice(pols)}], "GroupPolicyList": []})
    for u in users:
        assume = rng.sample(roles, min(2, len(roles)))
        doc = {"Version": "2012-10-17", "Statement": [
            {"Effect": "Allow", "Action": "sts:AssumeRole", "Resource": [L.role_arn(ACCT, r) for r in assume]},
            {"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"}]}
        U.append({"UserName": u, "Arn": L.user_arn(ACCT, u),
                  "GroupList": rng.sample(groups, 1) if rng.random() < 0.3 else [],
                  "AttachedManagedPolicies": [], "UserPolicyList": [{"PolicyName": "p", "PolicyDocument": doc}]})
    for i, r in enumerate(roles):
        trusted = rng.sample(users, min(2, len(users)))
        trust = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Principal": {"AWS": [
            L.user_arn(ACCT, t) for t in trusted]}, "Action": "sts:AssumeRole"}]}
        inline = {"p": low}
        if rng.random() < 0.04:
            inline = {"p": {"Version": "2012-10-17", "Statement": [{"Effect": "Allow",
                      "Action": "iam:AttachRolePolicy", "Resource": L.role_arn(ACCT, rng.choice(roles))}]}}
        managed = [L.ADMIN_POLICY_ARN] if rng.random() < 0.01 else []
        R.append({"RoleName": r, "Arn": L.role_arn(ACCT, r), "AssumeRolePolicyDocument": trust,
                  "AttachedManagedPolicies": [{"PolicyArn": a} for a in managed],
                  "RolePolicyList": [{"PolicyName": k, "PolicyDocument": v} for k, v in inline.items()],
                  "InstanceProfileList": []})
    for a in pols:
        PL.append({"PolicyName": a.rsplit("/", 1)[-1], "Arn": a, "AttachmentCount": 1, "DefaultVersionId": "v1",
                   "PolicyVersionList": [{"VersionId": "v1", "Document": low, "IsDefaultVersion": True}]})
    PL.append({"PolicyName": "AdministratorAccess", "Arn": L.ADMIN_POLICY_ARN, "AttachmentCount": 1,
               "DefaultVersionId": "v1", "PolicyVersionList": [{"VersionId": "v1", "Document": L.ADMIN_DOC,
                                                                "IsDefaultVersion": True}]})
    return {"UserDetailList": U, "RoleDetailList": R, "GroupDetailList": G, "Policies": PL}, users, roles, groups, pols


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--sizes", type=int, nargs="+", default=[50, 100, 200, 400])
    ap.add_argument("--events", type=int, default=40)
    ap.add_argument("--seed", type=int, default=3)
    ap.add_argument("--out", default=os.path.join(ROOT, "results", "engine_scaling.csv"))
    args = ap.parse_args()
    os.makedirs(os.path.dirname(args.out), exist_ok=True)
    rows = []
    for n in args.sizes:
        rng = random.Random(args.seed)
        details, users, roles, groups, pols = synthetic_details(n, rng)
        t = time.perf_counter()
        eng = Engine.from_snapshot(details)
        full_ms = (time.perf_counter() - t) * 1000
        actor = synth.user_actor(ACCT, "u0", "AKIAU0")
        clock = [2_000_000.0]

        def ev(name, params, resp=None):
            clock[0] += 5
            return synth.make_event(name, actor, params, resp, clock[0])

        makers = {
            "attach_policy_to_role": lambda: ev("AttachRolePolicy", {"roleName": rng.choice(roles),
                                                                      "policyArn": rng.choice(pols)}),
            "update_trust": lambda: ev("UpdateAssumeRolePolicy", {"roleName": rng.choice(roles), "policyDocument": json.dumps(
                {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Principal": {"AWS": L.user_arn(ACCT, rng.choice(users))},
                                                         "Action": "sts:AssumeRole"}]})}),
            "add_user_to_group": lambda: ev("AddUserToGroup", {"userName": rng.choice(users), "groupName": rng.choice(groups)}),
            "policy_version_fanout": lambda: ev("CreatePolicyVersion", {"policyArn": pols[0], "policyDocument": json.dumps(
                {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"}]}),
                "setAsDefault": True}, {"policyVersion": {"versionId": "v%d" % (rng.randint(2, 999))}}),
            "create_role": lambda: ev("CreateRole", {"roleName": "new%d" % rng.randint(0, 10 ** 9),
                                                      "assumeRolePolicyDocument": json.dumps(L.trust_root(ACCT))}),
        }
        for name, make in makers.items():
            times, recomputed = [], []
            for _ in range(args.events):
                e = make()
                if name == "create_role":
                    e["responseElements"] = {"role": {"arn": L.role_arn(ACCT, e["requestParameters"]["roleName"])}}
                t = time.perf_counter()
                eng.process(e)
                times.append((time.perf_counter() - t) * 1000)
                recomputed.append(eng.last_stats.get("recomputed_nodes", 0))
            rows.append({"principals": n, "event": name, "events": len(times),
                         "event_ms_median": round(statistics.median(times), 3),
                         "event_ms_p95": round(sorted(times)[int(0.95 * (len(times) - 1))], 3),
                         "recomputed_nodes_median": int(statistics.median(recomputed)),
                         "full_rebuild_ms": round(full_ms, 1),
                         "speedup_median": round(full_ms / max(statistics.median(times), 1e-6), 1)})
            r = rows[-1]
            print("N=%-5d %-24s event median %8.3f ms (p95 %8.3f) recomputed %-4d | full rebuild %9.1f ms | x%.0f" % (
                n, name, r["event_ms_median"], r["event_ms_p95"], r["recomputed_nodes_median"], full_ms, r["speedup_median"]))
        ok, diffs = eng.check_equivalence()
        print("N=%-5d incremental graph == rebuilt-from-scratch graph after %d events: %s" % (
            n, len(makers) * args.events, ok))
        assert ok, diffs
    with open(args.out, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        w.writeheader()
        w.writerows(rows)
    print("wrote", args.out)


if __name__ == "__main__":
    main()
