# Design notes (use these as the skeleton of the paper's Design / Threat Model sections)

## Problem
IAM attackers usually do not break through a perimeter: they steal a low-privilege credential and chain legitimate IAM
features until they reach administrator access. Each step is an allowed API call. Batch posture scanners rebuild the whole
"who can become whom" graph on a schedule; single-event rules cannot see chains and do not know which principals are powerful.

## Contributions the code supports (claim only what your own measurements back up)
1. A typed IAM escalation graph kept up to date **from CloudTrail events** instead of rebuilt from API downloads: one idempotent
   handler per IAM event, a principal-level impact set, and an exact k-bounded incremental hops-to-ADMIN table.
2. A **telemetry dictionary** (`evidence.hop_signature`) that maps each graph edge to the log event(s) that show it being used,
   including `iam:PassRole`, which is a permission and never appears in CloudTrail by itself.
3. **Session-chain evidence**: AssumeRole / CreateAccessKey responses carry the new access-key id; later events with that key are
   linked back to the root identity, so a path can be matched to one actor's ordered, time-bounded sequence of calls.
4. A reproducible **benchmark**: lab account, five real attack scenarios, a simulation with nine families, baselines, a benign workload.

## Model
* Nodes: users, roles, groups, and a virtual sink ADMIN. Edge `A -> B` (label = technique): "A can obtain B's privileges".
* SELF edges (A -> ADMIN) depend only on A's effective permissions; PAIR edges (A -> B) on A's permissions and B's own attributes
  (trust policy, ARN, instance profiles). This locality is what makes impact sets small and the incremental update testable.
* Admin-equivalence = full access to five canary actions across IAM/EC2/S3/Lambda/DynamoDB (so PowerUserAccess, which uses
  NotAction to exclude IAM, is not treated as administrator).
* Evaluation is over-approximating: conditions are not evaluated (an allow with a condition gives a "conditional" edge, a deny
  with a condition is ignored).

## Classification
risk (path to ADMIN within k hops) x evidence (how much of the path was executed, in order, inside a time window, in one session chain):
posture finding / WATCH / ACTIVE. An allowlist suppresses known automation. Alerts are de-duplicated per (path, level) with a cooldown.

## Threat model
* Attacker: holds a stolen low-privilege credential (long-term key or temporary session) and can call IAM/STS and the services
  used for PassRole; wants administrator access.
* Trusted: CloudTrail records and their delivery to EventBridge; the detector's own AWS permissions and state bucket.
* Attacks on the detector itself: stopping logging or disabling/deleting the EventBridge rule is treated as an alert (EVASION).
* Out of scope: SCPs, resource policies other than role trust policies, cross-account chains, data-plane events, credentials used
  from places that never touch IAM/STS, attackers who modify the detector's state bucket or Lambda.

## Known limitations (put these in the paper)
single account; identity + trust policies + permission boundaries only; ~10 techniques; synthetic scaling data; CloudTrail
delivery delay (minutes) bounds detection time for every approach; events can arrive late or out of order (idempotent handlers +
periodic reconciliation, not prevention); a slow attacker whose steps are further apart than the window is only seen as WATCH;
baseline rules were written by the authors (replace with a published rule set before claiming superiority).

## Evaluation plan (what each result supports)
| question | experiment | file |
|---|---|---|
| how much does event-driven beat batch scanning? | model staleness / fresh-misconfiguration awareness vs scan interval | `simulate.py` |
| does the graph add coverage over simple rules? | 4 uncovered families + published rule baseline (to add) | `simulate.py`, `baselines.py` |
| false alerts | benign DevOps workload | `simulate.py` |
| correct? | randomised incremental == rebuild; distance algorithm vs rebuild | `tests/` |
| scales? | graph layer to 100k nodes; engine layer 50-400 principals | `scaling_bench.py`, `engine_scaling.py` |
| real latency | CloudTrail delivery / queue / processing / end to end, 20 runs per scenario | `run_attacks.py` |
| cost | AWS bill + pricing page at your measured event rate | (manual) |
