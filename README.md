# iamwatch

Event-driven detection of multi-step **AWS IAM privilege escalation**.

It keeps a live map ("graph") of *who can become whom* in your AWS account, updates that map the moment someone
changes an IAM rule, and checks the audit log (CloudTrail) to see whether anyone actually *walked* a dangerous route.

| situation | result |
|---|---|
| a route to administrator exists, nobody used it | **posture finding** (`scripts/scan.py`, `reports/posture.json`) |
| part of the route was executed | **WATCH** alert (stored, not e-mailed by default) |
| the whole route was executed in order, inside the time window | **ACTIVE** alert (e-mail) |
| someone stops logging / deletes the EventBridge rule | **EVASION** alert (e-mail) |

> **v2 (new-account edition).** Follow `RUNBOOK.md` - it takes you from an empty AWS account to all results. New in v2:
> nine attack families on real AWS, a GuardDuty comparison, real benign load, a gap-fill job that recovers events EventBridge
> never delivered, and a 12 h "linked window" for slow credential chains. The engine, tests and offline experiments were run
> here (see the test count below); the real-AWS parts are exercised against a mocked AWS (moto) and the CloudFormation
> template, but the first real run of the four new attack families (X1-X4) is your smoke test in RUNBOOK section 4.

---------------------------------------------------------------------------------------------------

## 1. How the pieces connect

```
 you / attacker               AWS (region us-east-1 - IAM events always appear here)
 ──────────────      ┌──────────────────────────────────────────────────────────────────────────┐
  IAM / STS calls ──►│ CloudTrail (management events, always on)                                │
                     │      │                                                                   │
                     │      ▼                                                                   │
                     │ EventBridge rule  IamEventRule  (matches the 48 event names we use)     │
                     │      │  MessageGroupId = "iamwatch"                                      │
                     │      ▼                                                                   │
                     │ SQS FIFO queue ──(5 failures)──► dead-letter FIFO queue                  │
                     │      │  one batch at a time, in order                                    │
                     │      ▼                                                                   │
                     │ Lambda  <stack>-engine   (python3.12, handler.py + iamwatch package)     │
                     │   1. load engine state ◄──────────────► S3 bucket  state/engine.json     │
                     │   2. de-duplicate event ───────────────► DynamoDB  events table          │
                     │   3. update graph, match evidence                                        │
                     │   4. store alert ──────────────────────► DynamoDB  alerts table          │
                     │   5. notify ───────────────────────────► SNS topic ──► your e-mail       │
                     │   6. save state + reports/posture.json ► S3                              │
                     │                                                                          │
                     │ EventBridge schedule (every 6 h) ──► same Lambda, {"action":"reconcile"} │
                     │      full IAM re-download, rebuild, diff ► S3 reports/drift-*.json       │
                     └──────────────────────────────────────────────────────────────────────────┘
```

Everything above is created by **one command** (`scripts/deploy.py`) from `infra/template.yaml`.
Nothing is clicked in the console. The FIFO queue with a single message group is what guarantees events are processed one
batch at a time and in order (so no reserved-concurrency setting is needed, which new AWS accounts often cannot set).

## 2. What is in the folder

| path | what it is | where it runs |
|---|---|---|
| `src/iamwatch/` | the engine: policy evaluation, edge catalog, graph, evidence, classification | Lambda **and** your laptop |
| `lambda_src/handler.py` | Lambda entry point (SQS -> engine -> S3/DynamoDB/SNS) | Lambda |
| `infra/template.yaml` | CloudFormation: every AWS resource | AWS (deployed by `deploy.py`) |
| `scripts/deploy.py`, `teardown.py` | build zip, upload, create/update/delete the stack | laptop |
| `scripts/scan.py`, `snapshot.py` | posture scan / IAM download | laptop |
| `scripts/replay.py` | replay events through the engine offline (`--demo` needs no AWS) | laptop |
| `scripts/fetch_events.py`, `check_fields.py` | download real CloudTrail events and verify the fields the design relies on | laptop |
| `scripts/show_alerts.py` | print the alerts stored by the deployed stack | laptop |
| `scripts/export_tables.py` | save the events/alerts tables and reports to your laptop (do this before teardown) | laptop |
| `docs/EXPERIMENTS.md` | the full experiment runbook and which result goes into which part of the paper | - |
| `scripts/diagnose.py` | read-only health check of the whole chain (CloudTrail, trail, rule, queue, Lambda, tables) with a verdict | laptop |
| `lab/setup_lab.py` | create the deliberately vulnerable lab identities | laptop -> your **lab** account |
| `lab/attacks.py` | run / reset the nine attack scenarios (s1-s5, x1-x4) | laptop -> lab account |
| `lab/benign_load.py` | an hour of real, random benign IAM/STS activity (false-alert test) | laptop -> lab account |
| `scripts/guardduty.py` | enable / collect findings / disable Amazon GuardDuty (comparison baseline) | laptop -> lab account |
| `experiments/live_gapfill.py`, `benign_eval.py`, `analyze_live.py`, `analyze_robust.py` | gap-fill test, benign evaluation, tables and figures | laptop |
| `scripts/campaign.ps1`, `offline_all.ps1` | the whole campaign / all offline experiments in order | laptop |
| `experiments/` | `simulate.py`, `scaling_bench.py`, `engine_scaling.py` (offline), `run_attacks.py` (real AWS), `analyze.py` | laptop |
| `tests/` | the test-suite incl. randomised "incremental == rebuild" correctness tests | laptop |
| `results/` | example output of the **offline** experiments (re-generate your own) | - |

## 3. One-time setup (about 30 minutes)

1. **AWS account**: use a separate, empty account just for this project (new e-mail address). Turn on MFA for the root user,
   create a normal admin user for daily work (IAM Identity Center or an IAM user), never use root again. Set a $5 budget alert.
   Do all of the following with the admin user.
2. **Install**: Python 3.11+, Git, AWS CLI v2. Then:
   ```
   python -m venv .venv
   .venv\Scripts\activate          # Windows        (macOS/Linux: source .venv/bin/activate)
   pip install -r requirements-dev.txt
   aws configure                    # admin user's keys, default region us-east-1, output json
   aws sts get-caller-identity      # must print your account id
   ```
   (On some systems the command is `python3` / `py` instead of `python`.)
3. **Check everything works offline first** (no AWS calls):
   ```
   python -m pytest tests -q                # 239 passed (takes ~35 s)
   python scripts/replay.py --demo          # prints WATCH/ACTIVE alerts for the five attacks
   ```

## 4. Deploy to AWS

```
python scripts/deploy.py --email you@example.com
```
It builds `build/engine.zip`, creates a private artifact bucket, uploads the zip, creates the CloudFormation stack `iamwatch`
(about 3 minutes; it also creates a CloudTrail trail and its log bucket) and prints the outputs (also saved to `build/outputs.json`).

* **Open the e-mail "AWS Notification - Subscription Confirmation" and click *Confirm subscription*.** No confirmation = no alerts.
* Options: `--allowlist terraform-role,ci-bot` (principals that never alert), `--max-hops 5`, `--window-seconds 3600`,
  `--notify-watch true`, `--cooldown 3600` (use `--cooldown 60` while running repeated experiments).
* Re-running the same command updates the stack in place (e.g. after you change code).
* If creation fails, the script prints the failed resource and the reason. Fix it and run the command again.
* On the **free plan** some services can be restricted; if the stack fails with an access/plan error, upgrade the account to the
  paid plan (credits carry over) and keep the budget alert on.

The first Lambda run finds no saved state, so it downloads your IAM state once and builds the graph (bootstrap).
Posture report: `s3://<StateBucketName>/reports/posture.json`.

## 5. Create the lab and run your first attack

```
python lab/setup_lab.py                  # creates 6 users, 4 roles, 1 policy, access keys (saved in lab/lab_credentials.json)
python lab/attacks.py run s1             # dev-user assumes eks-worker-role, then attaches AdministratorAccess to it
```
Wait **5-10 minutes** (CloudTrail delivers events with a delay), then:
```
python scripts/show_alerts.py
```
Expected: a `WATCH` (first hop) and an `ACTIVE` alert `dev-user --AssumeRole--> eks-worker-role --AttachRolePolicy--> ADMIN`
with evidence 2/2 and an e-mail. Run the others with `python lab/attacks.py run s2` ... `s5` or `run all`, and undo everything with
`python lab/attacks.py reset`.

| scenario | technique | stolen identity |
|---|---|---|
| s1 | AssumeRole, then AttachRolePolicy on the assumed role | dev-user |
| s2 | CreatePolicyVersion (admin version set as default) | ci-user |
| s3 | UpdateAssumeRolePolicy, then AssumeRole of an admin role | ops-user |
| s4 | PassRole + Lambda CreateFunction with an admin role | deploy-user |
| s5 | CreateAccessKey for an admin user | helpdesk-user |

> **Safety**: the lab identities can escalate to administrator on purpose, and their keys sit in `lab/lab_credentials.json`
> (git-ignored). Use a dedicated account with no real data and destroy the lab when finished (section 9).

### Verify the design's assumptions against real CloudTrail (do this once, it matters)

```
python scripts/fetch_events.py --minutes 90      # saves data/events.json
python scripts/check_fields.py                   # every field the detector relies on: OK / MISSING
python scripts/replay.py --snapshot data/snapshot.json --events data/events.json   # after: python scripts/snapshot.py
```
Any `MISSING` means a field name differs in your account; fix the matching entry in `src/iamwatch/evidence.py -> hop_signature`
(and `events.py` if it is a state event), re-run the tests, and redeploy.

## 6. What I could NOT verify (check these on first deployment)

1. **CloudTrail -> EventBridge**: AWS documents that IAM/management events only reach EventBridge rules when a CloudTrail
   *trail* exists in the same region, and that a rule must be in state `ENABLED_WITH_ALL_CLOUDTRAIL_MANAGEMENT_EVENTS` to match
   them. The template now creates a trail (write-only management events, first copy free) and uses that rule state. The first
   version of this project had neither and no alert ever appeared - that was found on the first real run. If events still do not
   arrive, run `python scripts/diagnose.py`; it pinpoints the broken link.
   **Second finding from the same real run:** `AssumeRole` is a *read-only* management event, so the trail must record
   read **and** write events (`ReadWriteType: All`). With a write-only trail the engine never sees the role-switch step:
   s1 was attributed to the role instead of `dev-user`, and s3 stayed at WATCH.
2. **Event field names** (see `check_fields.py`): `responseElements.credentials.accessKeyId` on `AssumeRole`, event name
   `CreateFunction20150331` and `requestParameters.role`, `requestParameters.iamInstanceProfile` on `RunInstances`,
   `requestParameters.roleARN` on `CreateStack`.
3. **IAM propagation**: IAM is eventually consistent; the lab scripts retry, but a scenario can still fail once and succeed on retry.
4. **FIFO + Lambda**: standard SQS FIFO event-source behaviour; the handler returns partial-batch failures in order. Untested live.
5. **Free-plan restrictions** on some services (see section 4).
6. **Delivery order**: EventBridge delivers events at-least-once and possibly out of order. The handler is idempotent (duplicate
   `eventID` ignored; state handlers can be re-applied), but a *late* event arriving after a *newer* one can briefly make the
   graph stale. The 6-hourly reconcile job detects and reports this drift; it is a documented limitation.

## 7. Run the experiments (for the paper)

All offline experiments are deterministic (seeded) and need no AWS:
```
python experiments/simulate.py --reps 30          # live vs batch scan (5-60 min) vs stateless rules, 9 attack families
python experiments/scaling_bench.py --sizes 1000 10000 50000 100000 --ops 100
python experiments/engine_scaling.py --sizes 50 100 200 400 --events 30
python experiments/analyze.py                     # -> results/summary.md + results/fig_*.png
```
The real-AWS experiment (needs the deployed stack, redeploy with `--cooldown 60` first):
```
python experiments/run_attacks.py --scenarios s1 s2 s3 s4 s5 --reps 20
python experiments/analyze.py
```
Each run takes 3-10 minutes (CloudTrail delay), so 5 scenarios x 20 runs takes many hours - start it in the evening.
It records CloudTrail-to-queue delivery delay, queue delay, processing time, end-to-end time, and whether the stateless-rule baseline
would also have fired. It also times a full batch scan (`results/batch_scan.json`).

What the offline experiments measure (and do not):

| experiment | measures | does NOT measure |
|---|---|---|
| `simulate.py` coverage / false alerts | detection of 9 attack families, noise accounts, benign workload | real wall-clock latency; real accounts |
| `simulate.py` staleness / awareness | how long a **batch-style** scanner leaves the model stale vs the live engine | CloudTrail delivery delay (shared by all approaches) |
| `scaling_bench.py` | cost of repairing the hop-distance table after one change, up to 100k synthetic nodes | policy evaluation; real IAM structure |
| `engine_scaling.py` | one IAM event vs re-deriving all edges, synthetic accounts of 50-400 principals | API download time of a batch scan (would favour the engine further) |

### Honest findings already visible in the offline results

* **The graph's distance table is cheap to rebuild** (a k-bounded search from ADMIN: 26 ms at 100k synthetic nodes, 1 ms at
  10k). The exact incremental update is much cheaper still: at 100k nodes about 0.02-0.06 ms per change, i.e. roughly 400-1,400x
  cheaper than the rebuild, and 17-5,000x cheaper (depending on the kind of change) than the coarse "recompute the whole k-hop
  neighbourhood" repair (`update_dist_ball`). But at small sizes the gap to a rebuild is small (3-12x at 1,000 nodes), and the
  **real saving of the event-driven design is elsewhere**: not re-downloading IAM and not re-deriving every edge from policies,
  which is quadratic in the number of principals (`engine_scaling.py`: one event is 10-170x cheaper than a full rebuild at 50-200
  principals and 32-123x at 400; laptop timings are noisy, so repeat them on your machine). Report it that way, with the
  synthetic-data caveat.
* **The "stateless rules 0%" result on the uncovered families is partly by construction**: the four uncovered attack families
  (x1-x4) and the five rules were both chosen by the author. A reviewer will say the baseline is a strawman. Before you publish,
  replace `StatelessRules` by (or add) a published rule set, e.g. the open-source Sigma AWS CloudTrail rules and the vendor
  detections you can find (Splunk, Elastic, etc.), and say how you mapped them. Also be explicit that on the *covered* families
  simple rules detect everything - the engine's advantage there is attribution and fewer false alerts, not coverage.
* **Live "staleness = 0" is by construction** in the simulation (event-time clock). Real end-to-end latency comes only from
  `run_attacks.py` and will be dominated by CloudTrail's delivery delay.

## 8. How the detection works (short)

* `policy.py` - simplified IAM policy evaluator (wildcards, NotAction/NotResource, explicit deny, boundaries; conditions are
  *not* evaluated: an allow with a condition becomes a "conditional" edge).
* `rules.py` - the technique catalog. SELF edges (principal -> ADMIN): HasAdmin, Attach/Put{User,Role,Group}Policy,
  CreatePolicyVersion, SetDefaultPolicyVersion. PAIR edges: AssumeRole (identity + trust policy), UpdateAssumeRolePolicy,
  CreateAccessKey, UpdateLoginProfile, AddUserToGroup, PassRole:lambda/ec2/cloudformation.
* `events.py` - one idempotent handler per IAM event; each returns which principals' edges must be recomputed.
* `graph.py` - multigraph + k-bounded hops-to-ADMIN table maintained by an exact incremental algorithm
  (dynamic single-sink shortest paths, Ramalingam-Reps style); `update_dist_ball` is the coarse version kept for the benchmark.
* `evidence.py` - ledger of recent events, **session chains** (AssumeRole / CreateAccessKey responses carry the new access key id,
  later events with that key belong to the same chain), and the **telemetry dictionary** `hop_signature` mapping every edge type to
  the log event(s) that show it being used - including PassRole, which is never logged itself.
* `engine.py` - ties it together. Each event is matched against the graph **before and after** its own state change.
* `baselines.py` - stateless rules and a batch-style "stale model" operation of the same engine (for the comparison).

Correctness is checked by property tests: after any random sequence of 60 events on random accounts (400 random accounts, checked
after every event) the incremental graph equals one rebuilt from scratch, and the distance algorithm matches a full rebuild on
3,000 random graphs with batched updates.

## 9. Clean up (stop all costs)

```
python lab/setup_lab.py --destroy      # remove the vulnerable lab identities and their keys
python scripts/teardown.py             # delete the stack, the state bucket contents and the artifact bucket
```
Teardown deletes the EventBridge rules and may e-mail an EVASION alert about it; that is expected.
Lab-scale traffic should stay far inside AWS's free allowances, but keep the budget alert on and check the Billing page.

## 10. Troubleshooting

| symptom | likely cause / fix |
|---|---|
| no alert after 15 minutes | **run `python scripts/diagnose.py` first** - it prints a VERDICT. Then, if needed: `python scripts/fetch_events.py --minutes 30` - did CloudTrail record the events? Then check the queue and Lambda logs (CloudWatch group `/aws/lambda/iamwatch-engine`). Is the stack in us-east-1? |
| alerts exist but no e-mail | SNS subscription not confirmed (check spam), or the alert was WATCH (use `--notify-watch true`). |
| repeated runs give no new alert | cooldown (default 1 h). Redeploy with `--cooldown 60`. |
| messages pile up in the dead-letter queue | the Lambda raised an error 5 times: read the CloudWatch log for the traceback. |
| `AccessDenied` in `deploy.py` | the AWS user needs permission to create IAM roles, Lambda, SQS, DynamoDB, S3, SNS, EventBridge, CloudFormation (an admin user is simplest). |
| `deploy.py` fails on a service | free-plan restriction - upgrade the account plan. |
| lab scenario fails once | IAM propagation; run `python lab/attacks.py reset` and try again. |
| `check_fields.py` shows MISSING | a CloudTrail field differs in your account: adapt `hop_signature` / `events.py`, run tests, redeploy. |
