# iamwatch v2 - upgrade your existing AWS account and run the real experiments (PowerShell, `C:\iamwatch`)

What is new in v2 (and why the results will be stronger)
- **All nine attack families run on real AWS** (S1-S5 and X1-X4; v1 ran only S1-S5 live, 3 times each).
- **GuardDuty** (Amazon's own threat detector) runs on the same attacks as a real competitor, next to the simple-rule baseline.
- **Real benign activity** (about 60 minutes of ordinary IAM work in the account) instead of generated events.
- **Gap-fill job**: events that never reach the queue are recovered from the CloudTrail event history; tested live by
  switching the EventBridge rule off during the attack.
- **12-hour linked window**: a slow attacker who waits more than 1 hour between steps of a credential chain is no longer missed.
- Stress tests (noise, lost events, slow attacker, two attackers, benign load) now compare "before" and "after" those two fixes.

## 0. Rules (same as before)
- Never paste AWS keys or secrets in chat. They live only in `C:\Users\<you>\.aws\credentials`.
- Use only the lab account (no real data): the lab identities escalate to administrator on purpose.
- Never delete `.venv`, `build\outputs.json`, `lab\lab_credentials.json` or `.aws\` while the experiments run.
- Do not run `teardown.py` or `setup_lab.py --destroy` until the results are exported and sent back.
- `results\export\` contains your account ID and user names: never share or publish it.
- Laptop plugged in, sleep off (Settings > System > Power > Screen and sleep > Never). The campaign is resumable.

## 1. Upgrade the SAME account (about 25 minutes). PowerShell, in this order
Your account already has the old lab, the old stack and old results. Nothing is deleted except what is listed here.

    # 1a  archive the old results (never use them in the paper) and put the new code in place
    cd C:\iamwatch
    Rename-Item results results_v1_OLD
    mkdir results
    Expand-Archive C:\Users\shind\Downloads\iamwatch_v2.zip -DestinationPath C:\Users\shind\Downloads\v2tmp -Force
    robocopy C:\Users\shind\Downloads\v2tmp\iamwatch C:\iamwatch /E /XD __pycache__ .pytest_cache
    Remove-Item scripts\final_run.ps1 -ErrorAction SilentlyContinue
    # (robocopy 0-7 = success. It never deletes .venv, build\outputs.json or lab\lab_credentials.json)

    # 1b  environment + tests
    .\.venv\Scripts\Activate.ps1
    pip install -r requirements-dev.txt
    python -m pytest tests -q                  # all tests must pass (about 1 minute)

    # 1c  undo any leftover attack, then add the new identities (existing ones are kept)
    python lab/attacks.py reset
    python lab/setup_lab.py

    # 1d  update the stack (adds gap-fill, 12 h window); your e-mail subscription stays confirmed
    python scripts/deploy.py --email YOUR_REAL_EMAIL --cooldown 1

    # 1e  clean slate for the stack + GuardDuty on
    python scripts/reset_stack_data.py
    python scripts/guardduty.py enable
    python scripts/diagnose.py                 # expect an overall OK verdict
    Start-Sleep 60

## 4. Smoke test - GATE before the long run (about 15 minutes)
    python experiments/run_attacks.py --reps 1 --out results\smoke.csv
Every one of the nine lines must end with `"detected": 1`. If any family fails, **stop and send me the output of that run plus**
`python scripts/show_alerts.py` - do not start the campaign. (X1-X4 have never run on real AWS before, so a small fix here is possible.)
Then reset: `Remove-Item results\smoke.csv ; python lab/attacks.py reset ; python scripts/reset_stack_data.py ; Start-Sleep 60`

## 5. The campaign (about 4-5 hours for -Reps 10, unattended)
    .\scripts\campaign.ps1 -Reps 10
It runs, in order: 60 min of benign load, 90 attacks (9 families x 10), the gap-fill test, a 45-minute wait for GuardDuty,
the export and the analysis. If it stops for any reason, run the same command again: finished parts are skipped
(attack repetitions resume where they stopped). For a stronger paper use `-Reps 20` (about 8 h, e.g. overnight).
Best for GuardDuty: do section 1 in the evening and start the campaign the next morning, so it has had time to learn.

While it runs, in a SECOND PowerShell window (venv active), run the offline experiments (no AWS needed):
    .\scripts\offline_all.ps1

## 6. What to send me
From `C:\iamwatch\results\`: all `*.csv`, `*.json`, `*.md`, `*.png` and `alerts_all.txt` - **not** the `export` folder.
Also the last 30 lines of the campaign window. I will rebuild the Results section from these files only.

## 7. After I confirm the results are complete
    python scripts/guardduty.py disable
    python scripts/teardown.py
    python lab/setup_lab.py --destroy

## Time and cost
| step | time | AWS cost |
|---|---|---|
| setup + deploy + smoke test | ~1 h | cents |
| campaign (-Reps 10) | ~4-5 h | < $1 (GuardDuty has a 30-day free trial) |
| offline experiments | ~30 min | none |

## If something goes wrong
| symptom | fix |
|---|---|
| `InvalidClientTokenId` on an attack | `python lab/setup_lab.py` again (re-issues the lab keys) |
| waiting for an alert forever | `python scripts/diagnose.py`, then `python scripts/show_alerts.py`; send me both |
| a run looks stuck after reset | press Ctrl+C, run `python lab/attacks.py reset`, start the same command again (it resumes) |
| `Throttling` errors | wait 2 minutes and start the same command again |
| laptop slept during the campaign | start `.\scripts\campaign.ps1 -Reps 10` again |
| `live_gapfill.py` was interrupted | it restores the EventBridge rule by itself; if unsure run `python scripts/diagnose.py` and check the rule is ENABLED |

## Honest expectations
Whatever comes out is the result. If GuardDuty finds nothing, that is what we report (with the caveat that it needs a learning
period); if a family is missed, we analyse why, fix the engine and re-run - both outcomes make a publishable paper.
