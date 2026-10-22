# The long real-AWS campaign, in the right order. Resumable: if it stops, run the same command again.
#   .\scripts\campaign.ps1 -Reps 10     (about 90 attacks, ~2 h)      .\scripts\campaign.ps1 -Reps 20   (~4 h)
param([int]$Reps = 10, [int]$GapfillReps = 5, [int]$BenignMinutes = 60)
$ErrorActionPreference = "Stop"
$sw = [Diagnostics.Stopwatch]::StartNew()
function Run { & $args[0] $args[1..($args.Length - 1)]; if ($LASTEXITCODE -ne 0) { throw "command failed: $args" } }
Write-Host "== 1/6 benign load ($BenignMinutes min) - GuardDuty also uses this time to learn the account's normal behaviour"
if (-not (Test-Path results\benign_live.json)) {
    Run python lab/benign_load.py --minutes $BenignMinutes
    Start-Sleep 120
    Run python experiments/benign_eval.py
}
Write-Host "== 2/6 attacks: all nine families x $Reps"
Run python experiments/run_attacks.py --reps $Reps
Write-Host "== 3/6 gap-fill recovery test"
Run python experiments/live_gapfill.py --scenarios s1 x1 s3 --reps $GapfillReps
python scripts/guardduty.py check
if ($LASTEXITCODE -eq 0) {
    Write-Host "== 4/6 waiting 45 min so GuardDuty can publish its findings"
    Start-Sleep 2700
    Run python scripts/guardduty.py collect
} else {
    Write-Host "== 4/6 GuardDuty is not available in this account - skipping it (the paper will compare with the rule baseline only)"
}
Write-Host "== 5/6 export tables and figures"
python scripts/show_alerts.py > results\alerts_all.txt
Run python scripts/export_tables.py
Run python experiments/analyze_live.py
Run python experiments/analyze.py
Write-Host ("CAMPAIGN DONE in {0:n1} min - send results\*.csv, results\*.json, results\*.md (NOT results\export)" -f $sw.Elapsed.TotalMinutes)