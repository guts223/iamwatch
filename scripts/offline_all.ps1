# Offline experiments (no AWS, about 20-30 minutes). Run from C:\iamwatch with (.venv) active.
$ErrorActionPreference = "Stop"
$sw = [Diagnostics.Stopwatch]::StartNew()
function Run { & $args[0] $args[1..($args.Length - 1)]; if ($LASTEXITCODE -ne 0) { throw "command failed: $args" } }
Run python -m pytest tests -q
Run python experiments/simulate.py --reps 30
Run python experiments/robustness.py --reps 30
Run python experiments/scaling_bench.py --sizes 1000 10000 50000 100000 --ops 100
Run python experiments/engine_scaling.py --sizes 50 100 200 400 --events 30
Run python experiments/analyze_robust.py
Write-Host ("OFFLINE DONE in {0:n1} min" -f $sw.Elapsed.TotalMinutes)
