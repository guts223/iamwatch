# Experiments (v2)

The step-by-step instructions are in `RUNBOOK.md` in the project root. Which result goes where in the paper:

| file | paper element |
|---|---|
| `summary_live.md` Table L1 + `fig_live_family.png` | Live detection per family: IAMWatch vs single-event rules vs GuardDuty |
| `summary_live.md` Table L2 + `fig_live_delay.png` | Live delay and its split (CloudTrail delivery / queue / processing) |
| `summary_live.md` Table L3 (`benign_live.json`) | False alerts on real benign activity |
| `summary_live.md` Table L4 (`gapfill_real.csv`) | Recovery of events that never reached the queue |
| `summary_robust.md` + `fig_robust.png` | Stress tests (simulation): noise, lost events (+ gap-fill), slow attacker (fixed vs linked window), two attackers, benign load |
| `summary.md` sections 1-6 | Simulated coverage, staleness, scaling (label as simulation / synthetic) |
| `batch_scan.json` | Measured runtime of a full scan |
