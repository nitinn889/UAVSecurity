# Phase 9 findings (for Phase 10 tuning)

Observations that came out of the campaign and are worth acting on, ordered
by how much they affect real detection capability.

---

## 1. `gps_spoof` is marginal by construction, not by accident

**Observed:** `gps_spoof` detects inconsistently across identical runs
(detected 2.43 s, 2.02 s, then missed entirely — same config, same code).
When it does fire it produces exactly one `physics` flag; when it misses it
produces zero flags and GPS trust never leaves 1.00.

**Why.** The injector ramps a 50 m latitude offset over 3.0 s
(`gps_spoof_offset_m=50.0`, `gps_spoof_ramp_s=3.0`) and, critically, edits
**only `latitude_deg`** — `vel_n_m_s` / `vel_e_m_s` are left untouched
(`injector_node._gps_cb`). Against `trust_engine._physics_gps` at the 10 Hz
snapshot rate that gives:

| quantity | value | threshold | fires? |
|---|---|---|---|
| per-update position jump | 50 m / 3.0 s / 10 Hz ≈ **1.67 m** | `gps_max_pos_jump` 50 m | no |
| implied horizontal speed | 1.67 m / 0.1 s ≈ **16.7 m/s** | `gps_max_horiz_speed` 20 m/s | **marginal — 83% of threshold** |
| GPS-vs-EKF velocity disagreement | ≈ 0 (velocity not spoofed) | `cross_gps_ekf_vel_thresh` 3 m/s | no |
| GPS-vs-baro altitude | 0 (horizontal spoof) | `cross_gps_baro_alt_thresh` 15 m | no |

So the entire detection rests on one check sitting 17% under its threshold.
Whether a given run trips it comes down to sampling jitter, which is exactly
the behaviour seen.

**Recommendations (Phase 10), best first:**

1. **Add a position/velocity consistency check.** This spoof is internally
   contradictory: position advances at ~16.7 m/s while the receiver's own
   velocity fields report ~0. `_physics_gps` currently collapses these into
   `effective_speed = max(reported, implied)` and compares that to one
   threshold — it never compares reported *against* implied. A spoofer that
   edits position without forging matching velocity should be caught on the
   contradiction alone, regardless of magnitude, and that is both more
   sensitive and harder to evade than lowering a speed limit.
2. **Lower `gps_max_horiz_speed`** from 20 m/s. The config comments note the
   x500 airframe tops out around 12 m/s, so 20 leaves far more headroom than
   the vehicle needs; ~15 m/s would catch this ramp with margin.
3. Only then consider a cumulative-drift check (GPS position vs EKF position
   integrated over a window), which also catches slow spoofs that stay under
   any per-update speed limit.

Note this is a **tuning gap, not a regression** — it behaves identically
before and after the Phase 9 changes.

---

## 2. The ML layer currently subtracts value

Replaying all 43 logged flights through the live detector:

| | windows | anomalies | confidence |
|---|---|---|---|
| clean flight | 88,409 | 916 (1.04%) | ≤ 0.5444 |
| under attack | 1,200 | **0 (0.00%)** | — |

Zero true positives across all six scenarios; every hit observed to date is
a false positive. Consistent with `models/training_report.json`, which
records `targets_met=false`, `contamination=0.1` and 0% detection for
`gps_position_spoof`, `gps_frozen` and `command_injection`.

`ml_confidence_min: 0.6` now gates the penalty so these cannot move a trust
score. The detector still runs and publishes, so a retrained model resumes
contributing with no code change.

**Recommendation:** retrain on data that actually covers dynamic flight
(climb, translation, descent), not the mostly-hover set used so far, and
re-tune `contamination` against a held-out attack set. Until then the ML
layer should be considered instrumentation, not a detector.

---

## 3. `false_positives_pre_attack` measures the model, not the system

`injector_node` increments it on `degraded OR flags OR ml_flagged`, where
`ml_flagged` reads the detector's **raw** `is_anomaly` — before the
confidence gate. Since a sub-threshold anomaly now changes no score and
fires no action, that counter overstates operational false alarms.

`scripts/phase9_false_positive_run.py` reports both separately:
model-level (raw ML hits) and system-level (trust actually degraded or a
response actually fired). Use the system-level number when quoting a
false-positive rate; use the model-level one when judging the model.

---

## 4. Harness issues fixed during Phase 9 (recorded so they don't recur)

- **Supervisor state leaked between runs.** `run_attack_scenario.sh` has
  always relaunched the PC-side supervisor per run; the long-lived Pi
  container silently removed that, carrying trust scores, sliding windows and
  `response_engine`'s never-cancelled RTH/HOVER latches into the next run.
  Runs after the first were measuring an already-escalated supervisor.
  Fixed by restarting the container before each run.
- **Replay window keyed without a session id.** A restarted publisher
  legitimately restarts its sequence at 1 and was indistinguishable from a
  replay: 1845 false alarms, and under `drop_replayed=true` it would have
  halted telemetry entirely. Fixed with a per-process session id bound into
  the AEAD tag.
- **DDS advertised an unreachable `docker0` locator.** Discovery completed
  and topics appeared on both hosts while no user data ever arrived. Fixed
  with interface whitelisting + unicast initial peers — and the whitelist
  must include `127.0.0.1`, or a node cannot reach the XRCE agent on its own
  machine.
- **PX4 must be launched with `ROS_DOMAIN_ID` set**, since its `rcS` copies
  it into `UXRCE_DDS_DOM_ID`; otherwise the bridged `/fmu/*` topics land on
  domain 0 while everything else is on 42.
