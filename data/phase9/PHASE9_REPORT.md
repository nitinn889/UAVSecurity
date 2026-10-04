# Phase 9 — Integration Testing & Attack Campaign Results

_Generated 2026-10-04 16:16 UTC_

Supervisor ran on: **Raspberry Pi (Docker)**  
Total runs: **35**  
Source: `campaign_main.jsonl`

## Headline numbers

| Metric | Value |
|---|---|
| Attack scenarios | 6 |
| Runs producing a report | 30 |
| Runs where the attack was detected | 28 |
| **Detection accuracy** | **0.9333** |
| Detection latency (s) | 1.323 ± 1.046 (0.040–2.813) |

## False positives on clean flights

Two different things get called a "false positive"; they are reported separately because the fix changed one and not the other.

| Metric | Value | Meaning |
|---|---|---|
| Clean flights flown | 5 | |
| Model-level ML anomalies | 7 (0.0048) | How often the IsolationForest calls clean data anomalous. Non-zero by construction: it was trained with contamination=0.1. |
| …passing the confidence gate | 0 | How many were confident enough to move a trust score. |
| **System-level FP flights** | **0** (**0.0000**) | Clean flights where trust actually degraded or a response fired — the rate an operator experiences. |

## Per-attack results

| Attack | Runs | Detected | Rate | Detection latency (s) | Recovery (s) | Flags |
|---|---|---|---|---|---|---|
| `cmd_inject` | 5 | 5 | 1.00 | 0.121 ± 0.022 (0.096–0.161) | 6.27 ± 0.06 (6.21–6.36) | 128.8 ± 1.0 (128–130) |
| `gps_deny` | 5 | 5 | 1.00 | 2.213 ± 0.052 (2.158–2.303) | 3.53 ± 0.05 (3.46–3.60) | 128.2 ± 0.7 (127–129) |
| `gps_freeze` | 5 | 5 | 1.00 | 2.295 ± 0.062 (2.216–2.361) | 3.54 ± 0.02 (3.51–3.56) | 127.4 ± 0.5 (127–128) |
| `gps_spoof` | 5 | 3 | 0.60 | 1.325 ± 1.073 (0.324–2.813) | 0.03 ± 0.01 (0.01–0.04) | 0.6 ± 0.5 (0–1) |
| `imu_noise` | 5 | 5 | 1.00 | 0.103 ± 0.052 (0.040–0.160) | 3.50 ± 0.05 (3.44–3.56) | 149.4 ± 0.5 (149–150) |
| `telemetry_replay` | 5 | 5 | 1.00 | 1.881 ± 0.663 (0.557–2.264) | 7.22 ± 0.05 (7.16–7.29) | 129.0 ± 1.1 (128–131) |

### How to read these

- **`gps_spoof` is the one scenario below 100%, and the reason is a threshold margin rather than a detector failure.** The injector ramps a 50 m offset over 3 s and edits only `latitude_deg`, leaving the velocity fields untouched. At the 10 Hz snapshot rate that is a 1.67 m per-update jump (vs the 50 m `gps_max_pos_jump` limit) and an implied horizontal speed of ~16.7 m/s against a `gps_max_horiz_speed` of 20 m/s — 83% of the threshold. Detection rests on one check sitting 17% under its limit, so whether a run trips it comes down to sampling jitter. That also explains the single flag when it fires, and the ~0.97 GPS minimum: the score barely moves. See `findings.md` for the recommended fix (a position/velocity consistency check — the spoof is internally contradictory, since position advances at 16.7 m/s while the receiver reports ~0 velocity, and nothing currently compares the two).
- **Flag counts are not a quality ranking.** `gps_spoof` produces ~1 flag and `imu_noise` ~149 because the latter violates a per-sample physics bound on every sample, while the former trips one borderline check. More flags means a louder signal, not a better detector.
- **Recovery time is only meaningful where trust actually fell.** `gps_spoof`'s ~0.03 s recovery reflects a score that never left ~0.97, not fast remediation.

## Combined / overlapping attacks

### `combined_gps_freeze_imu_noise`

Components: `gps_freeze`, `imu_noise`  
Runs: 5  
Simultaneous component detection rate: **1.0000**

> **Read the per-component latencies with caution.** The harness overlays two attacks by running two `run_attack_scenario.sh` instances concurrently, staggered by 12 s so the second attaches to the already-running PX4. Each instance launches its *own* `sensor_monitor`, so during the overlap two publishers feed `/security/sensor_snapshot` — one presenting the manipulated sensor and one the real one. The detection *rate* is therefore meaningful (both components were caught in every run), but the latencies are inflated by that interference and by the stagger, and should not be compared against the single-attack figures. Overlaying both injectors inside one launch file, sharing a single `sensor_monitor`, would be the correct fix.

| Component | Runs | Detected | Rate | Latency (s) |
|---|---|---|---|---|
| `gps_freeze` | 5 | 5 | 1.00 | 12.358 ± 0.225 (12.053–12.613) |
| `imu_noise` | 5 | 5 | 1.00 | 0.306 ± 0.155 (0.096–0.453) |

## Trust score minima under attack

How far each component was driven down while the attack was active (1.0 = untouched, 0.0 = fully untrusted).

| Attack | GPS | IMU | BAROMETER | ATTITUDE | COMMANDS |
|---|---|---|---|---|---|
| `cmd_inject` | 1.00 | 1.00 | 1.00 | 1.00 | 0.00 |
| `gps_deny` | 0.00 | 1.00 | 1.00 | 1.00 | 1.00 |
| `gps_freeze` | 0.00 | 1.00 | 1.00 | 1.00 | 1.00 |
| `gps_spoof` | 0.97 | 1.00 | 1.00 | 1.00 | 1.00 |
| `imu_noise` | 1.00 | 0.00 | 1.00 | 1.00 | 1.00 |
| `telemetry_replay` | 0.00 | 0.94 | 1.00 | 1.00 | 1.00 |

## Response actions fired

| Attack | Actions (count across runs) |
|---|---|
| `cmd_inject` | `COMMAND_HOVER`×5, `COMMAND_RTH`×5, `ENTER_DEGRADED_MODE`×5, `FLAG_ONLY`×5, `REJECT_COMMAND`×5, `ROTATE_ENCRYPTION_KEY`×5 |
| `gps_deny` | `COMMAND_HOVER`×5, `COMMAND_RTH`×5, `ENTER_DEGRADED_MODE`×5, `FLAG_ONLY`×5, `ISOLATE_GPS`×5, `REDUCE_GPS_WEIGHT`×5 |
| `gps_freeze` | `COMMAND_HOVER`×5, `COMMAND_RTH`×5, `ENTER_DEGRADED_MODE`×5, `FLAG_ONLY`×5, `ISOLATE_GPS`×5, `REDUCE_GPS_WEIGHT`×5 |
| `gps_spoof` | `ENTER_DEGRADED_MODE`×4, `FLAG_ONLY`×4, `REDUCE_GPS_WEIGHT`×4 |
| `imu_noise` | `COMMAND_HOVER`×5, `COMMAND_RTH`×5, `ENTER_DEGRADED_MODE`×5, `FLAG_ONLY`×5, `ISOLATE_IMU`×5 |
| `telemetry_replay` | `COMMAND_HOVER`×5, `COMMAND_RTH`×5, `ENTER_DEGRADED_MODE`×5, `FLAG_ONLY`×5, `ISOLATE_GPS`×5, `REDUCE_GPS_WEIGHT`×5 |

## Communication overhead (PC ↔ Pi)

Measured as byte-counter deltas on the direct Ethernet link across each run. The two ends are independent counters, so PC tx ≈ Pi rx is a consistency check on the measurement.

| Attack | PC tx (bytes) | PC rx (bytes) | Throughput (B/s) |
|---|---|---|---|
| `cmd_inject` | 1751179 ± 17741 (1724624–1773234) | 1078323 ± 3173 (1074374–1083456) | 39114 ± 1106 (37760–40230) |
| `gps_deny` | 1754154 ± 20642 (1724382–1782044) | 1035463 ± 5733 (1024500–1040262) | 37499 ± 796 (36810–39046) |
| `gps_freeze` | 1743051 ± 16740 (1720362–1765812) | 1029481 ± 7679 (1016832–1038856) | 38318 ± 1003 (37018–39274) |
| `gps_spoof` | 1371556 ± 616773 (167207–1775870) | 737998 ± 340174 (74572–961910) | 28495 ± 13005 (3248–37994) |
| `imu_noise` | 1736168 ± 7156 (1727852–1749074) | 1048034 ± 6955 (1041550–1057042) | 38487 ± 1123 (37032–39435) |
| `telemetry_replay` | 2021643 ± 8657 (2008726–2032238) | 1105046 ± 7028 (1095954–1115330) | 43226 ± 1456 (41382–44634) |

## Raspberry Pi resource usage

Sampled every 5 s while each scenario ran. CPU is summed across the supervisor's processes, so 100% = one full core of the Pi's four.

| Attack | CPU % (mean of run means) | CPU % (mean of run peaks) | RSS MB | Load avg |
|---|---|---|---|---|
| `cmd_inject` | 15.05 | 21.54 | 223.6 | 0.36 |
| `gps_deny` | 15.09 | 21.50 | 223.7 | 0.20 |
| `gps_freeze` | 14.91 | 21.40 | 223.6 | 0.37 |
| `gps_spoof` | 12.54 | 19.14 | 222.5 | 0.19 |
| `imu_noise` | 14.91 | 21.20 | 223.6 | 0.13 |
| `telemetry_replay` | 14.74 | 21.16 | 223.7 | 0.12 |

## Encryption

ChaCha20-Poly1305 (AEAD) active on both PC↔Pi hops for every run above: `/security/sensor_snapshot` outbound and `/security/mitigation_intent` inbound.

- Envelopes opened by the Pi supervisor: **1825**
- Authentication failures: **0**
- Malformed envelopes: **0**
- Replays detected: **935**
- Replay alarms outside an attack window: **0**
- Key epoch at end of campaign: **0**

**The replay detections are true positives.** All replay detections fall inside the five telemetry_replay attack windows -- the first alarm lands in the same second as the first attack start, the last 3s after the final window closes (the injector's post-attack loop). Zero replay alarms across the other 30 attack runs and the 5 clean flights, confirming the per-process session-id fix. telemetry_replay is therefore detected twice over: by trust_engine's staleness check and, independently, by the AEAD sequence check.

That is the encryption layer earning its place rather than just adding overhead: it caught an attack on its own, from the sequence numbers alone, without reference to any sensor threshold.

## Validation performed

| Check | Result |
|---|---|
| Unit/integration tests | **92 passed** (66 pre-Phase-9 + 26 added) |
| Clean flight, full cycle, encryption on | trust held `1.00` on all five components; **zero** escalations |
| Clean-flight false positives | **0/5 flights** escalated |
| Supervisor on Pi, in Docker | ran all 35 campaign runs; peak CPU ~21% of one core, ~224 MB RSS |
| Encrypted wire check | no plaintext telemetry present in `/security/sensor_snapshot`; sealed envelopes only |
| Full stack together (sim + PC nodes + Pi supervisor + dashboard) | dashboard ingested 530 snapshots / 541 trust updates with **0 decrypt errors** while an attack ran; response chain visible end to end |

The campaign runs themselves were executed without the dashboard attached — it is a passive observer, and leaving it off keeps one fewer subscriber on every topic — so it was verified separately in-situ, as the last row records.

## Open items for Phase 10

See `data/phase9/findings.md` for detail. In short:

1. **`gps_spoof` detection is marginal by construction** (83% of one threshold). Recommended fix is a GPS position/velocity consistency check, not a threshold nudge — the spoof is internally contradictory and that is both more sensitive and harder to evade.
2. **The ML layer contributes no detection value as trained** — 0 true positives across 1200 attack windows, 916 false positives across 88409 clean ones. It is gated off from affecting scores and needs retraining on data covering dynamic flight.
3. **The combined-attack harness double-publishes** `/security/sensor_snapshot`; overlay both injectors in one launch file sharing a single `sensor_monitor` to get trustworthy overlap latencies.
4. **`crypto.drop_replayed` is `false`** so `telemetry_replay` still measures trust_engine's own detector. A production build should set it true, which would stop replayed telemetry at the crypto layer outright.

