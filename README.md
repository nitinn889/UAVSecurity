# UAV Security Supervisor

An onboard security supervisor for a PX4 UAV: it watches the vehicle's own
sensor and command streams, scores how far each one can be trusted, and takes
autonomous mitigating action when a stream stops being credible.

Runs against PX4 SITL + Gazebo on a workstation, with the supervisor itself
deployable to a Raspberry Pi companion computer over an encrypted link.

---

## What it actually does

```
 PX4 SITL + Gazebo  ──uXRCE-DDS──┐
 (workstation)                   │
                                 ▼
                        sensor_monitor  (PC)
                                 │  /security/sensor_snapshot
                                 │  ChaCha20-Poly1305 sealed
                                 ▼
                     ┌───────────────────────┐
                     │  supervisor  (Pi)     │
                     │   TrustEngine         │  physics / cross-sensor /
                     │   AnomalyDetector     │  temporal rule checks
                     │   ResponseEngine      │  + ML fusion (gated)
                     └───────────────────────┘
                                 │  /security/mitigation_intent
                                 │  ChaCha20-Poly1305 sealed
                                 ▼
                         actuator  (PC)  ──▶ /fmu/in/vehicle_command
                                 │
                            dashboard  (live web UI)
```

The split exists because the Pi deliberately does **not** build `px4_msgs`:
`supervisor` speaks only `rclpy` + `std_msgs`, consuming JSON snapshots and
emitting JSON mitigation intents, which `actuator` (on the PC, next to the DDS
agent) translates into real PX4 writes.

### Detection

`TrustEngine` holds a 0..1 trust score per component (GPS, IMU, barometer,
attitude, commands) and decays it on three classes of check:

| Class | Examples |
|---|---|
| **Physics** | impossible GPS speed/jump, accel magnitude outside survivable bounds, command ID outside the whitelist |
| **Cross-sensor** | GPS altitude vs barometer, GPS velocity vs EKF velocity, attitude vs gyro-integrated attitude |
| **Temporal** | GPS frozen while armed and moving, GPS stream stale/replayed, IMU frozen, command flood |

### Response

`ResponseEngine` escalates by overall trust: flag → de-weight GPS → isolate a
sensor → degraded mode → hover → RTH → land. Hover is cancellable by
hysteresis; RTH and LAND deliberately are not.

---

## Results (Phase 9)

35 runs on the full distributed stack — PX4 SITL on the PC, supervisor on a
Raspberry Pi 4 in Docker, encryption active throughout.

| Attack | Detected | Mean latency |
|---|---|---|
| `imu_noise` | 5/5 | 0.103 s |
| `cmd_inject` | 5/5 | 0.121 s |
| `telemetry_replay` | 5/5 | 1.881 s |
| `gps_deny` | 5/5 | 2.213 s |
| `gps_freeze` | 5/5 | 2.295 s |
| `gps_spoof` | 3/5 | 1.325 s |
| `combined` (freeze + noise) | 5/5 runs, 2/2 components each | — |

- **Detection accuracy: 93.3%** (28/30 single-attack runs)
- **False-positive rate on clean flights: 0/5 flights escalated**
- Pi cost: ~21% peak of one core, ~224 MB RSS
- PC↔Pi link: ~38 KB/s

Full numbers in [`data/phase9/PHASE9_REPORT.md`](data/phase9/PHASE9_REPORT.md).
Known limitations and ranked recommendations in
[`data/phase9/findings.md`](data/phase9/findings.md).

### Two results worth reading the caveats on

**`gps_spoof` at 60% is a threshold margin, not a detector failure.** The
injector ramps a 50 m offset over 3 s and edits only latitude, leaving the
velocity fields alone. That is a 1.67 m per-update jump against a 50 m limit,
and an implied speed of 16.7 m/s against a 20 m/s limit — detection rests on
one check sitting 17% under its threshold, so sampling jitter decides each
run. The spoof is internally contradictory (position advancing at 16.7 m/s
while the receiver reports ~0 velocity) and nothing currently compares those
two, which is the recommended fix.

**The ML layer contributes no detection value as currently trained.** Replaying
43 logged flights through it: 916 anomalies across 88,409 clean windows, and
**0 across 1,200 attack windows**. It was trained with `contamination=0.1`,
which by construction labels ~10% of its own training distribution anomalous,
on a mostly-hover dataset — so a normal takeoff climb lands in that tail. It
is gated by `ml_confidence_min` so it cannot move a trust score, still runs
and publishes, and resumes contributing with no code change once retrained.
All detection that currently works is rule-based.

---

## Encryption

ChaCha20-**Poly1305** (AEAD) on both hops that cross the wire. Bare ChaCha20
would give confidentiality with no integrity — a flipped ciphertext bit flips
the plaintext bit undetected, which is self-defeating for a system whose whole
job is detecting tampering.

- Per-epoch keys via `HKDF-SHA256(root_key, "epoch:N")`, so rotation needs no
  key exchange: the epoch rides in the authenticated header and the receiver
  derives the matching key. This is what makes the `ROTATE_ENCRYPTION_KEY`
  response action do real work.
- Replay windows keyed on `(sender, session, epoch)`. The per-process session
  id matters: without it a legitimately restarted publisher restarts its
  sequence at 1 and is indistinguishable from a replay attacker.
- It earned its keep: during the campaign it produced **935 replay detections,
  every one inside a `telemetry_replay` attack window**, and zero false alarms
  across the other 30 attack runs and 5 clean flights. That attack is now
  caught twice over — by the staleness check and independently by the AEAD
  sequence check.

PX4's own `/fmu/*` topics are **not** encrypted; that needs changes to PX4
firmware and the XRCE agent, outside this workspace.

### Key setup (required)

No key is committed. Generate one per deployment:

```bash
python3 -c "import os;print(os.urandom(32).hex())" > config/chacha20_key.hex
chmod 600 config/chacha20_key.hex
```

The same key must exist on both machines. `$UAV_SEC_KEY` overrides the file if
you would rather it never touch disk. Set `crypto.enabled: false` in
`config/security_config.yaml` to run in the clear (useful for A/B measuring
the encryption overhead).

---

## Getting started

### Prerequisites

- ROS 2 (this tree targets `lyrical`) with `rclpy`, `std_msgs`
- PX4-Autopilot + Gazebo, and `px4_msgs` built in a sibling workspace
  (`~/px4_msgs_ws`)
- `MicroXRCEAgent`
- Python: `numpy`, `scikit-learn`, `joblib`, `pyyaml`, `cryptography`, `flask`

### Build

```bash
source /opt/ros/lyrical/setup.bash
source ~/px4_msgs_ws/install/setup.bash
colcon build --packages-select security_supervisor attack_injector security_dashboard
source install/setup.bash
```

### Run a clean flight

```bash
./scripts/phase9_sim_up.sh --restart        # PX4 + Gazebo + XRCE agent, waits for real data
./scripts/phase9_env.sh ros2 run security_supervisor sensor_monitor &
./scripts/phase9_env.sh ros2 run security_supervisor supervisor &
./scripts/phase9_env.sh ros2 run security_supervisor actuator &
./scripts/phase9_env.sh ros2 run security_dashboard dashboard_node &   # http://localhost:8080
./scripts/phase9_env.sh python3 scripts/test_flight.py
```

`phase9_env.sh` exists because three things have to agree or the stack fails in
ways that look like detector bugs: `ROS_DOMAIN_ID`, the Fast DDS profile, and
the three workspace overlays.

### Run one attack

```bash
./scripts/run_attack_scenario.sh gps_spoof 15
# gps_spoof | gps_freeze | cmd_inject | imu_noise | telemetry_replay | gps_deny
```

### Run the campaign and regenerate the report

```bash
./scripts/phase9_env.sh python3 scripts/phase9_campaign.py --runs 5
./scripts/phase9_env.sh python3 scripts/phase9_aggregate.py
./scripts/phase9_env.sh python3 scripts/phase9_report.py
```

Add `--no-pi` to keep the supervisor on the workstation.

### Tests

```bash
./scripts/phase9_env.sh python3 -m pytest src/*/test/ -q    # 92 tests
```

---

## Deploying the supervisor to a Raspberry Pi

The Pi runs the supervisor in Docker. Build and run:

```bash
rsync -az src/security_supervisor config models docker pi@<pi>:~/uav_security_ws/
ssh pi@<pi> "cd ~/uav_security_ws && docker build -f docker/Dockerfile.pi-supervisor -t uav-supervisor ."
ssh pi@<pi> "docker run -d --restart unless-stopped --name uav-supervisor --network host \
  -e ROS_DOMAIN_ID=42 \
  -e FASTDDS_DEFAULT_PROFILES_FILE=/root/uav_security_ws/config/fastdds_pi.xml \
  -v ~/uav_security_ws/config:/root/uav_security_ws/config:ro \
  -v ~/uav_security_ws/models:/root/uav_security_ws/models:ro \
  -v ~/uav_security_ws/data/logs:/root/uav_security_ws/data/logs \
  uav-supervisor"
```

### Networking gotchas, all of which cost real debugging time

1. **PX4 must be *launched* with `ROS_DOMAIN_ID` set.** Its `rcS` copies the
   variable into `UXRCE_DDS_DOM_ID`; miss it and the bridged `/fmu/*` topics
   land on domain 0 while everything else is on 42. `MicroXRCEAgent` has no
   domain flag and follows whatever the PX4 client asks for.
2. **Restrict Fast DDS to the direct link.** Each host otherwise advertises a
   locator for *every* interface, including `docker0` (172.17.0.1) — an address
   the peer cannot reach. Discovery still completes, so both sides list the
   topics and it looks healthy, while no user data ever arrives. See
   `config/fastdds_pc.xml` / `fastdds_pi.xml`.
3. **Keep `127.0.0.1` in that whitelist.** `useBuiltinTransports=false` drops
   the shared-memory and loopback transports too, and without loopback a node
   cannot reach the XRCE agent on its *own* machine: it publishes happily and
   receives nothing.
4. **Give the Pi's wired interface `ipv4.never-default`**, or a point-to-point
   link with no gateway steals the default route and the Pi loses internet.

---

## Layout

```
src/security_supervisor/      trust engine, ML detector, response engine,
                              crypto channel, sensor monitor, actuator
src/attack_injector/          six attack scenarios + launch files
src/security_dashboard/       live web dashboard (Flask + SSE)
config/                       all thresholds and tunables; DDS profiles
models/                       trained IsolationForest + scaler
scripts/                      sim bring-up, flights, campaign, aggregation, report
docker/                       Pi (arm64) supervisor image
docs/architecture.md          topic graph, node roles, design notes
data/phase9/                  campaign results, report, findings
```

Nothing is hardcoded in `trust_engine.py`; every threshold lives in
`config/trust_config.yaml` with a comment explaining why it has that value.

### Legacy prototype

The standalone scripts at the repository root are the earlier single-file
exploration that preceded this workspace. They are kept for reference and are
not part of the ROS 2 system described above. They work in attack/defence
pairs:

| Attack side | Defence side |
|---|---|
| `attackSim.py` | `secureBlackBox.py` |
| `telemetryGeneration.py` | `blackBox.py` |
| `gpsSpoof.py`, `injection.py` | `gpsspoofDetection.py` |

`decryptedLogs.py` reads back what `secureBlackBox.py` wrote;
`MacOSdebug.md` holds macOS-specific setup notes for them.

---

## Status

Phases 1–9 complete: sensor monitoring, trust scoring, ML fusion, attack
injection, autonomous response, Pi deployment, live dashboard, encrypted
control plane, and a measured attack campaign.

Next: tuning against the Phase 9 numbers — the `gps_spoof` consistency check
and retraining the anomaly detector on dynamic-flight data are the two items
that would move detection capability most.
