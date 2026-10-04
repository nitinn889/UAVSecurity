# Security Supervisor Architecture — Phase 1

## Overview

The security supervisor is a ROS 2 (Lyrical) software stack that sits between
PX4's uXRCE-DDS bridge and the vehicle's control loop. It observes PX4's
sensor and status topics, scores the trustworthiness of each subsystem,
detects anomalies, and can override outgoing vehicle commands when a threat
is confirmed. In Phase 1 the nodes exist as structural stubs; scoring,
detection, and response logic are implemented in later phases.

## Simulation stack (Phase 1)

- **PX4-Autopilot** (`main` branch) running SITL
- **Gazebo Jetty** (`gz-sim` 10.x) — Gazebo **Harmonic** is EOL and not
  packaged for Ubuntu 26.04 (resolute); Jetty is the current release
  packaged for this OS and is what PX4's `make px4_sitl gz_x500` target
  drives.
- **Micro XRCE-DDS Agent** (built from source — no `resolute` apt package
  exists yet) bridging PX4's uORB topics to ROS 2 as `/fmu/out/*` and
  `/fmu/in/*`
- **ROS 2 Lyrical**, `rclpy` only

## Node roles (`security_supervisor` package)

| Node | Role |
|---|---|
| `sensor_monitor` | Subscribes to all `/fmu/out/*` PX4 topics, normalizes readings into per-component snapshots for downstream consumers. |
| `trust_engine` (Phase 3) | Maintains a dynamic trust score per component (GPS, IMU, telemetry, comm link, control commands) from `sensor_monitor` output and physics-consistency signals. |
| `anomaly_detector` (Phase 4) | Combines ML anomaly models with physics-based consistency checks (e.g. GPS-vs-IMU dead-reckoning divergence) to flag specific attack signatures. |
| `response_engine` (Phase 6) | Converts trust scores + anomaly flags into autonomous responses (alert, sensor fusion re-weighting, failsafe, command override) published to `/fmu/in/vehicle_command`. |
| `supervisor_node` | Composition root; owns/coordinates the above nodes and exposes the aggregate security status. |

## Topic graph

```
                        PX4 SITL (uORB)
                               |
                    Micro XRCE-DDS Agent (udp4:8888)
                               |
                       ROS 2 DDS network
                               |
        -------------------------------------------------
        |          |          |          |              |
  /fmu/out/     /fmu/out/  /fmu/out/  /fmu/out/     /fmu/out/
  vehicle_      sensor_    vehicle_   vehicle_      battery_
  local_        combined   gps_       attitude      status
  position                 position
        |          |          |          |              |
        -------------------------------------------------
                               |
                        sensor_monitor
                               | (per-component snapshots, std_msgs/String JSON)
                               v
                         trust_engine
                               | (trust scores per component)
                               v
                       anomaly_detector
                               | (anomaly flags + confidence)
                               v
                       response_engine
                               |
                               v
                    /fmu/in/vehicle_command  (override / failsafe)
                    /fmu/in/trajectory_setpoint
                    /fmu/in/offboard_control_mode
```

### Subscriptions / publications per node

- **sensor_monitor**
  - Subscribes: `/fmu/out/vehicle_local_position`, `/fmu/out/vehicle_global_position`,
    `/fmu/out/sensor_combined`, `/fmu/out/vehicle_gps_position`,
    `/fmu/out/vehicle_attitude`, `/fmu/out/battery_status`
  - Publishes: `/security/sensor_snapshot` (`std_msgs/String`, JSON)
- **trust_engine**
  - Subscribes: `/security/sensor_snapshot`
  - Publishes: `/security/trust_scores` (`std_msgs/String`, JSON)
- **anomaly_detector**
  - Subscribes: `/security/sensor_snapshot`, `/security/trust_scores`
  - Publishes: `/security/anomaly_events` (`std_msgs/String`, JSON)
- **response_engine**
  - Subscribes: `/security/trust_scores`, `/security/anomaly_events`
  - Publishes: `/fmu/in/vehicle_command`, `/security/response_actions` (`std_msgs/String`, JSON)
- **supervisor_node**
  - Subscribes: `/security/trust_scores`, `/security/anomaly_events`, `/security/response_actions`
  - Publishes: `/security/status` (`std_msgs/String`, JSON, aggregate)

## Security event schema (Phase 1)

Custom message types are deferred; Phase 1 uses `std_msgs/String` carrying a
JSON payload so the schema can evolve without a rebuild of `px4_msgs`-style
generated interfaces. All security topics share this envelope:

```json
{
  "timestamp_us": 1234567890,
  "source_node": "trust_engine",
  "component": "gps",
  "event_type": "trust_score | anomaly | response_action | status",
  "payload": { }
}
```

`payload` is event-type-specific, e.g. for `trust_score`:
`{"score": 0.87, "previous_score": 0.95, "reason": "gps_imu_divergence"}`.
A future phase may promote this to a dedicated `security_msgs` package
(`SecurityEvent.msg`) once the schema stabilizes.

## SITL parameters required for offboard flight without RC/GCS

By default PX4 refuses to arm unless a manual-control (RC/joystick) source or
a ground-control-station connection is present — neither applies to a
companion-computer-only OFFBOARD flight like `scripts/test_flight.py`. Two
parameters must be set (once per SITL session, or persisted via a parameter
file) or the arm command is rejected with `TEMPORARILY_REJECTED`:

- `COM_RC_IN_MODE = 4` ("Disable manual control") — stops PX4 requiring a
  calibrated RC receiver.
- `NAV_DLL_ACT = 0` ("Disabled") — stops PX4 requiring an active GCS/data-link
  connection to arm (see `rcAndDataLinkCheck.cpp`: `gcs_connection_required =
  NAV_DLL_ACT > 0`).

These can be set at runtime over MAVLink (e.g. via `pymavlink`
`param_set_send`) or baked into a PX4 parameter file loaded at boot for
repeatable test runs.

## Raspberry Pi integration (Phase 7)

The Pi joins the same DDS network rather than a separate bridge:

1. Set the same `ROS_DOMAIN_ID` on both machines. Note this is an
   **environment variable**, not `config/dds_params.yaml` — nothing in the
   codebase reads that file's `ros_domain_id`, it is reference material
   only. PX4 matters too: its `rcS` copies `$ROS_DOMAIN_ID` into the
   `UXRCE_DDS_DOM_ID` parameter, so PX4 SITL must be *launched* with the
   variable set or the bridged `/fmu/*` topics land on domain 0 while
   everything else is on 42. `MicroXRCEAgent` has no domain flag of its own
   and follows whatever the PX4 client requests.
2. The Pi does **not** build `px4_msgs` and does not subscribe to `/fmu/*`.
   `supervisor_node` imports only `rclpy` + `std_msgs`: it consumes JSON
   snapshots on `/security/sensor_snapshot` and emits JSON mitigation
   intents on `/security/mitigation_intent`, which `actuator_node` — kept on
   the PC beside the DDS agent — translates into real `px4_msgs` writes.
   That split is what keeps the Pi image free of the rosidl toolchain.
   For a hardware Pi on the airframe, the XRCE agent would move to the Pi
   (serial to the flight controller) and this split would invert.
3. Discovery needs explicit configuration on a direct PC↔Pi link; the
   default multicast assumption is not sufficient. See
   `config/fastdds_pc.xml` / `config/fastdds_pi.xml`:
   - Each host advertises a unicast locator for *every* local interface by
     default. With `docker0` present, the peer receives `172.17.0.1` — an
     address that does not exist on its network. Discovery still completes,
     so both sides list the topics and it looks healthy, but user data never
     arrives. Restrict the transport to the direct-link address.
   - The whitelist must also include `127.0.0.1`. `useBuiltinTransports=false`
     removes the shared-memory and loopback transports along with the
     unwanted ones, and without loopback a node cannot reach the XRCE agent
     or its siblings on its *own* machine — it publishes happily and
     receives nothing.
   - `initialPeersList` makes discovery unicast so it does not depend on
     multicast crossing the link at all.

## Phase 9: control-plane encryption and campaign harness

`crypto_channel.py` seals the two hops that cross the wire
(`/security/sensor_snapshot` PC→Pi, `/security/mitigation_intent` Pi→PC)
with ChaCha20-Poly1305. Design notes live in that module; the operationally
important points:

- **AEAD, not bare ChaCha20.** Raw ChaCha20 is a stream cipher with no
  integrity, so a flipped ciphertext bit flips the plaintext bit undetected.
  For a system whose purpose is detecting tampering, that would be
  self-defeating.
- **Key rotation needs no key exchange.** Per-epoch keys are
  `HKDF-SHA256(root_key, "epoch:N")`; the epoch travels in the authenticated
  header and the receiver derives the same key. This is what makes the
  pre-existing `ROTATE_ENCRYPTION_KEY` response action do real work.
- **Replay windows are keyed on `(sender, session, epoch)`.** The per-process
  session id matters: a restarted publisher legitimately restarts its
  sequence at 1, and without a session id that is indistinguishable from a
  replay — it produced 1845 false alarms in one campaign and would have
  halted telemetry entirely under `drop_replayed=true`.
- `PX4`'s own `/fmu/*` topics are **not** encrypted; that would require
  changing PX4 firmware and the XRCE agent, which is outside this workspace.

Campaign harness (`scripts/phase9_*.py`):

- `phase9_sim_up.sh` waits for actual sensor **data**, not just topic
  registration — the agent registers every `/fmu/*` topic as soon as PX4's
  client connects, so topics appear even when Gazebo failed to attach and
  PX4 is publishing nothing.
- `phase9_campaign.py` restarts the Pi supervisor container before every run.
  `run_attack_scenario.sh` has always relaunched the PC-side supervisor per
  run; a long-lived container silently removed that, leaking trust scores,
  sliding windows and `response_engine`'s never-cancelled RTH/HOVER latches
  into subsequent runs.
- Pi CPU/RSS/load and link byte counters are sampled over SSH during each
  run. Sampling failures are non-fatal by design — a slow `ps` must not
  destroy an attack run's data.

## Known limitations

- **The ML anomaly layer currently contributes no detection value.** The
  IsolationForest in `models/` was trained with `contamination=0.1`, which by
  construction puts ~10% of its own training distribution below the decision
  threshold, and `models/training_report.json` records `targets_met=false`
  with 0% detection for `gps_position_spoof`, `gps_frozen` and
  `command_injection`. Replaying all 43 logged flights through it measured
  916 anomalies across 88409 clean windows and **0 across 1200 attack
  windows** — i.e. every hit observed to date is a false positive.
  `ml_confidence_min` (trust_config.yaml) gates the penalty so those cannot
  move a trust score; the detector still runs, publishes and logs, so a
  retrained model resumes contributing with no code change. Retraining on
  data that covers dynamic flight is the real fix and is Phase 10 work.
- All detection that currently works is `trust_engine`'s rule-based physics,
  cross-sensor and temporal checks.
- `security_msgs` custom interfaces are still not defined; the JSON envelope
  has been sufficient.
- The checked-in `config/chacha20_key.hex` is a development key. A real
  deployment must generate its own, keep it 0600, and prefer `$UAV_SEC_KEY`
  so it never touches disk.
- `crypto.drop_replayed` defaults to **false** so the `telemetry_replay`
  scenario still measures `trust_engine`'s own replay detection latency.
  A production build should set it true.
