"""Dynamic per-component trust scoring engine (Phase 3).

TrustEngine is a plain Python class (no ROS 2 dependency) so it can be unit
tested without a running ROS 2 environment. It is driven by supervisor_node,
which feeds it parsed /security/sensor_snapshot dicts and republishes the
resulting TrustReport on /security/trust_scores and /security/status.

Design note on EMA smoothing vs. single-event decay:
  The canonical per-component score reacts directly and immediately to a
  detected anomaly (matching the spec's framing of physics checks as "hard
  rules, immediate"). EMA(alpha=ema_alpha) is applied separately, only to a
  status-hysteresis score used for the human-readable TRUSTED/DEGRADED/
  UNTRUSTED label, to prevent that label from flapping on borderline scores.
  Blending the canonical score itself toward its own history via EMA would
  mathematically cap a single update's drop at (1 - ema_alpha) * old_score
  (e.g. 0.7 when old_score=1.0 and ema_alpha=0.3) no matter how severe the
  underlying violation is — which would make it impossible for one severe
  event to ever pull a fresh score below that floor.
"""
import math
import os
import time
from collections import deque
from dataclasses import dataclass, field
from typing import Dict, List, Optional

import yaml

DEFAULT_CONFIG_PATH = os.path.expanduser('~/uav_security_ws/config/trust_config.yaml')

COMPONENTS = ('gps', 'imu', 'barometer', 'attitude', 'commands')

EARTH_RADIUS_M = 6371000.0

ARMING_STATE_ARMED = 2  # px4_msgs.msg.VehicleStatus.ARMING_STATE_ARMED


def haversine_m(lat1, lon1, lat2, lon2):
    """Great-circle distance between two lat/lon points, in meters."""
    phi1, phi2 = math.radians(lat1), math.radians(lat2)
    dphi = math.radians(lat2 - lat1)
    dlambda = math.radians(lon2 - lon1)
    a = math.sin(dphi / 2.0) ** 2 + math.cos(phi1) * math.cos(phi2) * math.sin(dlambda / 2.0) ** 2
    return 2.0 * EARTH_RADIUS_M * math.asin(min(1.0, math.sqrt(a)))


def wrap_angle(angle_rad):
    """Wrap an angle to (-pi, pi] to avoid false deltas across the +/-pi seam."""
    return math.atan2(math.sin(angle_rad), math.cos(angle_rad))


def rolling_std(values):
    n = len(values)
    if n < 2:
        return 0.0
    mean = sum(values) / n
    variance = sum((v - mean) ** 2 for v in values) / n
    return math.sqrt(variance)


def ratio_severity(value, threshold, moderate_ratio, severe_ratio):
    """Classify a magnitude-based violation by how many multiples of the
    threshold it reaches. Used for continuous rate/delta/magnitude checks."""
    if threshold <= 0:
        return 'severe'
    ratio = abs(value) / threshold
    if ratio >= severe_ratio:
        return 'severe'
    if ratio >= moderate_ratio:
        return 'moderate'
    return 'minor'


@dataclass
class AnomalyFlag:
    component: str    # 'gps' | 'imu' | 'barometer' | 'attitude' | 'commands'
    check_type: str   # 'physics' | 'cross_sensor' | 'temporal'
    severity: str      # 'minor' | 'moderate' | 'severe'
    reason: str
    value: float
    threshold: float


@dataclass
class TrustReport:
    scores: Dict[str, float]
    flags: List[AnomalyFlag]
    overall_trust: float
    timestamp_us: int


def _load_config(path):
    with open(path, 'r') as handle:
        return yaml.safe_load(handle)


class TrustEngine:
    def __init__(self, config_path: Optional[str] = None):
        self.config_path = config_path or DEFAULT_CONFIG_PATH
        self.cfg = _load_config(self.config_path)

        self.scores = {c: self.cfg['initial_score'] for c in COMPONENTS}
        # EMA-smoothed score used only for /security/status hysteresis.
        self.status_scores = dict(self.scores)

        self.prev = None  # previous snapshot's fields needed for delta checks
        self.start_timestamp_us = None

        window = self.cfg['temporal_window_size']
        self.windows = {
            'gps_lat': deque(maxlen=window),
            'gps_lon': deque(maxlen=window),
            'gps_alt': deque(maxlen=window),
            'baro_alt': deque(maxlen=window),
            'imu_ax': deque(maxlen=window),
            'imu_ay': deque(maxlen=window),
            'imu_az': deque(maxlen=window),
            'accel_mag': deque(maxlen=window),
        }

        self._gps_frozen_consecutive = 0
        self._command_history = []  # list of (timestamp_us, command_id)
        self._commands_seen_warmup = set()
        self._last_command_key = None
        self._last_invalid_command_ts = None  # Phase 6 Task 5 flood-recovery

        # Phase 5 GPS staleness detection state (see _temporal_gps_staleness).
        self._last_snapshot_ts = None
        self._last_gps_value_key = None
        self._gps_stale_since_wall = None

    # ------------------------------------------------------------------
    def update(self, snapshot: dict) -> TrustReport:
        ts = snapshot.get('timestamp_us', 0)
        if self.start_timestamp_us is None:
            self.start_timestamp_us = ts

        flags: List[AnomalyFlag] = []
        deltas = {c: 0.0 for c in COMPONENTS}

        # Command dedup is computed once here and shared by both the physics
        # whitelist check and the temporal flood/warmup checks. Without this,
        # a command that stays cached in the snapshot's last_command field
        # (because nothing newer has arrived) would get re-flagged as a
        # fresh violation on every single update -- severe decay every
        # cycle, forever, completely overwhelming the recovery rate and
        # permanently pinning the commands score at 0 even long after the
        # actual command stream (e.g. a flood attack) has stopped.
        new_command = self._dedupe_command(snapshot.get('last_command'), ts)

        self._physics_checks(snapshot, ts, new_command, flags, deltas)
        self._cross_sensor_checks(snapshot, ts, flags, deltas)
        self._temporal_checks(snapshot, ts, new_command, flags, deltas)

        cfg = self.cfg
        for component in COMPONENTS:
            if deltas[component] != 0.0:
                new_score = self.scores[component] + deltas[component]
            else:
                new_score = self.scores[component] + cfg['recovery_rate']
            self.scores[component] = min(cfg['score_max'], max(cfg['score_min'], new_score))

        alpha = cfg['ema_alpha']
        for component in COMPONENTS:
            self.status_scores[component] = (
                alpha * self.scores[component] + (1.0 - alpha) * self.status_scores[component])

        self._update_prev(snapshot, ts)

        overall = min(self.scores.values())
        return TrustReport(
            scores=dict(self.scores), flags=flags, overall_trust=overall, timestamp_us=ts)

    def _dedupe_command(self, cmd, ts):
        """Returns cmd if it represents a genuinely NEW command arrival this
        cycle (by msg_timestamp, falling back to the (command, param1,
        param2) tuple), else None -- including when cmd is None or the same
        cached command as last cycle."""
        if not cmd or cmd.get('command') is None:
            return None

        dedupe_key = cmd.get('msg_timestamp')
        if dedupe_key is None:
            dedupe_key = (cmd.get('command'), cmd.get('param1'), cmd.get('param2'))

        if dedupe_key == self._last_command_key:
            return None

        self._last_command_key = dedupe_key
        return cmd

    def status_label(self, score: float) -> str:
        cfg = self.cfg
        if score < cfg['status_untrusted_max']:
            return 'UNTRUSTED'
        if score > cfg['status_trusted_min']:
            return 'TRUSTED'
        return 'DEGRADED'

    # ------------------------------------------------------------------
    # Task 2: physics-based consistency checks (hard rules, immediate)
    # ------------------------------------------------------------------
    def _physics_checks(self, snap, ts, new_command, flags, deltas):
        cfg = self.cfg
        gps = snap.get('gps')
        imu = snap.get('imu')
        baro = snap.get('baro')
        prev = self.prev

        if gps:
            self._physics_gps(gps, ts, prev, flags, deltas)
        if imu:
            self._physics_imu(imu, flags, deltas)
        if baro:
            self._physics_baro(baro, prev, flags, deltas)
        if new_command is not None:
            self._physics_commands(new_command, flags, deltas)

    def _physics_gps(self, gps, ts, prev, flags, deltas):
        cfg = self.cfg
        vel_n, vel_e, vel_d = gps.get('vel_n'), gps.get('vel_e'), gps.get('vel_d')
        lat, lon, alt = gps.get('lat'), gps.get('lon'), gps.get('alt')

        reported_speed = math.hypot(vel_n or 0.0, vel_e or 0.0)
        implied_speed = None
        speed_source = 'reported'

        if (prev and prev.get('gps_lat') is not None and lat is not None
                and prev.get('ts') is not None):
            dt = (ts - prev['ts']) / 1e6
            if dt > 0:
                dist = haversine_m(prev['gps_lat'], prev['gps_lon'], lat, lon)
                implied_speed = dist / dt

                if dist > cfg['gps_max_pos_jump']:
                    sev = ratio_severity(dist, cfg['gps_max_pos_jump'], cfg['ratio_moderate'], cfg['ratio_severe'])
                    flags.append(AnomalyFlag('gps', 'physics', sev,
                        f'GPS position jumped {dist:.1f} m between updates',
                        dist, cfg['gps_max_pos_jump']))
                    deltas['gps'] += cfg[f'decay_{sev}']

                if prev.get('gps_alt') is not None and alt is not None:
                    dalt = abs(alt - prev['gps_alt'])
                    if dalt > cfg['gps_max_alt_jump']:
                        sev = ratio_severity(dalt, cfg['gps_max_alt_jump'], cfg['ratio_moderate'], cfg['ratio_severe'])
                        flags.append(AnomalyFlag('gps', 'physics', sev,
                            f'GPS altitude jumped {dalt:.1f} m between updates',
                            dalt, cfg['gps_max_alt_jump']))
                        deltas['gps'] += cfg[f'decay_{sev}']

        # Effective horizontal speed = max(receiver-reported, implied from a
        # position jump). A spoofer that keeps vel_n/vel_e "sane" while the
        # reported position itself jumps is still an impossible-speed event.
        effective_speed = max(reported_speed, implied_speed or 0.0)
        if implied_speed and implied_speed > reported_speed:
            speed_source = 'implied from position delta'
        if effective_speed > cfg['gps_max_horiz_speed']:
            sev = ratio_severity(effective_speed, cfg['gps_max_horiz_speed'], cfg['ratio_moderate'], cfg['ratio_severe'])
            flags.append(AnomalyFlag('gps', 'physics', sev,
                f'GPS horizontal speed {effective_speed:.1f} m/s ({speed_source}) exceeds max',
                effective_speed, cfg['gps_max_horiz_speed']))
            deltas['gps'] += cfg[f'decay_{sev}']

        if vel_d is not None and abs(vel_d) > cfg['gps_max_vert_speed']:
            sev = ratio_severity(vel_d, cfg['gps_max_vert_speed'], cfg['ratio_moderate'], cfg['ratio_severe'])
            flags.append(AnomalyFlag('gps', 'physics', sev,
                f'GPS vertical speed {vel_d:.1f} m/s exceeds max',
                abs(vel_d), cfg['gps_max_vert_speed']))
            deltas['gps'] += cfg[f'decay_{sev}']

    def _physics_imu(self, imu, flags, deltas):
        cfg = self.cfg
        ax, ay, az = imu.get('ax'), imu.get('ay'), imu.get('az')
        gx, gy, gz = imu.get('gx'), imu.get('gy'), imu.get('gz')

        if None not in (ax, ay, az):
            amag = math.sqrt(ax * ax + ay * ay + az * az)
            if amag < cfg['imu_accel_min'] or amag > cfg['imu_accel_max']:
                bound = cfg['imu_accel_min'] if amag < cfg['imu_accel_min'] else cfg['imu_accel_max']
                # A physically-impossible accel magnitude (free-fall / crash)
                # is always treated as severe, not ratio-tiered.
                flags.append(AnomalyFlag('imu', 'physics', 'severe',
                    f'IMU accel magnitude {amag:.2f} m/s^2 outside '
                    f'[{cfg["imu_accel_min"]}, {cfg["imu_accel_max"]}]',
                    amag, bound))
                deltas['imu'] += cfg['decay_severe']

        if None not in (gx, gy, gz):
            gmag = math.sqrt(gx * gx + gy * gy + gz * gz)
            if gmag > cfg['imu_gyro_max']:
                sev = ratio_severity(gmag, cfg['imu_gyro_max'], cfg['ratio_moderate'], cfg['ratio_severe'])
                flags.append(AnomalyFlag('imu', 'physics', sev,
                    f'IMU gyro magnitude {gmag:.2f} rad/s exceeds max',
                    gmag, cfg['imu_gyro_max']))
                deltas['imu'] += cfg[f'decay_{sev}']

    def _physics_baro(self, baro, prev, flags, deltas):
        cfg = self.cfg
        pressure = baro.get('pressure')
        if pressure is None:
            return

        if pressure < cfg['baro_pressure_min'] or pressure > cfg['baro_pressure_max']:
            bound = cfg['baro_pressure_min'] if pressure < cfg['baro_pressure_min'] else cfg['baro_pressure_max']
            flags.append(AnomalyFlag('barometer', 'physics', 'severe',
                f'Barometer pressure {pressure:.0f} Pa outside valid range',
                pressure, bound))
            deltas['barometer'] += cfg['decay_severe']

        if prev and prev.get('baro_pressure') is not None:
            dpres = abs(pressure - prev['baro_pressure'])
            if dpres > cfg['baro_max_delta']:
                sev = ratio_severity(dpres, cfg['baro_max_delta'], cfg['ratio_moderate'], cfg['ratio_severe'])
                flags.append(AnomalyFlag('barometer', 'physics', sev,
                    f'Barometer pressure changed {dpres:.0f} Pa between updates',
                    dpres, cfg['baro_max_delta']))
                deltas['barometer'] += cfg[f'decay_{sev}']

    def _physics_commands(self, cmd, flags, deltas):
        cfg = self.cfg
        cid = int(cmd['command'])

        if cid not in cfg['allowed_command_ids']:
            flags.append(AnomalyFlag('commands', 'physics', 'severe',
                f'Command id {cid} not in allowed whitelist',
                float(cid), 0.0))
            deltas['commands'] += cfg['decay_severe']

        if cid == cfg['arm_command_id']:
            p1 = cmd.get('param1')
            if p1 is not None and round(p1, 3) not in tuple(cfg['arm_valid_param1']):
                flags.append(AnomalyFlag('commands', 'physics', 'severe',
                    f'ARM/DISARM command has invalid param1={p1}',
                    float(p1), 0.0))
                deltas['commands'] += cfg['decay_severe']

    # ------------------------------------------------------------------
    # Task 3: cross-sensor consistency checks
    # ------------------------------------------------------------------
    def _cross_sensor_checks(self, snap, ts, flags, deltas):
        cfg = self.cfg
        gps = snap.get('gps')
        baro = snap.get('baro')
        local = snap.get('local_pos')
        att = snap.get('attitude')
        prev = self.prev

        if gps and baro and gps.get('alt') is not None and baro.get('altitude') is not None:
            err = abs(gps['alt'] - baro['altitude'])
            if err > cfg['cross_gps_baro_alt_thresh']:
                if err > cfg['cross_gps_baro_alt_severe']:
                    sev = 'severe'
                elif err > cfg['cross_gps_baro_alt_moderate']:
                    sev = 'moderate'
                else:
                    sev = 'minor'
                flags.append(AnomalyFlag('gps', 'cross_sensor', sev,
                    f'GPS altitude deviates {err:.1f}m from barometer',
                    err, cfg['cross_gps_baro_alt_thresh']))
                deltas['gps'] += cfg[f'decay_{sev}']

        if gps and local and None not in (gps.get('vel_n'), gps.get('vel_e'), local.get('vx'), local.get('vy')):
            disagreement = math.hypot(gps['vel_n'] - local['vx'], gps['vel_e'] - local['vy'])
            if disagreement > cfg['cross_gps_ekf_vel_thresh']:
                flags.append(AnomalyFlag('gps', 'cross_sensor', 'moderate',
                    f'GPS velocity disagrees with EKF by {disagreement:.2f} m/s',
                    disagreement, cfg['cross_gps_ekf_vel_thresh']))
                deltas['gps'] += cfg['decay_moderate']

        if (att and prev and prev.get('att_roll') is not None
                and None not in (att.get('roll'), att.get('pitch'), att.get('yaw'),
                                  att.get('roll_rate'), att.get('pitch_rate'), att.get('yaw_rate'))
                and prev.get('ts') is not None):
            dt = (ts - prev['ts']) / 1e6
            if dt > 0:
                droll_expected = att['roll_rate'] * dt
                dpitch_expected = att['pitch_rate'] * dt
                dyaw_expected = att['yaw_rate'] * dt

                droll_actual = wrap_angle(att['roll'] - prev['att_roll'])
                dpitch_actual = wrap_angle(att['pitch'] - prev['att_pitch'])
                dyaw_actual = wrap_angle(att['yaw'] - prev['att_yaw'])

                disagreement = math.sqrt(
                    (droll_actual - droll_expected) ** 2
                    + (dpitch_actual - dpitch_expected) ** 2
                    + (dyaw_actual - dyaw_expected) ** 2)

                if disagreement > cfg['cross_att_imu_severe']:
                    flags.append(AnomalyFlag('attitude', 'cross_sensor', 'severe',
                        f'Attitude/IMU disagreement {disagreement:.2f} rad',
                        disagreement, cfg['cross_att_imu_severe']))
                    flags.append(AnomalyFlag('imu', 'cross_sensor', 'severe',
                        f'Attitude/IMU disagreement {disagreement:.2f} rad',
                        disagreement, cfg['cross_att_imu_severe']))
                    deltas['attitude'] += cfg['decay_severe']
                    deltas['imu'] += cfg['decay_severe']
                elif disagreement > cfg['cross_att_imu_thresh']:
                    flags.append(AnomalyFlag('attitude', 'cross_sensor', 'minor',
                        f'Attitude/IMU disagreement {disagreement:.2f} rad',
                        disagreement, cfg['cross_att_imu_thresh']))
                    deltas['attitude'] += cfg['decay_minor']

    # ------------------------------------------------------------------
    # Task 4: temporal pattern analysis (sliding window)
    # ------------------------------------------------------------------
    def _temporal_checks(self, snap, ts, new_command, flags, deltas):
        cfg = self.cfg
        gps = snap.get('gps')
        imu = snap.get('imu')
        local = snap.get('local_pos')
        baro = snap.get('baro')
        vstatus = snap.get('vehicle_status')

        armed = vstatus is not None and vstatus.get('arming_state') == ARMING_STATE_ARMED
        moving = False
        if local and local.get('vx') is not None and local.get('vy') is not None:
            moving = (local['vx'] ** 2 + local['vy'] ** 2) > cfg['temporal_gps_moving_speed_sq_thresh']

        self._update_windows(gps, imu, baro)
        self._temporal_gps_staleness(snap, ts, flags, deltas)
        self._temporal_gps_frozen(armed, moving, flags, deltas)
        self._temporal_gps_alt_drift(flags, deltas)
        self._temporal_imu_frozen(armed, flags, deltas)
        self._temporal_imu_hover_bias(armed, local, flags, deltas)
        self._temporal_commands(new_command, ts, flags, deltas)

    def _temporal_gps_staleness(self, snap, ts, flags, deltas):
        """Phase 5: detect an interrupted or replayed GPS data stream.

        Two independent attack signatures need catching with one check:
          - gps_deny (no new messages at all) and gps_freeze (identical
            values re-stamped with the current time): the GPS *values*
            (lat/lon/alt) stop changing while the outer snapshot timestamp
            (sensor_monitor's own publish-time clock) keeps advancing
            normally. Caught by tracking whether the GPS value tuple changed.
          - telemetry_replay: the injector loops a several-second buffer of
            *previously real* snapshots. Within one loop pass the replayed
            timestamps still increase locally (they're just an old,
            genuinely-recorded sequence), so comparing only against the
            immediately preceding call's timestamp only catches the single
            tick where the loop wraps back to its start -- a blip that
            clears itself on the very next (locally-increasing) tick and
            never accumulates past the staleness threshold. Comparing
            against the highest timestamp *ever seen* instead works: once
            replay starts, every buffered timestamp is from before the
            attack began, so every tick stays behind that high-water mark
            for the entire attack, continuously, until live data resumes.
        Either signal starts the stale-timer; a wall clock independent of
        the (attacker-controlled) snapshot timestamp measures how long
        we've been stuck, since a replayed snapshot's own timestamp can't
        be trusted to measure its own staleness.
        """
        cfg = self.cfg
        now_wall = time.monotonic()
        gps = snap.get('gps')

        is_first_call = self._last_snapshot_ts is None

        non_monotonic = (not is_first_call and ts is not None
                          and ts <= self._last_snapshot_ts)
        if ts is not None and (self._last_snapshot_ts is None or ts > self._last_snapshot_ts):
            self._last_snapshot_ts = ts

        gps_key = (gps.get('lat'), gps.get('lon'), gps.get('alt')) if gps else None
        gps_unchanged = (not is_first_call and gps_key is not None
                         and gps_key == self._last_gps_value_key)
        if gps_key is not None:
            self._last_gps_value_key = gps_key

        stalled = non_monotonic or gps_unchanged

        if stalled:
            if self._gps_stale_since_wall is None:
                self._gps_stale_since_wall = now_wall
        else:
            self._gps_stale_since_wall = None

        if self._gps_stale_since_wall is not None:
            stale_s = now_wall - self._gps_stale_since_wall
            if stale_s * 1e6 > cfg['gps_stale_thresh_us']:
                flags.append(AnomalyFlag('gps', 'temporal', 'severe',
                    f'GPS data stream interrupted -- no update for {stale_s:.1f}s',
                    stale_s, cfg['gps_stale_thresh_us'] / 1e6))
                deltas['gps'] += cfg['decay_severe']

    def _update_windows(self, gps, imu, baro):
        if gps and gps.get('lat') is not None and gps.get('lon') is not None:
            self.windows['gps_lat'].append(gps['lat'])
            self.windows['gps_lon'].append(gps['lon'])
        if gps and gps.get('alt') is not None:
            self.windows['gps_alt'].append(gps['alt'])
        if baro and baro.get('altitude') is not None:
            self.windows['baro_alt'].append(baro['altitude'])
        if imu:
            ax, ay, az = imu.get('ax'), imu.get('ay'), imu.get('az')
            if ax is not None:
                self.windows['imu_ax'].append(ax)
            if ay is not None:
                self.windows['imu_ay'].append(ay)
            if az is not None:
                self.windows['imu_az'].append(az)
            if None not in (ax, ay, az):
                self.windows['accel_mag'].append(math.sqrt(ax * ax + ay * ay + az * az))

    def _temporal_gps_frozen(self, armed, moving, flags, deltas):
        cfg = self.cfg
        if armed and moving and len(self.windows['gps_lat']) >= 1:
            lat_std = rolling_std(self.windows['gps_lat'])
            lon_std = rolling_std(self.windows['gps_lon'])
            if lat_std < cfg['temporal_gps_frozen_thresh'] and lon_std < cfg['temporal_gps_frozen_thresh']:
                self._gps_frozen_consecutive += 1
            else:
                self._gps_frozen_consecutive = 0
        else:
            self._gps_frozen_consecutive = 0

        if self._gps_frozen_consecutive > cfg['temporal_gps_frozen_min_consecutive']:
            flags.append(AnomalyFlag('gps', 'temporal', 'severe',
                f'GPS position frozen for {self._gps_frozen_consecutive} '
                f'consecutive updates while armed and moving',
                float(self._gps_frozen_consecutive),
                float(cfg['temporal_gps_frozen_min_consecutive'])))
            deltas['gps'] += cfg['decay_severe']

    def _temporal_gps_alt_drift(self, flags, deltas):
        cfg = self.cfg
        if len(self.windows['gps_alt']) >= 2 and len(self.windows['baro_alt']) >= 2:
            gps_mean = sum(self.windows['gps_alt']) / len(self.windows['gps_alt'])
            baro_mean = sum(self.windows['baro_alt']) / len(self.windows['baro_alt'])
            drift = abs(gps_mean - baro_mean)
            if drift > cfg['temporal_alt_drift_thresh']:
                flags.append(AnomalyFlag('gps', 'temporal', 'moderate',
                    f'GPS/baro altitude rolling means diverge {drift:.1f}m',
                    drift, cfg['temporal_alt_drift_thresh']))
                deltas['gps'] += cfg['decay_moderate']

    def _temporal_imu_frozen(self, armed, flags, deltas):
        cfg = self.cfg
        if armed and len(self.windows['imu_ax']) >= 2:
            stds = [rolling_std(self.windows[k]) for k in ('imu_ax', 'imu_ay', 'imu_az')]
            if all(s < cfg['temporal_imu_frozen_thresh'] for s in stds):
                flags.append(AnomalyFlag('imu', 'temporal', 'severe',
                    'IMU accelerometer frozen (near-zero variance) while armed',
                    max(stds), cfg['temporal_imu_frozen_thresh']))
                deltas['imu'] += cfg['decay_severe']

    def _temporal_imu_hover_bias(self, armed, local, flags, deltas):
        cfg = self.cfg
        is_hover = (armed and local
                    and None not in (local.get('vx'), local.get('vy'), local.get('vz'))
                    and (local['vx'] ** 2 + local['vy'] ** 2 + local['vz'] ** 2)
                    < cfg['temporal_gps_moving_speed_sq_thresh'])
        if is_hover and len(self.windows['accel_mag']) >= 2:
            mean_mag = sum(self.windows['accel_mag']) / len(self.windows['accel_mag'])
            bias = abs(mean_mag - cfg['gravity_reference'])
            if bias > cfg['temporal_accel_bias_thresh']:
                flags.append(AnomalyFlag('imu', 'temporal', 'moderate',
                    f'IMU accel magnitude bias {bias:.2f} m/s^2 from gravity during hover',
                    bias, cfg['temporal_accel_bias_thresh']))
                deltas['imu'] += cfg['decay_moderate']

    def _temporal_commands(self, new_command, ts, flags, deltas):
        cfg = self.cfg

        # new_command is already deduplicated by _dedupe_command() (called
        # once per update() and shared with the physics check) -- non-None
        # here means this is a genuinely new command arrival this cycle.
        if new_command is not None:
            cid = int(new_command['command'])
            self._command_history.append((ts, cid))

            if cid in cfg['allowed_command_ids']:
                # Whitelisted IDs are expected regardless of when they first
                # appear -- normal flights change mode, land, or RTL well
                # after any short warm-up window, and 821/20 are the
                # supervisor's own mitigation commands (see the whitelist's
                # comment in trust_config.yaml). The warm-up novelty check
                # below exists to catch unexpected/injected IDs, a purpose
                # the whitelist already serves; applying it to whitelisted
                # IDs too just makes every real flight self-flag.
                self._commands_seen_warmup.add(cid)
            else:
                self._last_invalid_command_ts = ts

                in_warmup = (self.start_timestamp_us is not None
                             and (ts - self.start_timestamp_us) <= cfg['flight_warmup_seconds'] * 1e6)
                if in_warmup:
                    self._commands_seen_warmup.add(cid)
                elif cid not in self._commands_seen_warmup:
                    flags.append(AnomalyFlag('commands', 'temporal', 'moderate',
                        f'Command id {cid} not seen during warm-up window',
                        float(cid), 0.0))
                    deltas['commands'] += cfg['decay_moderate']
                    self._commands_seen_warmup.add(cid)  # avoid re-flagging every occurrence

        # Phase 6 Task 5: once temporal_cmd_recovery_quiet_s have passed with
        # no new non-whitelisted command, shrink the flood lookback window so
        # stale invalid commands from an ended attack drain out of the count
        # faster than the original (full) window would allow -- otherwise the
        # flood flag (and the commands score) stays pinned for the full
        # original window even after the attack itself has already stopped.
        quiet_since_invalid = (
            self._last_invalid_command_ts is not None
            and (ts - self._last_invalid_command_ts) > cfg['temporal_cmd_recovery_quiet_s'] * 1e6)
        window_us = ((cfg['temporal_cmd_recovery_window'] if quiet_since_invalid
                      else cfg['temporal_cmd_window']) * 1e6)
        self._command_history = [(t, c) for (t, c) in self._command_history if ts - t <= window_us]
        count = len(self._command_history)
        if count > cfg['temporal_cmd_rate_max']:
            flags.append(AnomalyFlag('commands', 'temporal', 'severe',
                f'{count} commands received in last {window_us / 1e6:.0f}s (flood)',
                float(count), float(cfg['temporal_cmd_rate_max'])))
            deltas['commands'] += cfg['decay_severe']

    # ------------------------------------------------------------------
    def _update_prev(self, snap, ts):
        if self.prev is None:
            self.prev = {}
        gps = snap.get('gps') or {}
        baro = snap.get('baro') or {}
        att = snap.get('attitude') or {}

        self.prev['ts'] = ts
        for key, val in (
            ('gps_lat', gps.get('lat')), ('gps_lon', gps.get('lon')), ('gps_alt', gps.get('alt')),
            ('baro_pressure', baro.get('pressure')),
            ('att_roll', att.get('roll')), ('att_pitch', att.get('pitch')), ('att_yaw', att.get('yaw')),
        ):
            if val is not None:
                self.prev[key] = val
