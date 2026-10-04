"""Feature engineering for the ML anomaly detector (Phase 4).

FeatureEngineer is a plain Python class (no ROS dependency) so it is
unit-testable standalone and reusable by both the offline training script
(train_anomaly_detector.py) and the live AnomalyDetector.
"""
from typing import List, Optional

import numpy as np

FEATURE_NAMES = [
    # --- Instantaneous (from the latest snapshot) ---
    'gps_horiz_speed',
    'gps_vert_speed',
    'gps_baro_alt_diff',
    'ekf_gps_vel_diff',
    'accel_magnitude',
    'gyro_magnitude',
    'baro_pressure',
    'attitude_roll_abs',
    'attitude_pitch_abs',
    # --- Window (over the last window_size snapshots) ---
    'gps_lat_std',
    'gps_lon_std',
    'gps_alt_std',
    'gps_horiz_speed_mean',
    'gps_horiz_speed_std',
    'accel_magnitude_std',
    'gyro_magnitude_std',
    'baro_alt_std',
    'gps_baro_diff_std',
    'ekf_vel_diff_mean',
    # --- Delta (latest minus previous snapshot) ---
    'gps_lat_delta',
    'gps_lon_delta',
    'gps_alt_delta',
    'accel_delta',
]


def _get(section: Optional[dict], key: str) -> Optional[float]:
    if section is None:
        return None
    val = section.get(key)
    return float(val) if val is not None else None


def _series(rows: List[Optional[dict]], key: str) -> List[float]:
    """Extract one nested-dict key across a list of snapshot sections,
    dropping missing/None entries."""
    out = []
    for section in rows:
        val = _get(section, key)
        if val is not None:
            out.append(val)
    return out


class FeatureEngineer:
    feature_names = FEATURE_NAMES
    window_size = 30

    def compute(self, window: List[dict]) -> Optional[np.ndarray]:
        if window is None or len(window) < 2:
            return None

        latest = window[-1]
        previous = window[-2]

        gps_latest = latest.get('gps')
        local_latest = latest.get('local_pos')
        imu_latest = latest.get('imu')
        baro_latest = latest.get('baro')
        att_latest = latest.get('attitude')

        gps_prev = previous.get('gps')
        imu_prev = previous.get('imu')

        # --- Instantaneous ---
        vel_n = _get(gps_latest, 'vel_n') or 0.0
        vel_e = _get(gps_latest, 'vel_e') or 0.0
        vel_d = _get(gps_latest, 'vel_d') or 0.0
        gps_alt = _get(gps_latest, 'alt') or 0.0
        baro_alt = _get(baro_latest, 'altitude') or 0.0
        local_vx = _get(local_latest, 'vx') or 0.0
        local_vy = _get(local_latest, 'vy') or 0.0
        ax = _get(imu_latest, 'ax') or 0.0
        ay = _get(imu_latest, 'ay') or 0.0
        az = _get(imu_latest, 'az') or 0.0
        gx = _get(imu_latest, 'gx') or 0.0
        gy = _get(imu_latest, 'gy') or 0.0
        gz = _get(imu_latest, 'gz') or 0.0
        baro_pressure = _get(baro_latest, 'pressure') or 0.0
        roll = _get(att_latest, 'roll') or 0.0
        pitch = _get(att_latest, 'pitch') or 0.0

        gps_horiz_speed = float(np.hypot(vel_n, vel_e))
        gps_vert_speed = abs(vel_d)
        gps_baro_alt_diff = gps_alt - baro_alt
        ekf_gps_vel_diff = float(np.hypot(vel_n - local_vx, vel_e - local_vy))
        accel_magnitude = float(np.sqrt(ax * ax + ay * ay + az * az))
        gyro_magnitude = float(np.sqrt(gx * gx + gy * gy + gz * gz))
        attitude_roll_abs = abs(roll)
        attitude_pitch_abs = abs(pitch)

        # --- Window series ---
        gps_sections = [s.get('gps') for s in window]
        local_sections = [s.get('local_pos') for s in window]
        imu_sections = [s.get('imu') for s in window]
        baro_sections = [s.get('baro') for s in window]

        lats = _series(gps_sections, 'lat')
        lons = _series(gps_sections, 'lon')
        alts = _series(gps_sections, 'alt')
        baro_alts = _series(baro_sections, 'altitude')

        horiz_speeds = []
        accel_mags = []
        gyro_mags = []
        gps_baro_diffs = []
        ekf_vel_diffs = []
        for gps_s, local_s, imu_s, baro_s in zip(
                gps_sections, local_sections, imu_sections, baro_sections):
            vn = _get(gps_s, 'vel_n')
            ve = _get(gps_s, 'vel_e')
            if vn is not None and ve is not None:
                horiz_speeds.append(float(np.hypot(vn, ve)))

            iax, iay, iaz = _get(imu_s, 'ax'), _get(imu_s, 'ay'), _get(imu_s, 'az')
            if None not in (iax, iay, iaz):
                accel_mags.append(float(np.sqrt(iax * iax + iay * iay + iaz * iaz)))

            igx, igy, igz = _get(imu_s, 'gx'), _get(imu_s, 'gy'), _get(imu_s, 'gz')
            if None not in (igx, igy, igz):
                gyro_mags.append(float(np.sqrt(igx * igx + igy * igy + igz * igz)))

            g_alt, b_alt = _get(gps_s, 'alt'), _get(baro_s, 'altitude')
            if g_alt is not None and b_alt is not None:
                gps_baro_diffs.append(g_alt - b_alt)

            lvx, lvy = _get(local_s, 'vx'), _get(local_s, 'vy')
            if None not in (vn, ve, lvx, lvy):
                ekf_vel_diffs.append(float(np.hypot(vn - lvx, ve - lvy)))

        def _std(values):
            return float(np.std(values)) if values else 0.0

        def _mean(values):
            return float(np.mean(values)) if values else 0.0

        gps_lat_std = _std(lats)
        gps_lon_std = _std(lons)
        gps_alt_std = _std(alts)
        gps_horiz_speed_mean = _mean(horiz_speeds)
        gps_horiz_speed_std = _std(horiz_speeds)
        accel_magnitude_std = _std(accel_mags)
        gyro_magnitude_std = _std(gyro_mags)
        baro_alt_std = _std(baro_alts)
        gps_baro_diff_std = _std(gps_baro_diffs)
        ekf_vel_diff_mean = _mean(ekf_vel_diffs)

        # --- Delta (latest vs. previous snapshot) ---
        lat_latest, lat_prev = _get(gps_latest, 'lat'), _get(gps_prev, 'lat')
        lon_latest, lon_prev = _get(gps_latest, 'lon'), _get(gps_prev, 'lon')
        alt_latest, alt_prev = _get(gps_latest, 'alt'), _get(gps_prev, 'alt')

        gps_lat_delta = (lat_latest - lat_prev) if None not in (lat_latest, lat_prev) else 0.0
        gps_lon_delta = (lon_latest - lon_prev) if None not in (lon_latest, lon_prev) else 0.0
        gps_alt_delta = (alt_latest - alt_prev) if None not in (alt_latest, alt_prev) else 0.0

        iax_prev, iay_prev, iaz_prev = _get(imu_prev, 'ax'), _get(imu_prev, 'ay'), _get(imu_prev, 'az')
        if None not in (iax_prev, iay_prev, iaz_prev):
            accel_magnitude_prev = float(np.sqrt(
                iax_prev * iax_prev + iay_prev * iay_prev + iaz_prev * iaz_prev))
            accel_delta = accel_magnitude - accel_magnitude_prev
        else:
            accel_delta = 0.0

        vector = [
            gps_horiz_speed, gps_vert_speed, gps_baro_alt_diff, ekf_gps_vel_diff,
            accel_magnitude, gyro_magnitude, baro_pressure,
            attitude_roll_abs, attitude_pitch_abs,
            gps_lat_std, gps_lon_std, gps_alt_std,
            gps_horiz_speed_mean, gps_horiz_speed_std,
            accel_magnitude_std, gyro_magnitude_std,
            baro_alt_std, gps_baro_diff_std, ekf_vel_diff_mean,
            gps_lat_delta, gps_lon_delta, gps_alt_delta, accel_delta,
        ]

        assert len(vector) == len(FEATURE_NAMES)
        return np.array(vector, dtype=np.float32)
