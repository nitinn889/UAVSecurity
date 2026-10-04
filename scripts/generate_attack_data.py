#!/usr/bin/env python3
"""Generate a labelled training dataset from clean baseline flight logs by
applying five synthetic attack transformations.

Reads: ~/uav_security_ws/data/logs/*.csv (Phase 2 baseline flight logs)
Writes: ~/uav_security_ws/data/training_data.csv
        ~/uav_security_ws/data/training_labels.csv
"""
import glob
import os

import numpy as np
import pandas as pd

WS_ROOT = os.path.expanduser('~/uav_security_ws')
LOG_DIR = os.path.join(WS_ROOT, 'data', 'logs')
OUTPUT_DATA = os.path.join(WS_ROOT, 'data', 'training_data.csv')
OUTPUT_LABELS = os.path.join(WS_ROOT, 'data', 'training_labels.csv')

RNG_SEED = 42
ATTACK_SUBSET_FRACTION = 0.4


def load_clean_data():
    paths = sorted(glob.glob(os.path.join(LOG_DIR, '*.csv')))
    if not paths:
        raise SystemExit(f'No CSV files found in {LOG_DIR}')
    frames = [pd.read_csv(p) for p in paths]
    df = pd.concat(frames, ignore_index=True)
    df['attack_label'] = 0
    return df


def _set_span(df, column, start, span, values):
    arr = df[column].to_numpy().copy()
    arr[start:start + span] = values
    df[column] = arr


def _mark_attacked(df, start, span):
    labels = df['attack_label'].to_numpy().copy()
    labels[start:start + span] = 1
    df['attack_label'] = labels


# ----------------------------------------------------------------------
# Attack transformations. Each takes a clean DataFrame and returns a
# modified copy with 'attack_label' set to 1 for affected rows.
# ----------------------------------------------------------------------
def gps_position_spoof(df, magnitude_m=50.0, rng=None):
    rng = rng or np.random.default_rng()
    df = df.copy()
    ramp, hold = 20, 30
    span = ramp + hold
    if len(df) <= span:
        return df

    start = int(rng.integers(0, len(df) - span))
    deg_offset = magnitude_m / 111111.0  # 1 deg latitude ~= 111,111 m
    ramp_offsets = np.concatenate([
        np.linspace(0.0, deg_offset, ramp, endpoint=False),
        np.full(hold, deg_offset),
    ])

    for col in ('gps_lat', 'gps_lon'):
        arr = df[col].to_numpy().copy()
        arr[start:start + span] = arr[start:start + span] + ramp_offsets
        df[col] = arr

    _mark_attacked(df, start, span)
    return df


def gps_velocity_spoof(df, vel_spike=18.0, rng=None):
    rng = rng or np.random.default_rng()
    df = df.copy()
    span = 5
    if len(df) <= span:
        return df

    start = int(rng.integers(0, len(df) - span))
    _set_span(df, 'gps_vel_n', start, span, vel_spike)
    _mark_attacked(df, start, span)
    return df


def gps_frozen(df, freeze_duration=25, rng=None):
    rng = rng or np.random.default_rng()
    df = df.copy()
    span = freeze_duration
    if len(df) <= span:
        return df

    start = int(rng.integers(0, len(df) - span))
    for col in ('gps_lat', 'gps_lon', 'gps_alt'):
        frozen_value = df[col].to_numpy()[start]
        _set_span(df, col, start, span, frozen_value)
    # local_vx/local_vy are intentionally left untouched: the vehicle keeps
    # moving while the GPS reading itself is frozen.
    _mark_attacked(df, start, span)
    return df


def command_injection(df, n_injections=15, rng=None):
    """Each injected row is a discrete, single-row event (unlike the
    continuous-span attacks above), so scattering them at random positions
    is both spec-compliant and harmless to the temporal contiguity that
    neighbouring windows depend on."""
    rng = rng or np.random.default_rng()
    df = df.copy()
    if len(df) == 0:
        return df

    template_idx = rng.integers(0, len(df), size=n_injections)
    injected_rows = df.iloc[template_idx].copy().reset_index(drop=True)
    injected_rows['last_cmd_id'] = 999
    injected_rows['last_cmd_param1'] = 0.0
    injected_rows['last_cmd_param2'] = 0.0
    injected_rows['attack_label'] = 1

    insert_positions = sorted(int(p) for p in rng.integers(0, len(df) + 1, size=n_injections))

    pieces = []
    prev = 0
    for i, pos in enumerate(insert_positions):
        pieces.append(df.iloc[prev:pos])
        pieces.append(injected_rows.iloc[[i]])
        prev = pos
    pieces.append(df.iloc[prev:])

    return pd.concat(pieces, ignore_index=True)


def sensor_noise_amplification(df, scale=8.0, rng=None):
    rng = rng or np.random.default_rng()
    df = df.copy()
    span = 10
    if len(df) <= span:
        return df

    start = int(rng.integers(0, len(df) - span))
    for col in ('imu_ax', 'imu_ay', 'imu_az'):
        arr = df[col].to_numpy().copy()
        arr[start:start + span] = arr[start:start + span] * scale
        df[col] = arr

    _mark_attacked(df, start, span)
    return df


ATTACKS = [
    ('gps_position_spoof', gps_position_spoof),
    ('gps_velocity_spoof', gps_velocity_spoof),
    ('gps_frozen', gps_frozen),
    ('command_injection', command_injection),
    ('sensor_noise_amplification', sensor_noise_amplification),
]


def make_attack_variant(clean_df, attack_fn, rng):
    """Take a random *contiguous* 40% slice of clean_df, attack it, and
    recombine with the untouched remaining 60% to produce a full-size
    'mostly clean, one attack signature embedded' variant.

    NOTE on the "shuffle" instruction: sampling a scattered random 40% of
    individual rows (rather than a contiguous slice) — or shuffling row
    order afterwards — would destroy the temporal contiguity that both the
    attack functions themselves (e.g. "25 consecutive frozen rows") and
    Task 3's sliding-window feature extraction ("every window of 30
    consecutive rows") depend on. Resolved by keeping each block's row
    order intact; only the subset's *position* within the flight log is
    randomized, and the concatenation order of the five attack-type blocks
    (in main()) is randomized instead of shuffling individual rows.
    """
    n = len(clean_df)
    subset_size = int(round(n * ATTACK_SUBSET_FRACTION))
    start = int(rng.integers(0, n - subset_size + 1))

    subset = clean_df.iloc[start:start + subset_size].reset_index(drop=True)
    remainder = pd.concat(
        [clean_df.iloc[:start], clean_df.iloc[start + subset_size:]],
        ignore_index=True)

    attacked_subset = attack_fn(subset, rng=rng)

    return pd.concat([attacked_subset, remainder], ignore_index=True)


def main():
    rng = np.random.default_rng(RNG_SEED)
    clean_df = load_clean_data()

    variants = {}
    for name, fn in ATTACKS:
        variants[name] = make_attack_variant(clean_df, fn, rng)

    # Randomize the order the six blocks (clean + 5 attack variants) are
    # concatenated in, but keep each block's own row order intact — see the
    # contiguity note in make_attack_variant().
    blocks = [clean_df] + list(variants.values())
    block_order = rng.permutation(len(blocks))
    combined = pd.concat([blocks[i] for i in block_order], ignore_index=True)

    os.makedirs(os.path.dirname(OUTPUT_DATA), exist_ok=True)
    combined.to_csv(OUTPUT_DATA, index=False)
    combined[['attack_label']].to_csv(OUTPUT_LABELS, index=False)

    total_rows = len(combined)
    attacked_rows = int(combined['attack_label'].sum())
    clean_rows = total_rows - attacked_rows

    print(f'Loaded {len(clean_df)} clean rows from {LOG_DIR}')
    print(f'\nWrote {OUTPUT_DATA}')
    print(f'  total rows:    {total_rows}')
    print(f'  clean rows:    {clean_rows}')
    print(f'  attacked rows: {attacked_rows}')
    print('\nBreakdown by attack type (rows flagged attack_label=1 within '
          "that attack's own variant):")
    for name, variant_df in variants.items():
        n_flagged = int(variant_df['attack_label'].sum())
        print(f'  {name:<28} variant_rows={len(variant_df):>5}  attacked_rows={n_flagged}')

    print(f'\nWrote {OUTPUT_LABELS} ({total_rows} rows)')


if __name__ == '__main__':
    main()
