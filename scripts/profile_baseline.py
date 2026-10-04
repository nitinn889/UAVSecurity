#!/usr/bin/env python3
"""Statistical profile of all baseline flight logs.

Reads every CSV under data/logs/, computes per-column statistics, and writes
data/baseline_profile.json — the reference for "normal" behaviour used by the
trust engine (Phase 3) and anomaly detector (Phase 4).
"""
import csv
import glob
import json
import os
import statistics

WS_ROOT = os.path.expanduser('~/uav_security_ws')
LOG_DIR = os.path.join(WS_ROOT, 'data', 'logs')
PROFILE_PATH = os.path.join(WS_ROOT, 'data', 'baseline_profile.json')

PERCENTILE = 99

# Monotonic sample index, not a behavioural signal — mean/std of it is
# meaningless as a "normal behaviour" reference.
EXCLUDED_COLUMNS = {'timestamp_us'}


def percentile(sorted_values, pct):
    """Linear-interpolated percentile of an already-sorted list."""
    if not sorted_values:
        return None
    if len(sorted_values) == 1:
        return sorted_values[0]

    rank = (pct / 100.0) * (len(sorted_values) - 1)
    low = int(rank)
    high = min(low + 1, len(sorted_values) - 1)
    weight = rank - low
    return sorted_values[low] * (1.0 - weight) + sorted_values[high] * weight


def load_csv_files(log_dir):
    paths = sorted(glob.glob(os.path.join(log_dir, '*.csv')))
    if not paths:
        raise SystemExit(f'No CSV files found in {log_dir}')

    columns = {}
    per_file_rows = {}

    for path in paths:
        rows = 0
        with open(path, newline='') as handle:
            for row in csv.DictReader(handle):
                rows += 1
                for key, raw in row.items():
                    if key is None or raw is None or raw == '':
                        continue
                    try:
                        value = float(raw)
                    except ValueError:
                        continue  # non-numeric column, skip
                    columns.setdefault(key, []).append(value)
        per_file_rows[path] = rows

    return columns, per_file_rows


def profile_columns(columns):
    profile = {}

    for name, values in sorted(columns.items()):
        if not values or name in EXCLUDED_COLUMNS:
            continue

        mean = statistics.fmean(values)
        std = statistics.stdev(values) if len(values) > 1 else 0.0
        deviations = sorted(abs(v - mean) for v in values)

        profile[name] = {
            'count': len(values),
            'mean': mean,
            'std': std,
            'min': min(values),
            'max': max(values),
            f'p{PERCENTILE}_abs_dev': percentile(deviations, PERCENTILE),
        }

    return profile


def print_summary(profile, per_file_rows):
    print(f'\nBaseline logs profiled ({len(per_file_rows)} file(s)):')
    for path, rows in per_file_rows.items():
        print(f'  {os.path.basename(path)}: {rows} rows')
    print(f'\nTotal samples: {sum(per_file_rows.values())}')

    header = (f'{"column":<20}{"count":>8}{"mean":>14}{"std":>13}'
              f'{"min":>14}{"max":>14}{f"p{PERCENTILE}_abs_dev":>16}')
    print(f'\n{header}')
    print('-' * len(header))

    for name, stats in profile.items():
        print(f'{name:<20}{stats["count"]:>8}{stats["mean"]:>14.4f}'
              f'{stats["std"]:>13.4f}{stats["min"]:>14.4f}{stats["max"]:>14.4f}'
              f'{stats[f"p{PERCENTILE}_abs_dev"]:>16.4f}')
    print('-' * len(header))

    constant = [n for n, s in profile.items() if s['std'] == 0.0]
    if constant:
        print(f'\nZero-variance columns (no signal for anomaly detection, '
              f'constant in SITL): {", ".join(constant)}')


def main():
    columns, per_file_rows = load_csv_files(LOG_DIR)
    profile = profile_columns(columns)

    output = {
        'source_files': {os.path.basename(p): r for p, r in per_file_rows.items()},
        'total_samples': sum(per_file_rows.values()),
        'percentile': PERCENTILE,
        'columns': profile,
    }

    os.makedirs(os.path.dirname(PROFILE_PATH), exist_ok=True)
    with open(PROFILE_PATH, 'w') as handle:
        json.dump(output, handle, indent=2)

    print_summary(profile, per_file_rows)
    print(f'\nProfile written to {PROFILE_PATH}')


if __name__ == '__main__':
    main()
