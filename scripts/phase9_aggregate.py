#!/usr/bin/env python3
"""Aggregate Phase 9 campaign runs into the results file Phase 10 tunes from.

Reads the JSONL written by phase9_campaign.py and emits mean/std/min/max per
attack type for every metric, plus campaign-wide detection accuracy and
false-positive rate.

Usage:
  ./phase9_aggregate.py                                  # newest campaign
  ./phase9_aggregate.py data/phase9/campaign_*.jsonl     # specific files
  ./phase9_aggregate.py --out data/phase9/results.json
"""
import argparse
import glob
import json
import math
import os
import sys
from datetime import datetime, timezone

WS = os.path.expanduser('~/uav_security_ws')
RESULTS_DIR = os.path.join(WS, 'data', 'phase9')

# Metrics pulled straight out of each injector report.
REPORT_METRICS = [
    'detection_latency_s',
    'first_response_action_latency_s',
    'post_attack_recovery_time_s',
    'total_flags_during_attack',
    'ml_anomaly_detections',
    'false_positives_pre_attack',
    'highest_response_level_reached',
]


def stats(values):
    values = [v for v in values if v is not None]
    if not values:
        return None
    n = len(values)
    mean = sum(values) / n
    # Population std: these are all the runs performed, not a sample of them.
    var = sum((v - mean) ** 2 for v in values) / n
    return {
        'n': n,
        'mean': round(mean, 6),
        'std': round(math.sqrt(var), 6),
        'min': round(min(values), 6),
        'max': round(max(values), 6),
    }


def load_records(paths):
    records = []
    for path in paths:
        with open(path) as fh:
            for line in fh:
                line = line.strip()
                if line:
                    records.append(json.loads(line))
    return records


def summarize_attack(attack_type, runs):
    reports = [r['report'] for r in runs if r.get('report')]
    detected = [r for r in reports if r.get('detection_latency_s') is not None]

    summary = {
        'runs_attempted': len(runs),
        'runs_with_report': len(reports),
        'runs_detected': len(detected),
        # Detection accuracy over runs that actually produced a report: a run
        # whose report is missing failed to execute, which is a harness
        # failure rather than a missed detection, and is reported separately
        # as runs_attempted vs runs_with_report.
        'detection_rate': round(len(detected) / len(reports), 4) if reports else None,
        'metrics': {},
    }

    for metric in REPORT_METRICS:
        s = stats([r.get(metric) for r in reports])
        if s:
            summary['metrics'][metric] = s

    for component in ('gps', 'imu', 'barometer', 'attitude', 'commands'):
        s = stats([(r.get('score_minimums') or {}).get(component) for r in reports])
        if s:
            summary['metrics'][f'score_min_{component}'] = s

    # False positives: flags raised before the attack window opened.
    fp_runs = [r.get('false_positives_pre_attack', 0) or 0 for r in reports]
    if fp_runs:
        summary['false_positive_rate_per_run'] = round(
            sum(1 for v in fp_runs if v > 0) / len(fp_runs), 4)
        summary['false_positives_total'] = sum(fp_runs)

    actions = {}
    for r in reports:
        for action in r.get('response_actions_fired', []):
            actions[action] = actions.get(action, 0) + 1
    if actions:
        summary['response_actions_frequency'] = dict(sorted(actions.items()))

    for key, label in (('pc_link', 'pc_link'), ('pi_link', 'pi_link')):
        rx = stats([r.get(key, {}).get('rx_bytes') for r in runs if r.get(key)])
        tx = stats([r.get(key, {}).get('tx_bytes') for r in runs if r.get(key)])
        thr = stats([r.get(key, {}).get('throughput_bytes_per_s')
                     for r in runs if r.get(key)])
        if rx or tx:
            summary[label] = {k: v for k, v in
                              (('rx_bytes', rx), ('tx_bytes', tx),
                               ('throughput_bytes_per_s', thr)) if v}

    pi_metrics = {}
    for key in ('supervisor_cpu_percent', 'supervisor_rss_mb', 'loadavg_1min', 'mem_used_mb'):
        means = stats([r.get('pi_resources', {}).get(key, {}).get('mean')
                       for r in runs if r.get('pi_resources')])
        peaks = stats([r.get('pi_resources', {}).get(key, {}).get('max')
                       for r in runs if r.get('pi_resources')])
        if means or peaks:
            pi_metrics[key] = {'across_run_means': means, 'across_run_peaks': peaks}
    if pi_metrics:
        summary['pi_resources'] = pi_metrics

    return summary


def summarize_combined(attack_type, runs):
    total_components = 0
    total_detected = 0
    per_component = {}
    for run in runs:
        for part, report in (run.get('reports') or {}).items():
            total_components += 1
            entry = per_component.setdefault(part, {'runs': 0, 'detected': 0, 'latencies': []})
            entry['runs'] += 1
            if report and report.get('detection_latency_s') is not None:
                total_detected += 1
                entry['detected'] += 1
                entry['latencies'].append(report['detection_latency_s'])

    for part, entry in per_component.items():
        entry['detection_rate'] = round(entry['detected'] / entry['runs'], 4) if entry['runs'] else None
        entry['detection_latency_s'] = stats(entry.pop('latencies'))

    return {
        'runs_attempted': len(runs),
        'combined': True,
        'component_attacks': runs[0].get('component_attacks') if runs else [],
        'simultaneous_component_detection_rate': (
            round(total_detected / total_components, 4) if total_components else None),
        'per_component': per_component,
    }


def main():
    parser = argparse.ArgumentParser(description='Aggregate Phase 9 campaign results')
    parser.add_argument('inputs', nargs='*')
    parser.add_argument('--out', default=None)
    args = parser.parse_args()

    paths = args.inputs
    if not paths:
        paths = sorted(glob.glob(os.path.join(RESULTS_DIR, 'campaign_*.jsonl')))
        paths = paths[-1:] if paths else []
    if not paths:
        print('No campaign files found.', file=sys.stderr)
        return 1

    records = load_records(paths)
    if not records:
        print('No records found.', file=sys.stderr)
        return 1

    by_attack = {}
    for record in records:
        by_attack.setdefault(record['attack_type'], []).append(record)

    results = {
        'generated_at': datetime.now(timezone.utc).isoformat(),
        'source_files': [os.path.basename(p) for p in paths],
        'total_runs': len(records),
        'supervisor_on_pi': any(r.get('supervisor_on_pi') for r in records),
        'per_attack': {},
    }

    for attack_type, runs in sorted(by_attack.items()):
        if any(r.get('combined') for r in runs):
            results['per_attack'][attack_type] = summarize_combined(attack_type, runs)
        else:
            results['per_attack'][attack_type] = summarize_attack(attack_type, runs)

    single = {k: v for k, v in results['per_attack'].items() if not v.get('combined')}
    detected = sum(v.get('runs_detected', 0) for v in single.values())
    reported = sum(v.get('runs_with_report', 0) for v in single.values())
    latencies = []
    fp_total = 0
    for attack_type, runs in by_attack.items():
        for run in runs:
            report = run.get('report')
            if report:
                if report.get('detection_latency_s') is not None:
                    latencies.append(report['detection_latency_s'])
                fp_total += report.get('false_positives_pre_attack', 0) or 0

    results['overall'] = {
        'attack_scenarios': len(single),
        'runs_with_report': reported,
        'runs_detected': detected,
        'detection_accuracy': round(detected / reported, 4) if reported else None,
        'detection_latency_s': stats(latencies),
        'false_positives_pre_attack_total': fp_total,
    }

    os.makedirs(RESULTS_DIR, exist_ok=True)
    out_path = args.out or os.path.join(RESULTS_DIR, 'phase9_results.json')
    with open(out_path, 'w') as fh:
        json.dump(results, fh, indent=2)

    print(f'Aggregated {len(records)} runs from {len(paths)} file(s) -> {out_path}')
    print(json.dumps(results['overall'], indent=2))
    for attack_type, summary in sorted(results['per_attack'].items()):
        if summary.get('combined'):
            print(f"  {attack_type}: simultaneous detection "
                  f"{summary.get('simultaneous_component_detection_rate')}")
        else:
            lat = summary['metrics'].get('detection_latency_s', {})
            print(f"  {attack_type}: detect_rate={summary.get('detection_rate')} "
                  f"latency_mean={lat.get('mean')}s (n={summary.get('runs_with_report')})")
    return 0


if __name__ == '__main__':
    sys.exit(main())
