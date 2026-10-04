#!/usr/bin/env python3
"""Phase 7 Task 7: end-to-end security-loop latency, measured from the PC.

Both measurement points are on this machine -- the wall time when
/security/sensor_snapshot is published here, and the wall time when the
matching /security/trust_scores arrives back -- so the figure is a true
round trip (PC -> LAN -> Pi -> TrustEngine + AnomalyDetector + ResponseEngine
-> LAN -> PC) and needs no clock synchronisation with the Pi.

Pairing is exact: TrustEngine copies the snapshot's timestamp_us straight
into its report (trust_engine.py:172), so it is the join key.

Caveat worth knowing when reading the numbers: supervisor_node republishes
its latest report on a 10 Hz *timer* rather than on each snapshot, so every
measurement carries up to ~100 ms of publish-timer quantisation on top of
the real transport + compute cost. Duplicated republishes of one report are
counted once (first arrival wins).

Usage:  python3 scripts/measure_latency.py [--samples 500]
"""

import argparse
import json
import os
import statistics
import time

import rclpy
from rclpy.node import Node
from std_msgs.msg import String

DEFAULT_SAMPLES = 500
MATCH_TOLERANCE_US = 5000  # +/-5 ms
REPORT_PATH = os.path.expanduser('~/uav_security_ws/data/latency_report.json')


class LatencyProbe(Node):
    def __init__(self, target_samples):
        super().__init__('latency_probe')
        self.target_samples = target_samples

        self.snapshot_times = {}       # timestamp_us -> wall time seen on PC
        self.matched_ts = set()        # report timestamps already counted
        self.latencies_ms = []
        self.unmatched = 0

        qos = 10
        self.create_subscription(String, '/security/sensor_snapshot', self._snapshot_cb, qos)
        self.create_subscription(String, '/security/trust_scores', self._trust_cb, qos)

        self.get_logger().info(
            f'Measuring end-to-end latency: collecting {target_samples} matched pairs...')

    def _snapshot_cb(self, msg):
        try:
            ts = json.loads(msg.data)['timestamp_us']
        except (json.JSONDecodeError, KeyError):
            return
        self.snapshot_times[ts] = time.time()

        # Bound the dict; at 10 Hz this keeps ~60 s of history.
        if len(self.snapshot_times) > 600:
            for old in sorted(self.snapshot_times)[:100]:
                del self.snapshot_times[old]

    def _trust_cb(self, msg):
        if len(self.latencies_ms) >= self.target_samples:
            return
        try:
            ts = json.loads(msg.data)['timestamp_us']
        except (json.JSONDecodeError, KeyError):
            return
        if ts in self.matched_ts:
            return

        sent = self.snapshot_times.get(ts)
        if sent is None:
            sent = self._match_within_tolerance(ts)
        if sent is None:
            self.unmatched += 1
            return

        self.matched_ts.add(ts)
        self.latencies_ms.append((time.time() - sent) * 1000.0)

        n = len(self.latencies_ms)
        if n % 50 == 0:
            self.get_logger().info(f'{n}/{self.target_samples} pairs matched')

    def _match_within_tolerance(self, ts):
        best = None
        best_delta = MATCH_TOLERANCE_US + 1
        for cand, wall in self.snapshot_times.items():
            delta = abs(cand - ts)
            if delta < best_delta:
                best, best_delta = wall, delta
        return best if best_delta <= MATCH_TOLERANCE_US else None

    def done(self):
        return len(self.latencies_ms) >= self.target_samples


def percentile(values, pct):
    ordered = sorted(values)
    idx = min(int(round((pct / 100.0) * (len(ordered) - 1))), len(ordered) - 1)
    return ordered[idx]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--samples', type=int, default=DEFAULT_SAMPLES)
    args = parser.parse_args()

    rclpy.init()
    probe = LatencyProbe(args.samples)
    try:
        while rclpy.ok() and not probe.done():
            rclpy.spin_once(probe, timeout_sec=0.5)
    except KeyboardInterrupt:
        pass

    samples = probe.latencies_ms
    unmatched = probe.unmatched
    probe.destroy_node()
    if rclpy.ok():
        rclpy.shutdown()

    if not samples:
        print('No matched pairs collected. Is sensor_monitor running here and '
              'supervisor_node running on the Pi?')
        raise SystemExit(1)

    report = {
        'samples': len(samples),
        'unmatched_trust_msgs': unmatched,
        'mean_ms': statistics.fmean(samples),
        'std_ms': statistics.stdev(samples) if len(samples) > 1 else 0.0,
        'p50_ms': percentile(samples, 50),
        'p95_ms': percentile(samples, 95),
        'p99_ms': percentile(samples, 99),
        'min_ms': min(samples),
        'max_ms': max(samples),
        'target_p95_ms': 200.0,
    }
    report['pass'] = report['p95_ms'] < report['target_p95_ms']

    print(f"\nSamples:       {report['samples']}")
    print(f"Mean latency:  {report['mean_ms']:.1f}ms")
    print(f"Std:           {report['std_ms']:.1f}ms")
    print(f"p50:           {report['p50_ms']:.1f}ms")
    print(f"p95:           {report['p95_ms']:.1f}ms")
    print(f"p99:           {report['p99_ms']:.1f}ms")
    print(f"min/max:       {report['min_ms']:.1f}ms / {report['max_ms']:.1f}ms")
    print(f"\np95 < 200ms target: {'PASS' if report['pass'] else 'FAIL'}")

    os.makedirs(os.path.dirname(REPORT_PATH), exist_ok=True)
    with open(REPORT_PATH, 'w') as fh:
        json.dump(report, fh, indent=2)
    print(f'Saved {REPORT_PATH}')


if __name__ == '__main__':
    main()
