#!/usr/bin/env python3
"""Measure the false-positive rate on clean flights (Phase 9).

Why this exists separately from the campaign's own counter: the injector's
false_positives_pre_attack increments on `degraded OR flags OR ml_flagged`,
and ml_flagged reads the detector's raw is_anomaly. Since the
ml_confidence_min gate, a raw is_anomaly below the floor changes no score and
triggers no action -- so that counter measures the *model*, while the number
that matters operationally is whether the *system* wrongly reacted.

This reports both, per clean flight:
  model_level  -- raw ML is_anomaly hits (model quality)
  system_level -- trust actually degraded, or a response action fired
                  (what a false alarm costs an operator)

Usage:  ./phase9_false_positive_run.py --flights 5
"""
import argparse
import json
import os
import signal
import subprocess
import sys
import time
from datetime import datetime, timezone

import rclpy
from rclpy.node import Node
from std_msgs.msg import String

WS = os.path.expanduser('~/uav_security_ws')
RESULTS_DIR = os.path.join(WS, 'data', 'phase9')

NON_ESCALATING = {'NONE', 'FLAG_ONLY'}


class CleanFlightWatcher(Node):
    def __init__(self):
        super().__init__('phase9_fp_watcher')
        self.create_subscription(String, '/security/trust_scores', self._trust_cb, 50)
        self.create_subscription(String, '/security/response_actions', self._response_cb, 50)

        self.updates = 0
        self.raw_ml_anomalies = 0
        self.gated_ml_anomalies = 0
        self.rule_flags = 0
        self.degraded_updates = 0
        self.min_scores = {}
        self.escalating_actions = set()
        self.max_response_level = 0

    def _trust_cb(self, msg):
        try:
            payload = json.loads(msg.data)
        except json.JSONDecodeError:
            return
        self.updates += 1

        scores = payload.get('scores') or {}
        for component, value in scores.items():
            self.min_scores[component] = min(self.min_scores.get(component, 1.0), value)
        if any(v < 1.0 for v in scores.values()):
            self.degraded_updates += 1

        self.rule_flags += len(payload.get('flags') or [])

        ml = payload.get('ml_anomaly') or {}
        if ml.get('is_anomaly'):
            self.raw_ml_anomalies += 1
            # Mirrors supervisor_node's gate; recorded so the report can show
            # how many raw hits the floor actually absorbed.
            if ml.get('confidence', 0.0) >= self._confidence_floor():
                self.gated_ml_anomalies += 1

    def _confidence_floor(self):
        if not hasattr(self, '_floor'):
            import yaml
            with open(os.path.join(WS, 'config', 'trust_config.yaml')) as fh:
                self._floor = yaml.safe_load(fh)['ml_confidence_min']
        return self._floor

    def _response_cb(self, msg):
        try:
            payload = json.loads(msg.data)
        except json.JSONDecodeError:
            return
        self.max_response_level = max(self.max_response_level, payload.get('response_level', 0))
        for action in payload.get('actions', []):
            if action not in NON_ESCALATING:
                self.escalating_actions.add(action)

    def summary(self):
        return {
            'trust_updates_observed': self.updates,
            'model_level_ml_anomalies': self.raw_ml_anomalies,
            'model_level_ml_rate': round(self.raw_ml_anomalies / self.updates, 6) if self.updates else None,
            'ml_anomalies_passing_gate': self.gated_ml_anomalies,
            'rule_based_flags': self.rule_flags,
            'updates_with_degraded_score': self.degraded_updates,
            'min_scores': {k: round(v, 4) for k, v in sorted(self.min_scores.items())},
            'escalating_actions': sorted(self.escalating_actions),
            'max_response_level': self.max_response_level,
            'system_level_false_positive': bool(self.escalating_actions) or self.degraded_updates > 0,
        }


def fly_once(timeout_s=150):
    """Run one clean test flight to completion."""
    log_path = '/tmp/phase9/fp_flight.log'
    with open(log_path, 'w') as sink:
        proc = subprocess.Popen(
            ['python3', os.path.join(WS, 'scripts', 'test_flight.py')],
            stdout=sink, stderr=subprocess.STDOUT, start_new_session=True)

    deadline = time.time() + timeout_s
    landed = False
    while time.time() < deadline:
        time.sleep(3)
        try:
            with open(log_path) as fh:
                if 'Land command sent' in fh.read():
                    landed = True
                    break
        except OSError:
            pass

    time.sleep(8)
    try:
        os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
    except (ProcessLookupError, PermissionError):
        pass
    return landed


def main():
    parser = argparse.ArgumentParser(description='Phase 9 clean-flight false-positive measurement')
    parser.add_argument('--flights', type=int, default=5)
    parser.add_argument('--out', default=os.path.join(RESULTS_DIR, 'phase9_false_positives.json'))
    args = parser.parse_args()

    os.makedirs(RESULTS_DIR, exist_ok=True)
    rclpy.init()

    flights = []
    for index in range(1, args.flights + 1):
        watcher = CleanFlightWatcher()
        print(f'[clean flight {index}/{args.flights}] flying...', flush=True)

        import threading
        stop = threading.Event()

        def spin():
            while not stop.is_set() and rclpy.ok():
                rclpy.spin_once(watcher, timeout_sec=0.1)

        thread = threading.Thread(target=spin, daemon=True)
        thread.start()
        landed = fly_once()
        stop.set()
        thread.join(timeout=5)

        record = watcher.summary()
        record['flight_index'] = index
        record['completed_landing'] = landed
        flights.append(record)
        print(f"  updates={record['trust_updates_observed']} "
              f"raw_ml={record['model_level_ml_anomalies']} "
              f"passed_gate={record['ml_anomalies_passing_gate']} "
              f"rule_flags={record['rule_based_flags']} "
              f"escalations={record['escalating_actions'] or 'NONE'}", flush=True)
        watcher.destroy_node()
        time.sleep(5)

    rclpy.shutdown()

    total_updates = sum(f['trust_updates_observed'] for f in flights)
    total_raw_ml = sum(f['model_level_ml_anomalies'] for f in flights)
    total_gated = sum(f['ml_anomalies_passing_gate'] for f in flights)
    system_fp_flights = sum(1 for f in flights if f['system_level_false_positive'])

    results = {
        'generated_at': datetime.now(timezone.utc).isoformat(),
        'flights': flights,
        'summary': {
            'clean_flights': len(flights),
            'total_trust_updates': total_updates,
            # Model-level: how often the IsolationForest calls clean flight
            # data anomalous at all. Expected to be non-zero by construction
            # (contamination=0.1), which is why the gate exists.
            'model_level_ml_anomalies': total_raw_ml,
            'model_level_ml_rate': round(total_raw_ml / total_updates, 6) if total_updates else None,
            'ml_anomalies_passing_confidence_gate': total_gated,
            # System-level: the operationally meaningful rate -- how many
            # clean flights saw any trust degradation or any escalating
            # response action.
            'system_level_false_positive_flights': system_fp_flights,
            'system_level_false_positive_rate': round(system_fp_flights / len(flights), 4) if flights else None,
        },
    }

    with open(args.out, 'w') as fh:
        json.dump(results, fh, indent=2)
    print(f'\nWrote {args.out}')
    print(json.dumps(results['summary'], indent=2))
    return 0


if __name__ == '__main__':
    sys.exit(main())
