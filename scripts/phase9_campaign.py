#!/usr/bin/env python3
"""Phase 9 attack campaign driver.

Runs each attack scenario N times against the live stack and records, per
run, the injector's own detection report plus the measurements the injector
cannot see from the PC side: PC<->Pi link bytes and the Pi's CPU/memory while
the supervisor is running there.

Reuses scripts/run_attack_scenario.sh rather than re-implementing the
launch/attack/teardown sequence, so the campaign measures the same code path
that Phases 5-8 were validated against.

Usage:
  ./phase9_campaign.py --runs 5
  ./phase9_campaign.py --runs 5 --attacks gps_spoof,imu_noise
  ./phase9_campaign.py --runs 1 --attacks combined_gps_freeze_imu_noise
  ./phase9_campaign.py --runs 5 --no-pi        # supervisor on the PC
"""
import argparse
import json
import os
import shlex
import subprocess
import sys
import time
from datetime import datetime, timezone

WS = os.path.expanduser('~/uav_security_ws')
ATTACK_LOG_DIR = os.path.join(WS, 'data', 'attack_logs')
RESULTS_DIR = os.path.join(WS, 'data', 'phase9')

SINGLE_ATTACKS = ['gps_spoof', 'gps_freeze', 'cmd_inject',
                  'imu_noise', 'telemetry_replay', 'gps_deny']

# Overlapping scenario: a GPS freeze and IMU noise at once, so two
# independent sensor paths degrade simultaneously. Picked because they are
# detected by different checks (temporal GPS-frozen vs IMU physics), which
# is what makes the combination a real test of the fusion logic rather than
# the same detector firing twice.
COMBINED_ATTACKS = {
    'combined_gps_freeze_imu_noise': ['gps_freeze', 'imu_noise'],
}

SSH_BASE = [
    'ssh',
    '-o', 'ConnectTimeout=8',
    '-o', 'BatchMode=yes',
    # Multiplex over a single background connection. Each sample otherwise
    # pays a full TCP+auth handshake across a link already carrying the DDS
    # stream, which is what pushed samples past their timeout.
    '-o', 'ControlMaster=auto',
    '-o', 'ControlPath=/tmp/phase9/.ssh-%r@%h:%p',
    '-o', 'ControlPersist=120',
]

# Pre-attack delay. With the supervisor local, 5s is plenty. With it on the
# Pi, the attack must not fire until cross-host DDS discovery has connected
# this run's new sensor_monitor to the restarted remote supervisor -- an
# attack that starts first is recorded as a miss with zero flags even though
# nothing about the detector failed. Measured discovery took up to ~10s, so
# 20s leaves real margin.
REMOTE_ATTACK_DELAY_S = float(os.environ.get('REMOTE_ATTACK_DELAY_S', '20.0'))
LOCAL_ATTACK_DELAY_S = float(os.environ.get('LOCAL_ATTACK_DELAY_S', '5.0'))

PI_HOST = os.environ.get('PI_HOST', 'nitin@192.168.7.72')
PI_CONTAINER = os.environ.get('PI_CONTAINER', 'uav-supervisor')
PC_IFACE = os.environ.get('PC_IFACE', 'eno1')
PI_IFACE = os.environ.get('PI_IFACE', 'end0')


def _run(cmd, timeout=None, check=False):
    """Never raises on timeout/failure.

    These helpers only gather side metrics. An ssh hiccup mid-campaign must
    degrade that run's metrics to 'missing', never abort the attack run
    itself -- losing a whole scenario because a `ps` call was slow is a far
    worse outcome than a gap in the CPU series.
    """
    try:
        return subprocess.run(cmd, shell=isinstance(cmd, str), capture_output=True,
                              text=True, timeout=timeout, check=check)
    except (subprocess.TimeoutExpired, subprocess.SubprocessError, OSError):
        return None


def reset_pi_supervisor(host, container=PI_CONTAINER, settle_s=12):
    """Restart the Pi supervisor container so each run starts clean.

    run_attack_scenario.sh pkills and relaunches the PC-side supervisor for
    every run, so each scenario historically began from a fresh TrustEngine,
    ResponseEngine and AnomalyDetector. Moving the supervisor into a
    long-lived container on the Pi silently removed that: trust scores,
    sliding windows, staleness timers and -- worst -- response_engine's
    deliberately never-cancelled RTH/HOVER/LAND latches all persisted into
    the next run. Runs after the first were then measuring an already-
    escalated supervisor rather than an independent trial.

    Restarting here restores run independence. It costs ~15s per run, which
    is cheap next to the alternative of non-independent samples.
    """
    out = _run(SSH_BASE + [host, f'docker restart {container}'], timeout=90)
    if out is None or out.returncode != 0:
        return False
    time.sleep(settle_s)
    return True


def _safe(fn, *args):
    """Call a metrics helper, swallowing anything it throws."""
    try:
        return fn(*args)
    except Exception:  # noqa: BLE001 -- metrics are best-effort by design
        return None


# ----------------------------------------------------------------------
def iface_bytes(iface):
    """rx/tx byte counters for a local interface, from /proc/net/dev."""
    try:
        with open('/proc/net/dev') as fh:
            for line in fh:
                if line.strip().startswith(iface + ':'):
                    fields = line.split(':')[1].split()
                    return {'rx_bytes': int(fields[0]), 'rx_packets': int(fields[1]),
                            'tx_bytes': int(fields[8]), 'tx_packets': int(fields[9])}
    except OSError:
        pass
    return None


def pi_iface_bytes(host, iface):
    out = _run(SSH_BASE + [host,
                f"cat /sys/class/net/{iface}/statistics/rx_bytes "
                f"/sys/class/net/{iface}/statistics/tx_bytes "
                f"/sys/class/net/{iface}/statistics/rx_packets "
                f"/sys/class/net/{iface}/statistics/tx_packets"], timeout=25)
    if out is None or out.returncode != 0:
        return None
    values = [int(v) for v in out.stdout.split() if v.strip().isdigit()]
    if len(values) != 4:
        return None
    return {'rx_bytes': values[0], 'tx_bytes': values[1],
            'rx_packets': values[2], 'tx_packets': values[3]}


def pi_resource_sample(host):
    """One CPU/memory sample from the Pi.

    %CPU is summed across the supervisor's processes (container included),
    so it is 'how much of one core', and can exceed 100 on the Pi's 4 cores.
    """
    script = (
        "ps -eo pcpu,rss,comm,args --no-headers | "
        "grep -E 'supervisor|security_supervisor' | grep -v grep | "
        "awk '{cpu+=$1; rss+=$2} END {print cpu\"|\"rss}'; "
        "cat /proc/loadavg | awk '{print $1}'; "
        "free -m | awk '/Mem:/ {print $3\"|\"$2}'"
    )
    out = _run(SSH_BASE + [host, script], timeout=25)
    if out is None or out.returncode != 0:
        return None
    lines = [ln.strip() for ln in out.stdout.strip().splitlines() if ln.strip()]
    sample = {}
    if lines:
        try:
            cpu, rss = lines[0].split('|')
            sample['supervisor_cpu_percent'] = float(cpu or 0.0)
            sample['supervisor_rss_mb'] = float(rss or 0.0) / 1024.0
        except (ValueError, IndexError):
            pass
    if len(lines) > 1:
        try:
            sample['loadavg_1min'] = float(lines[1])
        except ValueError:
            pass
    if len(lines) > 2:
        try:
            used, total = lines[2].split('|')
            sample['mem_used_mb'] = float(used)
            sample['mem_total_mb'] = float(total)
        except (ValueError, IndexError):
            pass
    return sample or None


# ----------------------------------------------------------------------
def newest_report(attack_type, since_ts):
    """Newest attack_report_<type>_*.json written after since_ts."""
    best, best_mtime = None, since_ts
    if not os.path.isdir(ATTACK_LOG_DIR):
        return None
    for name in os.listdir(ATTACK_LOG_DIR):
        if not (name.startswith(f'attack_report_{attack_type}_') and name.endswith('.json')):
            continue
        path = os.path.join(ATTACK_LOG_DIR, name)
        mtime = os.path.getmtime(path)
        if mtime > best_mtime:
            best, best_mtime = path, mtime
    if best is None:
        return None
    with open(best) as fh:
        return {'_report_path': best, **json.load(fh)}


def run_single(attack_type, duration_s, use_pi, run_index):
    """One scenario end-to-end, with side measurements wrapped around it."""
    if use_pi and not _safe(reset_pi_supervisor, PI_HOST):
        print(f'  [{attack_type} #{run_index}] WARNING: Pi supervisor reset failed; '
              f'run may inherit prior state', flush=True)
    print(f'  [{attack_type} #{run_index}] starting...', flush=True)
    started_at = time.time()

    pc_before = iface_bytes(PC_IFACE)
    pi_before = _safe(pi_iface_bytes, PI_HOST, PI_IFACE) if use_pi else None
    pi_samples = []
    if use_pi:
        sample = _safe(pi_resource_sample, PI_HOST)
        if sample:
            pi_samples.append(sample)

    env = dict(os.environ)
    env['RUN_SUPERVISOR'] = 'false' if use_pi else 'true'
    env.setdefault('ROS_DOMAIN_ID', '42')
    env['ATTACK_DELAY_S'] = str(REMOTE_ATTACK_DELAY_S if use_pi else LOCAL_ATTACK_DELAY_S)

    cmd = f'{shlex.quote(os.path.join(WS, "scripts", "run_attack_scenario.sh"))} ' \
          f'{shlex.quote(attack_type)} {duration_s}'
    proc = subprocess.Popen(cmd, shell=True, env=env,
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)

    # Sample the Pi while the scenario runs rather than only at the edges:
    # peak CPU during an attack is the number that matters for "can this run
    # on a Pi", and an average of two endpoints would hide it.
    deadline = time.time() + duration_s + REMOTE_ATTACK_DELAY_S + 90
    while proc.poll() is None and time.time() < deadline:
        time.sleep(5)
        if use_pi:
            sample = _safe(pi_resource_sample, PI_HOST)
            if sample:
                pi_samples.append(sample)
    try:
        stdout, _ = proc.communicate(timeout=60)
    except subprocess.TimeoutExpired:
        proc.kill()
        stdout, _ = proc.communicate()

    pc_after = iface_bytes(PC_IFACE)
    pi_after = _safe(pi_iface_bytes, PI_HOST, PI_IFACE) if use_pi else None
    elapsed = time.time() - started_at

    report = newest_report(attack_type, started_at)

    record = {
        'attack_type': attack_type,
        'run_index': run_index,
        'started_at': datetime.fromtimestamp(started_at, timezone.utc).isoformat(),
        'wall_time_s': round(elapsed, 2),
        'supervisor_on_pi': use_pi,
        'scenario_exit_code': proc.returncode,
        'report': report,
    }

    if pc_before and pc_after:
        record['pc_link'] = {
            'iface': PC_IFACE,
            'rx_bytes': pc_after['rx_bytes'] - pc_before['rx_bytes'],
            'tx_bytes': pc_after['tx_bytes'] - pc_before['tx_bytes'],
            'rx_packets': pc_after['rx_packets'] - pc_before['rx_packets'],
            'tx_packets': pc_after['tx_packets'] - pc_before['tx_packets'],
            'duration_s': round(elapsed, 2),
        }
        total = record['pc_link']['rx_bytes'] + record['pc_link']['tx_bytes']
        record['pc_link']['throughput_bytes_per_s'] = round(total / max(elapsed, 1e-6), 1)

    if pi_before and pi_after:
        record['pi_link'] = {
            'iface': PI_IFACE,
            'rx_bytes': pi_after['rx_bytes'] - pi_before['rx_bytes'],
            'tx_bytes': pi_after['tx_bytes'] - pi_before['tx_bytes'],
            'rx_packets': pi_after['rx_packets'] - pi_before['rx_packets'],
            'tx_packets': pi_after['tx_packets'] - pi_before['tx_packets'],
        }

    if pi_samples:
        def _series(key):
            return [s[key] for s in pi_samples if key in s]
        record['pi_resources'] = {}
        for key in ('supervisor_cpu_percent', 'supervisor_rss_mb', 'loadavg_1min', 'mem_used_mb'):
            values = _series(key)
            if values:
                record['pi_resources'][key] = {
                    'mean': round(sum(values) / len(values), 2),
                    'max': round(max(values), 2),
                    'min': round(min(values), 2),
                    'samples': len(values),
                }

    if report is None:
        record['error'] = 'no attack report produced'
        tail = (stdout or '')[-800:]
        record['scenario_tail'] = tail
        print(f'  [{attack_type} #{run_index}] NO REPORT (exit {proc.returncode})', flush=True)
    else:
        print(f'  [{attack_type} #{run_index}] detect={report.get("detection_latency_s")}s '
              f'flags={report.get("total_flags_during_attack")} '
              f'recovery={report.get("post_attack_recovery_time_s")}s', flush=True)
    return record


def run_combined(name, parts, duration_s, use_pi, run_index):
    """Overlapping attacks: launch the second scenario's injector while the
    first is still active, so their windows genuinely overlap."""
    if use_pi and not _safe(reset_pi_supervisor, PI_HOST):
        print(f'  [{name} #{run_index}] WARNING: Pi supervisor reset failed; '
              f'run may inherit prior state', flush=True)
    print(f'  [{name} #{run_index}] starting {"+".join(parts)}...', flush=True)
    started_at = time.time()

    pc_before = iface_bytes(PC_IFACE)
    pi_samples = []
    env = dict(os.environ)
    env['RUN_SUPERVISOR'] = 'false' if use_pi else 'true'
    env.setdefault('ROS_DOMAIN_ID', '42')
    env['ATTACK_DELAY_S'] = str(REMOTE_ATTACK_DELAY_S if use_pi else LOCAL_ATTACK_DELAY_S)

    procs = []
    for offset, part in enumerate(parts):
        cmd = f'{shlex.quote(os.path.join(WS, "scripts", "run_attack_scenario.sh"))} ' \
              f'{shlex.quote(part)} {duration_s}'
        procs.append((part, subprocess.Popen(cmd, shell=True, env=env,
                                             stdout=subprocess.PIPE,
                                             stderr=subprocess.STDOUT, text=True)))
        # Small stagger so the second injector attaches to the already-running
        # PX4 instance instead of both trying to launch one.
        if offset == 0:
            time.sleep(12)

    deadline = time.time() + duration_s + REMOTE_ATTACK_DELAY_S + 150
    while any(p.poll() is None for _n, p in procs) and time.time() < deadline:
        time.sleep(5)
        if use_pi:
            sample = _safe(pi_resource_sample, PI_HOST)
            if sample:
                pi_samples.append(sample)
    for _n, p in procs:
        if p.poll() is None:
            p.kill()
        try:
            p.communicate(timeout=30)
        except subprocess.TimeoutExpired:
            pass

    pc_after = iface_bytes(PC_IFACE)
    elapsed = time.time() - started_at

    reports = {}
    for part, _p in procs:
        reports[part] = newest_report(part, started_at)

    record = {
        'attack_type': name,
        'component_attacks': parts,
        'run_index': run_index,
        'started_at': datetime.fromtimestamp(started_at, timezone.utc).isoformat(),
        'wall_time_s': round(elapsed, 2),
        'supervisor_on_pi': use_pi,
        'combined': True,
        'reports': reports,
    }
    if pc_before and pc_after:
        record['pc_link'] = {
            'iface': PC_IFACE,
            'rx_bytes': pc_after['rx_bytes'] - pc_before['rx_bytes'],
            'tx_bytes': pc_after['tx_bytes'] - pc_before['tx_bytes'],
            'duration_s': round(elapsed, 2),
        }
    if pi_samples:
        cpu = [s['supervisor_cpu_percent'] for s in pi_samples if 'supervisor_cpu_percent' in s]
        if cpu:
            record['pi_resources'] = {'supervisor_cpu_percent': {
                'mean': round(sum(cpu) / len(cpu), 2), 'max': round(max(cpu), 2)}}

    detected = [p for p, r in reports.items()
                if r and r.get('detection_latency_s') is not None]
    record['components_detected'] = detected
    print(f'  [{name} #{run_index}] detected {len(detected)}/{len(parts)}: {detected}', flush=True)
    return record


# ----------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(description='Phase 9 attack campaign')
    parser.add_argument('--runs', type=int, default=5)
    parser.add_argument('--attacks', default=','.join(SINGLE_ATTACKS + list(COMBINED_ATTACKS)))
    parser.add_argument('--duration', type=float, default=15.0)
    parser.add_argument('--no-pi', action='store_true',
                        help='supervisor runs on the PC instead of the Pi')
    parser.add_argument('--out', default=None)
    args = parser.parse_args()

    use_pi = not args.no_pi
    attacks = [a.strip() for a in args.attacks.split(',') if a.strip()]

    os.makedirs(RESULTS_DIR, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')
    out_path = args.out or os.path.join(RESULTS_DIR, f'campaign_{stamp}.jsonl')

    print(f'Phase 9 campaign: {len(attacks)} scenarios x {args.runs} runs '
          f'(supervisor on {"Pi" if use_pi else "PC"}) -> {out_path}', flush=True)

    total = 0
    with open(out_path, 'a') as sink:
        for attack in attacks:
            for run_index in range(1, args.runs + 1):
                try:
                    if attack in COMBINED_ATTACKS:
                        record = run_combined(attack, COMBINED_ATTACKS[attack],
                                              args.duration, use_pi, run_index)
                    else:
                        record = run_single(attack, args.duration, use_pi, run_index)
                except Exception as exc:  # noqa: BLE001 -- one bad run must not end the campaign
                    record = {'attack_type': attack, 'run_index': run_index,
                              'error': f'{type(exc).__name__}: {exc}'}
                    print(f'  [{attack} #{run_index}] ERROR: {exc}', flush=True)
                sink.write(json.dumps(record) + '\n')
                sink.flush()
                total += 1
                time.sleep(5)

    print(f'Campaign complete: {total} runs -> {out_path}', flush=True)
    return 0


if __name__ == '__main__':
    sys.exit(main())
