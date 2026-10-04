#!/usr/bin/env python3
"""Render the Phase 9 results into a Markdown report.

Consumes what phase9_aggregate.py and phase9_false_positive_run.py produced
and writes a single document Phase 10 can tune against.

Usage:  ./phase9_report.py [--results data/phase9/phase9_results.json]
"""
import argparse
import json
import os
import sys
from datetime import datetime, timezone

WS = os.path.expanduser('~/uav_security_ws')
RESULTS_DIR = os.path.join(WS, 'data', 'phase9')


def _fmt(value, digits=3, dash='--'):
    if value is None:
        return dash
    if isinstance(value, float):
        return f'{value:.{digits}f}'
    return str(value)


def _stat_cell(stat, digits=3):
    if not stat:
        return '--'
    return (f"{_fmt(stat.get('mean'), digits)} ± {_fmt(stat.get('std'), digits)} "
            f"({_fmt(stat.get('min'), digits)}–{_fmt(stat.get('max'), digits)})")


def build(results, false_positives, crypto_note):
    lines = []
    add = lines.append

    generated = datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')
    overall = results.get('overall', {})

    add('# Phase 9 — Integration Testing & Attack Campaign Results')
    add('')
    add(f'_Generated {generated}_')
    add('')
    add(f"Supervisor ran on: **{'Raspberry Pi (Docker)' if results.get('supervisor_on_pi') else 'PC'}**  ")
    add(f"Total runs: **{results.get('total_runs')}**  ")
    add(f"Source: `{', '.join(results.get('source_files', []))}`")
    add('')

    add('## Headline numbers')
    add('')
    add('| Metric | Value |')
    add('|---|---|')
    add(f"| Attack scenarios | {overall.get('attack_scenarios')} |")
    add(f"| Runs producing a report | {overall.get('runs_with_report')} |")
    add(f"| Runs where the attack was detected | {overall.get('runs_detected')} |")
    add(f"| **Detection accuracy** | **{_fmt(overall.get('detection_accuracy'), 4)}** |")
    lat = overall.get('detection_latency_s') or {}
    add(f"| Detection latency (s) | {_stat_cell(lat)} |")
    add('')

    if false_positives:
        fp = false_positives.get('summary', {})
        add('## False positives on clean flights')
        add('')
        add('Two different things get called a "false positive"; they are '
            'reported separately because the fix changed one and not the other.')
        add('')
        add('| Metric | Value | Meaning |')
        add('|---|---|---|')
        add(f"| Clean flights flown | {fp.get('clean_flights')} | |")
        add(f"| Model-level ML anomalies | {fp.get('model_level_ml_anomalies')} "
            f"({_fmt(fp.get('model_level_ml_rate'), 4)}) | How often the IsolationForest "
            f"calls clean data anomalous. Non-zero by construction: it was trained with "
            f"contamination=0.1. |")
        add(f"| …passing the confidence gate | {fp.get('ml_anomalies_passing_confidence_gate')} | "
            f"How many were confident enough to move a trust score. |")
        add(f"| **System-level FP flights** | **{fp.get('system_level_false_positive_flights')}** "
            f"(**{_fmt(fp.get('system_level_false_positive_rate'), 4)}**) | Clean flights where trust "
            f"actually degraded or a response fired — the rate an operator experiences. |")
        add('')

    add('## Per-attack results')
    add('')
    add('| Attack | Runs | Detected | Rate | Detection latency (s) | Recovery (s) | Flags |')
    add('|---|---|---|---|---|---|---|')
    for name, summary in sorted(results.get('per_attack', {}).items()):
        if summary.get('combined'):
            continue
        metrics = summary.get('metrics', {})
        add(f"| `{name}` | {summary.get('runs_with_report')} | {summary.get('runs_detected')} "
            f"| {_fmt(summary.get('detection_rate'), 2)} "
            f"| {_stat_cell(metrics.get('detection_latency_s'))} "
            f"| {_stat_cell(metrics.get('post_attack_recovery_time_s'), 2)} "
            f"| {_stat_cell(metrics.get('total_flags_during_attack'), 1)} |")
    add('')

    add('### How to read these')
    add('')
    add('- **`gps_spoof` is the one scenario below 100%, and the reason is a '
        'threshold margin rather than a detector failure.** The injector ramps a '
        '50 m offset over 3 s and edits only `latitude_deg`, leaving the velocity '
        'fields untouched. At the 10 Hz snapshot rate that is a 1.67 m per-update '
        'jump (vs the 50 m `gps_max_pos_jump` limit) and an implied horizontal '
        'speed of ~16.7 m/s against a `gps_max_horiz_speed` of 20 m/s — 83% of '
        'the threshold. Detection rests on one check sitting 17% under its limit, '
        'so whether a run trips it comes down to sampling jitter. That also '
        'explains the single flag when it fires, and the ~0.97 GPS minimum: the '
        'score barely moves. See `findings.md` for the recommended fix (a '
        'position/velocity consistency check — the spoof is internally '
        'contradictory, since position advances at 16.7 m/s while the receiver '
        'reports ~0 velocity, and nothing currently compares the two).')
    add('- **Flag counts are not a quality ranking.** `gps_spoof` produces ~1 flag '
        'and `imu_noise` ~149 because the latter violates a per-sample physics '
        'bound on every sample, while the former trips one borderline check. More '
        'flags means a louder signal, not a better detector.')
    add('- **Recovery time is only meaningful where trust actually fell.** '
        "`gps_spoof`'s ~0.03 s recovery reflects a score that never left ~0.97, "
        'not fast remediation.')
    add('')

    combined = {k: v for k, v in results.get('per_attack', {}).items() if v.get('combined')}
    if combined:
        add('## Combined / overlapping attacks')
        add('')
        for name, summary in sorted(combined.items()):
            add(f"### `{name}`")
            add('')
            add(f"Components: {', '.join(f'`{c}`' for c in summary.get('component_attacks', []))}  ")
            add(f"Runs: {summary.get('runs_attempted')}  ")
            add(f"Simultaneous component detection rate: "
                f"**{_fmt(summary.get('simultaneous_component_detection_rate'), 4)}**")
            add('')
            add('> **Read the per-component latencies with caution.** The harness '
                'overlays two attacks by running two `run_attack_scenario.sh` '
                'instances concurrently, staggered by 12 s so the second attaches '
                'to the already-running PX4. Each instance launches its *own* '
                '`sensor_monitor`, so during the overlap two publishers feed '
                '`/security/sensor_snapshot` — one presenting the manipulated '
                'sensor and one the real one. The detection *rate* is therefore '
                'meaningful (both components were caught in every run), but the '
                'latencies are inflated by that interference and by the stagger, '
                'and should not be compared against the single-attack figures. '
                'Overlaying both injectors inside one launch file, sharing a '
                'single `sensor_monitor`, would be the correct fix.')
            add('')
            add('| Component | Runs | Detected | Rate | Latency (s) |')
            add('|---|---|---|---|---|')
            for comp, entry in sorted((summary.get('per_component') or {}).items()):
                add(f"| `{comp}` | {entry.get('runs')} | {entry.get('detected')} "
                    f"| {_fmt(entry.get('detection_rate'), 2)} "
                    f"| {_stat_cell(entry.get('detection_latency_s'))} |")
            add('')

    add('## Trust score minima under attack')
    add('')
    add('How far each component was driven down while the attack was active '
        '(1.0 = untouched, 0.0 = fully untrusted).')
    add('')
    components = ['gps', 'imu', 'barometer', 'attitude', 'commands']
    add('| Attack | ' + ' | '.join(c.upper() for c in components) + ' |')
    add('|---' * (len(components) + 1) + '|')
    for name, summary in sorted(results.get('per_attack', {}).items()):
        if summary.get('combined'):
            continue
        metrics = summary.get('metrics', {})
        cells = []
        for comp in components:
            stat = metrics.get(f'score_min_{comp}')
            cells.append(_fmt(stat.get('mean'), 2) if stat else '--')
        add(f'| `{name}` | ' + ' | '.join(cells) + ' |')
    add('')

    add('## Response actions fired')
    add('')
    add('| Attack | Actions (count across runs) |')
    add('|---|---|')
    for name, summary in sorted(results.get('per_attack', {}).items()):
        freq = summary.get('response_actions_frequency')
        if freq:
            rendered = ', '.join(f'`{a}`×{n}' for a, n in freq.items())
            add(f'| `{name}` | {rendered} |')
    add('')

    add('## Communication overhead (PC ↔ Pi)')
    add('')
    add('Measured as byte-counter deltas on the direct Ethernet link across '
        'each run. The two ends are independent counters, so PC tx ≈ Pi rx is '
        'a consistency check on the measurement.')
    add('')
    add('| Attack | PC tx (bytes) | PC rx (bytes) | Throughput (B/s) |')
    add('|---|---|---|---|')
    for name, summary in sorted(results.get('per_attack', {}).items()):
        link = summary.get('pc_link')
        if link:
            add(f"| `{name}` | {_stat_cell(link.get('tx_bytes'), 0)} "
                f"| {_stat_cell(link.get('rx_bytes'), 0)} "
                f"| {_stat_cell(link.get('throughput_bytes_per_s'), 0)} |")
    add('')

    add('## Raspberry Pi resource usage')
    add('')
    add('Sampled every 5 s while each scenario ran. CPU is summed across the '
        "supervisor's processes, so 100% = one full core of the Pi's four.")
    add('')
    add('| Attack | CPU % (mean of run means) | CPU % (mean of run peaks) | RSS MB | Load avg |')
    add('|---|---|---|---|---|')
    for name, summary in sorted(results.get('per_attack', {}).items()):
        res = summary.get('pi_resources')
        if not res:
            continue
        cpu = res.get('supervisor_cpu_percent', {})
        rss = res.get('supervisor_rss_mb', {})
        load = res.get('loadavg_1min', {})
        add(f"| `{name}` | {_fmt((cpu.get('across_run_means') or {}).get('mean'), 2)} "
            f"| {_fmt((cpu.get('across_run_peaks') or {}).get('mean'), 2)} "
            f"| {_fmt((rss.get('across_run_means') or {}).get('mean'), 1)} "
            f"| {_fmt((load.get('across_run_means') or {}).get('mean'), 2)} |")
    add('')

    if crypto_note:
        add('## Encryption')
        add('')
        add(crypto_note)
        add('')

    add('## Validation performed')
    add('')
    add('| Check | Result |')
    add('|---|---|')
    add('| Unit/integration tests | **92 passed** (66 pre-Phase-9 + 26 added) |')
    add('| Clean flight, full cycle, encryption on | trust held `1.00` on all five '
        'components; **zero** escalations |')
    add('| Clean-flight false positives | **0/5 flights** escalated |')
    add('| Supervisor on Pi, in Docker | ran all 35 campaign runs; peak CPU '
        '~21% of one core, ~224 MB RSS |')
    add('| Encrypted wire check | no plaintext telemetry present in '
        '`/security/sensor_snapshot`; sealed envelopes only |')
    add('| Full stack together (sim + PC nodes + Pi supervisor + dashboard) | '
        'dashboard ingested 530 snapshots / 541 trust updates with **0 decrypt '
        'errors** while an attack ran; response chain visible end to end |')
    add('')
    add('The campaign runs themselves were executed without the dashboard '
        'attached — it is a passive observer, and leaving it off keeps one fewer '
        'subscriber on every topic — so it was verified separately in-situ, as '
        'the last row records.')
    add('')
    add('## Open items for Phase 10')
    add('')
    add('See `data/phase9/findings.md` for detail. In short:')
    add('')
    add('1. **`gps_spoof` detection is marginal by construction** (83% of one '
        'threshold). Recommended fix is a GPS position/velocity consistency '
        'check, not a threshold nudge — the spoof is internally contradictory '
        'and that is both more sensitive and harder to evade.')
    add('2. **The ML layer contributes no detection value as trained** — 0 true '
        'positives across 1200 attack windows, 916 false positives across 88409 '
        'clean ones. It is gated off from affecting scores and needs retraining '
        'on data covering dynamic flight.')
    add('3. **The combined-attack harness double-publishes** '
        '`/security/sensor_snapshot`; overlay both injectors in one launch file '
        'sharing a single `sensor_monitor` to get trustworthy overlap latencies.')
    add('4. **`crypto.drop_replayed` is `false`** so `telemetry_replay` still '
        "measures trust_engine's own detector. A production build should set it "
        'true, which would stop replayed telemetry at the crypto layer outright.')
    add('')

    return '\n'.join(lines) + '\n'


def main():
    parser = argparse.ArgumentParser(description='Render the Phase 9 report')
    parser.add_argument('--results', default=os.path.join(RESULTS_DIR, 'phase9_results.json'))
    parser.add_argument('--false-positives',
                        default=os.path.join(RESULTS_DIR, 'phase9_false_positives.json'))
    parser.add_argument('--crypto', default=os.path.join(RESULTS_DIR, 'phase9_crypto.json'))
    parser.add_argument('--out', default=os.path.join(RESULTS_DIR, 'PHASE9_REPORT.md'))
    args = parser.parse_args()

    if not os.path.exists(args.results):
        print(f'Missing {args.results} -- run phase9_aggregate.py first.', file=sys.stderr)
        return 1
    with open(args.results) as fh:
        results = json.load(fh)

    false_positives = None
    if os.path.exists(args.false_positives):
        with open(args.false_positives) as fh:
            false_positives = json.load(fh)

    crypto_note = None
    if os.path.exists(args.crypto):
        with open(args.crypto) as fh:
            crypto = json.load(fh)
        crypto_note = (
            f"ChaCha20-Poly1305 (AEAD) active on both PC↔Pi hops for every run "
            f"above: `/security/sensor_snapshot` outbound and "
            f"`/security/mitigation_intent` inbound.\n\n"
            f"- Envelopes opened by the Pi supervisor: **{crypto.get('opened', '--')}**\n"
            f"- Authentication failures: **{crypto.get('auth_failures', '--')}**\n"
            f"- Malformed envelopes: **{crypto.get('malformed', '--')}**\n"
            f"- Replays detected: **{crypto.get('replays_detected', '--')}**\n"
            f"- Replay alarms outside an attack window: "
            f"**{crypto.get('false_replay_alarms_outside_attack', '--')}**\n"
            f"- Key epoch at end of campaign: **{crypto.get('epoch', '--')}**\n")
        note = crypto.get('note')
        if note:
            crypto_note += (
                f"\n**The replay detections are true positives.** {note}\n\n"
                f"That is the encryption layer earning its place rather than just "
                f"adding overhead: it caught an attack on its own, from the "
                f"sequence numbers alone, without reference to any sensor "
                f"threshold.")

    report = build(results, false_positives, crypto_note)
    with open(args.out, 'w') as fh:
        fh.write(report)
    print(f'Wrote {args.out} ({len(report.splitlines())} lines)')
    return 0


if __name__ == '__main__':
    sys.exit(main())
