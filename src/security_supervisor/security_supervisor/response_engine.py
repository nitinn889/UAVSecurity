"""Autonomous response and recovery engine (Phase 6).

ResponseEngine is a plain Python class (no ROS dependency) driven by
supervisor_node, which feeds it each cycle's TrustReport + AnomalyResult and
executes decision.actions via its own publisher methods.

Design notes on the two escalation mechanisms and how they interact:

  response_level (the reported integer 0-5) uses a *sticky floor*: once any
  action at a given level has fired, that level is the floor for
  `incident_window_s` seconds after the last unhealthy update (see
  trust_config.yaml). This satisfies "must only escalate, never de-escalate
  within a single incident window" for the reported severity number.

  COMMAND_HOVER specifically also has its own, separate, faster cancel
  rule: response_hover_cancel_consecutive_updates (default 5) consecutive
  updates with overall_trust above response_hover_cancel_trust_min cancel
  it -- i.e. remove COMMAND_HOVER from decision.actions -- independent of
  whether the 30s incident window has fully elapsed. Task 7's own test
  (test_hysteresis_hover_cancel) only asserts COMMAND_HOVER leaves
  .actions after 5 updates; it makes no claim about response_level itself
  dropping in the same cycle, so the two mechanisms don't conflict: the
  *number* can stay sticky at 3 for up to 30s while the *action* is
  already gone from the list.

  COMMAND_RTH/COMMAND_LAND are "publish once" at the ROS topic level (a
  supervisor_node execution-layer concern -- see supervisor_node.py's own
  de-duplication), but response_engine still reports them in
  decision.actions on every cycle once issued, since Task 7's
  test_rth_never_cancelled explicitly checks for exactly that.

Action -> response_level mapping (used to compute this cycle's "natural"
level from whatever actions the decision matrix produced):
  NONE=0, FLAG_ONLY=1, REJECT_COMMAND=1, ROTATE_ENCRYPTION_KEY=1,
  REDUCE_GPS_WEIGHT=1, ISOLATE_GPS=2, ISOLATE_IMU=2, ENTER_DEGRADED_MODE=2,
  COMMAND_HOVER=3, COMMAND_RTH=4, COMMAND_LAND=5.
This mapping is corroborated by Phase 6 Task 8's own expected levels (e.g.
"cmd_inject -> level >= 1 (REJECT_COMMAND + KEY_ROTATION)",
"imu_noise -> level >= 2 (ISOLATE_IMU)").
"""
from dataclasses import dataclass
from enum import Enum
from typing import List, Optional


class ResponseAction(Enum):
    NONE = 'NONE'
    FLAG_ONLY = 'FLAG_ONLY'
    REDUCE_GPS_WEIGHT = 'REDUCE_GPS_WEIGHT'
    REJECT_COMMAND = 'REJECT_COMMAND'
    ISOLATE_GPS = 'ISOLATE_GPS'
    ISOLATE_IMU = 'ISOLATE_IMU'
    ROTATE_ENCRYPTION_KEY = 'ROTATE_ENCRYPTION_KEY'
    ENTER_DEGRADED_MODE = 'ENTER_DEGRADED_MODE'
    COMMAND_HOVER = 'COMMAND_HOVER'
    COMMAND_RTH = 'COMMAND_RTH'
    COMMAND_LAND = 'COMMAND_LAND'


ACTION_LEVEL = {
    ResponseAction.NONE: 0,
    ResponseAction.FLAG_ONLY: 1,
    ResponseAction.REJECT_COMMAND: 1,
    ResponseAction.ROTATE_ENCRYPTION_KEY: 1,
    ResponseAction.REDUCE_GPS_WEIGHT: 1,
    ResponseAction.ISOLATE_GPS: 2,
    ResponseAction.ISOLATE_IMU: 2,
    ResponseAction.ENTER_DEGRADED_MODE: 2,
    ResponseAction.COMMAND_HOVER: 3,
    ResponseAction.COMMAND_RTH: 4,
    ResponseAction.COMMAND_LAND: 5,
}

LEVEL_NAMES = {0: 'NONE', 1: 'FLAG', 2: 'DEGRADED', 3: 'HOVER', 4: 'RTH', 5: 'LAND'}

WHITELIST_VIOLATION_MARKERS = ('not in allowed whitelist', 'invalid param1')


@dataclass
class ResponseDecision:
    actions: List[ResponseAction]
    reasons: List[str]
    response_level: int
    incident_active: bool
    timestamp_s: float


def _is_whitelist_violation(flag) -> bool:
    reason = flag.reason.lower()
    return any(marker in reason for marker in WHITELIST_VIOLATION_MARKERS)


class ResponseEngine:
    def __init__(self, config: dict):
        self.cfg = config

        self.trusted_min = config['status_trusted_min']
        self.untrusted_max = config['status_untrusted_max']
        self.incident_window_s = config['incident_window_s']
        self.hover_cancel_trust_min = config['response_hover_cancel_trust_min']
        self.hover_cancel_updates = config['response_hover_cancel_consecutive_updates']
        self.gps_rotate_key_confidence_min = config['response_gps_rotate_key_confidence_min']
        self.land_confidence_min = config['response_land_confidence_min']
        self.degraded_max = config['response_degraded_max']
        self.hover_max = config['response_hover_max']
        self.rth_max = config['response_rth_max']

        self.current_response_level = 0
        self.incident_start_time: Optional[float] = None
        self.last_unhealthy_time: Optional[float] = None
        self.consecutive_healthy_updates = 0

        self.hover_active = False
        self.rth_issued = False
        self.land_issued = False

    # ------------------------------------------------------------------
    def decide(self, trust_report, anomaly_result, current_time_s: float) -> ResponseDecision:
        ml_confidence = anomaly_result.confidence if anomaly_result is not None else None

        flags_by_component = {}
        for flag in trust_report.flags:
            flags_by_component.setdefault(flag.component, []).append(flag)

        actions: List[ResponseAction] = []
        reasons: List[str] = []

        def add(action, reason):
            if action not in actions:
                actions.append(action)
                reasons.append(reason)

        gps_actions, gps_reasons = self._decide_gps(
            trust_report.scores.get('gps', 1.0), flags_by_component.get('gps', []), ml_confidence)
        imu_actions, imu_reasons = self._decide_imu(
            trust_report.scores.get('imu', 1.0), flags_by_component.get('imu', []))
        cmd_actions, cmd_reasons = self._decide_commands(
            trust_report.scores.get('commands', 1.0), flags_by_component.get('commands', []))

        for a, r in zip(gps_actions + imu_actions + cmd_actions,
                         gps_reasons + imu_reasons + cmd_reasons):
            add(a, r)

        overall_actions, overall_reasons = self._decide_overall(
            trust_report.overall_trust, trust_report.scores, ml_confidence)
        for a, r in zip(overall_actions, overall_reasons):
            add(a, r)

        natural_level = max((ACTION_LEVEL[a] for a in actions), default=0)

        self._update_hover_state(overall_actions, trust_report.overall_trust)
        self._update_rth_land_state(overall_actions)

        # Sticky forced actions: re-add HOVER/RTH/LAND even if this cycle's
        # own natural computation didn't re-trigger them, per the
        # escalation-guard / never-cancelled rules (see module docstring).
        if self.hover_active:
            add(ResponseAction.COMMAND_HOVER, 'HOVER still active (not yet cancelled by hysteresis)')
        if self.rth_issued:
            add(ResponseAction.COMMAND_RTH, 'RTH previously issued -- never cancelled')
        if self.land_issued:
            add(ResponseAction.COMMAND_LAND, 'LAND previously issued -- never cancelled')

        if not actions:
            actions.append(ResponseAction.NONE)
            reasons.append('All components trusted, no active flags')

        effective_level = self._effective_level(natural_level, current_time_s)
        incident_active = effective_level > 0

        return ResponseDecision(
            actions=actions,
            reasons=reasons,
            response_level=effective_level,
            incident_active=incident_active,
            timestamp_s=current_time_s,
        )

    # ------------------------------------------------------------------
    def _decide_gps(self, score, flags, ml_confidence):
        actions, reasons = [], []
        check_types = {f.check_type for f in flags}
        has_flag = bool(flags)

        if score > self.trusted_min:
            if has_flag:
                actions.append(ResponseAction.FLAG_ONLY)
                reasons.append(f'GPS trusted (score={score:.2f}) but flag present ({sorted(check_types)})')
        elif score >= self.untrusted_max:
            if has_flag:
                actions.append(ResponseAction.REDUCE_GPS_WEIGHT)
                reasons.append(f'GPS degraded (score={score:.2f}) with active flag -- de-weighting in EKF')
            else:
                actions.append(ResponseAction.FLAG_ONLY)
                reasons.append(f'GPS degraded (score={score:.2f}), no active flag')
        else:
            if {'cross_sensor', 'temporal'} & check_types:
                matched = sorted({'cross_sensor', 'temporal'} & check_types)
                actions.append(ResponseAction.ISOLATE_GPS)
                reasons.append(f'GPS untrusted (score={score:.2f}) with {matched} flag -- isolating')
            else:
                actions.append(ResponseAction.ISOLATE_GPS)
                reasons.append(f'GPS untrusted (score={score:.2f}) -- isolating regardless of flag type')

            if ml_confidence is not None and ml_confidence > self.gps_rotate_key_confidence_min:
                actions.append(ResponseAction.ROTATE_ENCRYPTION_KEY)
                reasons.append(f'ML confidence {ml_confidence:.2f} > {self.gps_rotate_key_confidence_min} '
                               f'while GPS untrusted -- rotating key')

        return actions, reasons

    def _decide_imu(self, score, flags):
        actions, reasons = [], []
        check_types = {f.check_type for f in flags}
        has_flag = bool(flags)

        if score > self.trusted_min:
            if has_flag:
                actions.append(ResponseAction.FLAG_ONLY)
                reasons.append(f'IMU trusted (score={score:.2f}) but flag present ({sorted(check_types)})')
        elif score >= self.untrusted_max:
            actions.append(ResponseAction.FLAG_ONLY)
            reasons.append(f'IMU degraded (score={score:.2f})' + (' with physics flag' if 'physics' in check_types else ''))
        else:
            actions.append(ResponseAction.ISOLATE_IMU)
            matched = sorted({'physics', 'temporal'} & check_types) or ['no matching flag type']
            reasons.append(f'IMU untrusted (score={score:.2f}) with {matched} -- isolating, relying on GPS+baro')

        return actions, reasons

    def _decide_commands(self, score, flags):
        actions, reasons = [], []

        if any(_is_whitelist_violation(f) for f in flags):
            actions.append(ResponseAction.REJECT_COMMAND)
            reasons.append('Command whitelist violation -- rejecting immediately')

        if score > self.trusted_min:
            pass
        elif score >= self.untrusted_max:
            if ResponseAction.FLAG_ONLY not in actions:
                actions.append(ResponseAction.FLAG_ONLY)
                reasons.append(f'Command score degraded ({score:.2f})')
            actions.append(ResponseAction.ROTATE_ENCRYPTION_KEY)
            reasons.append(f'Command score degraded ({score:.2f}) -- rotating key as precaution')
        else:
            if ResponseAction.REJECT_COMMAND not in actions:
                actions.append(ResponseAction.REJECT_COMMAND)
                reasons.append(f'Command score untrusted ({score:.2f}) -- rejecting')
            actions.append(ResponseAction.ROTATE_ENCRYPTION_KEY)
            reasons.append(f'Command score untrusted ({score:.2f}) -- rotating key')

        return actions, reasons

    def _decide_overall(self, overall_trust, scores, ml_confidence):
        any_fully_untrusted = any(v <= 0.0 for v in scores.values())

        if (overall_trust <= 0.0 and any_fully_untrusted
                and ml_confidence is not None and ml_confidence > self.land_confidence_min):
            return ([ResponseAction.COMMAND_LAND],
                    [f'Overall trust {overall_trust:.2f} with a fully-untrusted component and '
                     f'ML confidence {ml_confidence:.2f} > {self.land_confidence_min} -- trust fully lost'])

        if overall_trust <= self.rth_max:
            return ([ResponseAction.COMMAND_RTH],
                    [f'Overall trust {overall_trust:.2f} <= {self.rth_max} -- critical, returning to launch'])

        if overall_trust <= self.hover_max:
            return ([ResponseAction.ENTER_DEGRADED_MODE, ResponseAction.COMMAND_HOVER],
                    [f'Overall trust {overall_trust:.2f} <= {self.hover_max} -- degraded mode',
                     f'Overall trust {overall_trust:.2f} <= {self.hover_max} -- holding position'])

        if overall_trust <= self.degraded_max:
            return ([ResponseAction.ENTER_DEGRADED_MODE],
                    [f'Overall trust {overall_trust:.2f} in degraded range (<= {self.degraded_max})'])

        return [], []

    # ------------------------------------------------------------------
    def _update_hover_state(self, overall_actions, overall_trust):
        if ResponseAction.COMMAND_HOVER in overall_actions:
            self.hover_active = True
            self.consecutive_healthy_updates = 0
            return

        if not self.hover_active:
            return

        if overall_trust > self.hover_cancel_trust_min:
            self.consecutive_healthy_updates += 1
            if self.consecutive_healthy_updates >= self.hover_cancel_updates:
                self.hover_active = False
                self.consecutive_healthy_updates = 0
        else:
            self.consecutive_healthy_updates = 0

    def _update_rth_land_state(self, overall_actions):
        if ResponseAction.COMMAND_RTH in overall_actions:
            self.rth_issued = True
        if ResponseAction.COMMAND_LAND in overall_actions:
            self.land_issued = True

    def _effective_level(self, natural_level, current_time_s):
        sticky_floor = 0
        if self.hover_active:
            sticky_floor = max(sticky_floor, ACTION_LEVEL[ResponseAction.COMMAND_HOVER])
        if self.rth_issued:
            sticky_floor = max(sticky_floor, ACTION_LEVEL[ResponseAction.COMMAND_RTH])
        if self.land_issued:
            sticky_floor = max(sticky_floor, ACTION_LEVEL[ResponseAction.COMMAND_LAND])

        this_cycle_level = max(natural_level, sticky_floor)

        if this_cycle_level > 0:
            self.last_unhealthy_time = current_time_s
            if self.incident_start_time is None:
                self.incident_start_time = current_time_s
            self.current_response_level = max(self.current_response_level, this_cycle_level)
        elif self.last_unhealthy_time is not None:
            if (current_time_s - self.last_unhealthy_time) >= self.incident_window_s:
                self.current_response_level = 0
                self.incident_start_time = None
                self.last_unhealthy_time = None

        return max(this_cycle_level, self.current_response_level)
