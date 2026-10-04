"""Thread-safe in-memory state for the security dashboard.

Deliberately free of any rclpy import: the ROS node feeds this store from its
executor thread while Flask reads it from request/SSE threads, and keeping the
store pure Python means the interesting logic (event de-duplication, history
windowing) is unit-testable without spinning up ROS.

De-duplication is the part that matters. TrustEngine re-reports an active flag
on every 10 Hz update and ResponseEngine re-reports a sticky action for the
whole incident window, so appending each one to the event log verbatim would
bury the operator in thousands of identical lines during a 15 s attack. The
store instead logs an event only on the absent -> present transition, and a
matching 'cleared' event on present -> absent.
"""

import math
import threading
import time
from collections import deque

M_PER_DEG_LAT = 111320.0

TRAJECTORY_MAXLEN = 3000     # ~5 min at 10 Hz
SCORE_HISTORY_MAXLEN = 600   # ~60 s at 10 Hz
EVENT_LOG_MAXLEN = 200

# Some mitigations are genuinely re-sent every cycle rather than once --
# COMMAND_HOVER is a trajectory setpoint, and PX4 requires a continuous
# setpoint stream to stay in offboard control. Each repeat is a real command,
# so it is counted rather than dropped, but repeats inside this window fold
# into the one log line instead of producing ten entries per second.
ACTUATION_COALESCE_S = 2.0

# Match the 10 Hz cadence of the perceived track so both history windows span
# the same wall-clock duration.
TRUE_POS_MIN_INTERVAL_S = 0.1

COMPONENTS = ('gps', 'imu', 'barometer', 'attitude', 'commands')

# Actions that are pure telemetry rather than an intervention; they would
# otherwise dominate the event log without telling the operator anything.
_UNINTERESTING_ACTIONS = frozenset({'NONE', 'FLAG_ONLY'})


class StateStore:
    def __init__(self, clock=time.time):
        self._clock = clock
        self._lock = threading.Lock()
        self._start_time = None

        self.trust_scores = {}
        self.overall_trust = None
        self.status_line = None
        self.response_level = 0
        self.incident_active = False
        self.active_actions = []
        self.ml_anomaly = None
        self.active_flags = []
        self.vehicle = {}

        self.score_history = {c: deque(maxlen=SCORE_HISTORY_MAXLEN) for c in COMPONENTS}
        self.overall_history = deque(maxlen=SCORE_HISTORY_MAXLEN)
        self.trajectory = deque(maxlen=TRAJECTORY_MAXLEN)
        self.true_trajectory = deque(maxlen=TRAJECTORY_MAXLEN)
        self.events = deque(maxlen=EVENT_LOG_MAXLEN)

        self._seen_flags = set()
        self._seen_actions = set()
        self._actuation_streams = {}
        self._gps_origin = None
        self._event_seq = 0
        self._counts = {'trust_scores': 0, 'snapshots': 0, 'true_pos': 0}
        self._last_rx = {}

    # ------------------------------------------------------------------
    def _elapsed(self):
        now = self._clock()
        if self._start_time is None:
            self._start_time = now
        return now - self._start_time

    def _log_event(self, kind, severity, text, t=None):
        self._event_seq += 1
        self.events.appendleft({
            'seq': self._event_seq,
            't': round(t if t is not None else self._elapsed(), 3),
            'kind': kind,
            'severity': severity,
            'text': text,
        })

    # ------------------------------------------------------------------
    def ingest_trust_scores(self, payload):
        """payload: the JSON dict published on /security/trust_scores."""
        with self._lock:
            t = self._elapsed()
            self._counts['trust_scores'] += 1
            self._last_rx['trust_scores'] = t

            scores = payload.get('scores') or {}
            self.trust_scores = scores
            for component, value in scores.items():
                if component in self.score_history:
                    self.score_history[component].append([round(t, 3), value])

            overall = payload.get('overall_trust')
            if overall is not None:
                self.overall_trust = overall
                self.overall_history.append([round(t, 3), overall])

            self.ml_anomaly = payload.get('ml_anomaly')
            self._update_flags(payload.get('flags') or [], t)

            response = payload.get('response')
            if response is not None:
                self._update_response(response, t)

    def _update_flags(self, flags, t):
        self.active_flags = flags
        current = {(f.get('component'), f.get('check_type'), f.get('severity')) for f in flags}

        for flag in flags:
            key = (flag.get('component'), flag.get('check_type'), flag.get('severity'))
            if key not in self._seen_flags:
                self._log_event(
                    'flag', flag.get('severity', 'minor'),
                    f"{flag.get('component', '?').upper()} {flag.get('check_type', '?')}: "
                    f"{flag.get('reason', '')}", t)

        for key in self._seen_flags - current:
            component, check_type, _ = key
            self._log_event('flag_cleared', 'info',
                            f'{str(component).upper()} {check_type} cleared', t)

        self._seen_flags = current

    def _update_response(self, response, t):
        self.response_level = response.get('response_level', 0)
        self.incident_active = bool(response.get('incident_active'))

        actions = [a for a in (response.get('actions') or [])
                   if a not in _UNINTERESTING_ACTIONS]
        self.active_actions = actions
        current = set(actions)

        reasons = dict(zip(response.get('actions') or [], response.get('reasons') or []))
        for action in actions:
            if action not in self._seen_actions:
                self._log_event('response', 'severe',
                                f'{action} -- {reasons.get(action, "")}', t)

        for action in self._seen_actions - current:
            self._log_event('response_cleared', 'info', f'{action} cancelled', t)

        self._seen_actions = current

    # ------------------------------------------------------------------
    def ingest_status(self, line):
        with self._lock:
            self.status_line = line

    def ingest_response_actions(self, payload):
        with self._lock:
            self._update_response(payload, self._elapsed())

    def ingest_mitigation_intent(self, payload):
        """Actuation events -- each one is a genuine command reaching PX4.

        Repeats of the same action within ACTUATION_COALESCE_S fold into the
        existing log line as a running count, so a continuously re-sent hover
        setpoint reads as one entry rather than ten per second. Actions are
        tracked per-name, since several interleave during an escalation.
        """
        with self._lock:
            action = payload.get('action', '?')
            reason = payload.get('reason', '')
            t = self._elapsed()

            stream = self._actuation_streams.get(action)
            if stream is not None and (t - stream['last_t']) <= ACTUATION_COALESCE_S:
                stream['count'] += 1
                stream['last_t'] = t
                stream['event']['text'] = (
                    f'{action} sent to PX4 (x{stream["count"]}) -- {reason}')
                return

            self._log_event('actuation', 'severe', f'{action} sent to PX4 -- {reason}', t)
            self._actuation_streams[action] = {
                'event': self.events[0], 'count': 1, 'last_t': t}

    def ingest_snapshot(self, payload):
        """Perceived state, i.e. what the security stack believes.

        The perceived track is derived from the snapshot's GPS lat/lon, NOT
        from local_pos. That distinction is the whole point of the overlay: a
        GPS spoof corrupts the GPS receiver fields, while local_pos carries the
        EKF solution read from the real topic. Plotting local_pos against the
        EKF would compare a track with itself and show zero divergence during
        an active spoof.
        """
        with self._lock:
            t = self._elapsed()
            self._counts['snapshots'] += 1
            self._last_rx['snapshot'] = t

            gps = payload.get('gps') or {}
            point = self._gps_to_local(gps)
            if point is not None:
                self.trajectory.append([round(t, 3), *point])

            # Without px4_msgs (e.g. on the Pi) there is no external truth
            # source, so fall back to the snapshot's own EKF local position.
            local = payload.get('local_pos')
            if local is not None and self._counts['true_pos'] == 0:
                self.true_trajectory.append([
                    round(t, 3), local.get('x'), local.get('y'), local.get('z')])

            vstatus = payload.get('vehicle_status') or {}
            battery = payload.get('battery') or {}
            self.vehicle = {
                'lat': gps.get('lat'), 'lon': gps.get('lon'), 'alt': gps.get('alt'),
                'fix_type': gps.get('fix_type'),
                'satellites_used': gps.get('satellites_used'),
                'arming_state': vstatus.get('arming_state'),
                'nav_state': vstatus.get('nav_state'),
                'battery_remaining': battery.get('remaining'),
            }

    def _gps_to_local(self, gps):
        """GPS lat/lon/alt -> NED metres relative to the first fix seen.

        Equirectangular projection: over the hundreds of metres a flight test
        covers, the error against a proper geodetic conversion is far below the
        metre-scale divergence this plot exists to show.
        """
        lat, lon = gps.get('lat'), gps.get('lon')
        if lat is None or lon is None:
            return None
        # PX4 reports 0,0 before the first fix; that is 'no data', not Null Island.
        if abs(lat) < 1e-9 and abs(lon) < 1e-9:
            return None

        alt = gps.get('alt') or 0.0
        if self._gps_origin is None:
            self._gps_origin = (lat, lon, alt)
        lat0, lon0, alt0 = self._gps_origin

        north = (lat - lat0) * M_PER_DEG_LAT
        east = (lon - lon0) * M_PER_DEG_LAT * math.cos(math.radians(lat0))
        return north, east, -(alt - alt0)

    def ingest_true_position(self, x, y, z):
        """Decimated to TRUE_POS_MIN_INTERVAL_S. PX4 publishes local position
        around 50 Hz, so storing every sample would fill the ring buffer five
        times faster than the 10 Hz perceived track and leave the plot showing
        a full perceived history against a truncated truth line."""
        with self._lock:
            t = self._elapsed()
            self._counts['true_pos'] += 1
            if (self.true_trajectory
                    and t - self.true_trajectory[-1][0] < TRUE_POS_MIN_INTERVAL_S):
                return
            self.true_trajectory.append([round(t, 3), x, y, z])

    # ------------------------------------------------------------------
    def snapshot(self):
        """A JSON-serialisable view of everything the frontend renders."""
        with self._lock:
            return {
                't': round(self._elapsed(), 3),
                'trust_scores': dict(self.trust_scores),
                'overall_trust': self.overall_trust,
                'status_line': self.status_line,
                'response_level': self.response_level,
                'incident_active': self.incident_active,
                'active_actions': list(self.active_actions),
                'active_flags': list(self.active_flags),
                'ml_anomaly': self.ml_anomaly,
                'vehicle': dict(self.vehicle),
                'score_history': {c: list(h) for c, h in self.score_history.items()},
                'overall_history': list(self.overall_history),
                'trajectory': list(self.trajectory),
                'true_trajectory': list(self.true_trajectory),
                'events': list(self.events),
                'counts': dict(self._counts),
                'last_rx': dict(self._last_rx),
            }
