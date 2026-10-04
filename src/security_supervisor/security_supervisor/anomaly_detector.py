"""ML anomaly detection layer (Phase 4).

AnomalyDetector is a plain Python class (no ROS dependency) so it is
unit-testable standalone. It wraps an IsolationForest trained offline by
scripts/train_anomaly_detector.py, and is driven by supervisor_node, which
feeds it parsed /security/sensor_snapshot dicts and fuses the result with
TrustEngine's rule-based flags.
"""
import json
import math
import os
from collections import deque
from dataclasses import dataclass
from typing import List, Optional

import joblib
import numpy as np

try:
    # Package-qualified import: used when installed/run as a ROS 2 node.
    from security_supervisor.feature_engineer import FeatureEngineer
except ImportError:
    # Flat import: used by unit tests that add this directory to sys.path
    # directly, so the module has no known parent package (see
    # test_anomaly_detector.py / test_trust_engine.py).
    from feature_engineer import FeatureEngineer

CONFIDENCE_SIGMOID_SCALE = 2.0
TOP_FEATURES_COUNT = 3


@dataclass
class AnomalyResult:
    is_anomaly: bool
    anomaly_score: float
    confidence: float
    top_features: List[str]
    timestamp_us: int


class AnomalyDetector:
    def __init__(self, model_dir: str):
        self.model = joblib.load(os.path.join(model_dir, 'isolation_forest.pkl'))
        self.scaler = joblib.load(os.path.join(model_dir, 'scaler.pkl'))
        with open(os.path.join(model_dir, 'feature_names.json'), 'r') as handle:
            self.feature_names = json.load(handle)

        self.feature_engineer = FeatureEngineer()
        self.window_size = self.feature_engineer.window_size
        self.buffer = deque(maxlen=self.window_size)

    def update(self, snapshot: dict) -> Optional[AnomalyResult]:
        self.buffer.append(snapshot)
        if len(self.buffer) < self.window_size:
            return None

        vector = self.feature_engineer.compute(list(self.buffer))
        if vector is None:
            return None

        scaled = self.scaler.transform(vector.reshape(1, -1))

        score = float(self.model.decision_function(scaled)[0])
        prediction = int(self.model.predict(scaled)[0])
        is_anomaly = prediction == -1

        # sigmoid(-score * 2.0): more negative decision_function (more
        # anomalous) -> confidence closer to 1.0.
        confidence = 1.0 / (1.0 + math.exp(CONFIDENCE_SIGMOID_SCALE * score))
        confidence = max(0.0, min(1.0, confidence))

        # Scaled mean is 0 by definition (StandardScaler); rank features by
        # distance from that mean to explain what drove the score.
        abs_scaled = np.abs(scaled[0])
        top_idx = np.argsort(-abs_scaled)[:TOP_FEATURES_COUNT]
        top_features = [self.feature_names[i] for i in top_idx]

        return AnomalyResult(
            is_anomaly=is_anomaly,
            anomaly_score=score,
            confidence=confidence,
            top_features=top_features,
            timestamp_us=snapshot.get('timestamp_us', 0),
        )
