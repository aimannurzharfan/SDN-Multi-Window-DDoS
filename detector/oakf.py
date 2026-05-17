#!/usr/bin/env python3
"""
Online Adaptive Kalman Filter (OAKF) for adaptive threshold computation.

Based on Ahmad and Alkhammash (2024), "Online Adaptive Kalman Filtering for
Real-Time Anomaly Detection in Wireless Sensor Networks."

A one-dimensional Kalman filter that tracks a slowly-changing baseline of
a network signal and emits an adaptive threshold around it. When a new
measurement deviates from the predicted baseline by more than k standard
deviations of the innovation, the measurement is flagged anomalous.

Anomalous measurements do NOT update the baseline, preventing the filter
from absorbing attack values into the "normal" estimate.
"""


class OAKF:
    """One-dimensional adaptive Kalman filter for threshold estimation."""

    def __init__(self,
                 process_noise: float = 1e-3,
                 measurement_noise: float = 1.0,
                 deviation_multiplier: float = 3.0,
                 warmup_cycles: int = 3):
        """
        Args:
            process_noise (Q):        expected baseline drift between cycles.
                                      Larger Q means threshold adapts faster.
            measurement_noise (R):    observation noise variance.
                                      Larger R means trust current estimate
                                      more than each new reading.
            deviation_multiplier (k): sigmas before anomaly.
                                      k=3 ~ 99.7% confidence (Gaussian).
            warmup_cycles:            initial cycles during which no anomaly
                                      is raised while baseline establishes.
        """
        self.Q = process_noise
        self.R = measurement_noise
        self.k = deviation_multiplier
        self.warmup_cycles = warmup_cycles

        # State
        self.x = 0.0
        self.P = 1.0
        self.n_updates = 0
        self.last_residual = 0.0
        self.last_threshold = 0.0
        self.last_measurement = 0.0

    def update(self, measurement: float):
        """
        Feed a new measurement.

        Returns:
            (is_anomaly, residual, threshold)
            - is_anomaly is False during warmup
            - residual  = measurement - predicted_estimate
            - threshold = k * sqrt(innovation_variance)
        """
        self.last_measurement = measurement
        self.n_updates += 1

        # First measurement: seed estimate; no anomaly yet
        if self.n_updates == 1:
            self.x = measurement
            self.P = 1.0
            self.last_residual = 0.0
            self.last_threshold = 0.0
            return False, 0.0, 0.0

        # Predict
        x_pred = self.x
        P_pred = self.P + self.Q

        # Innovation
        residual = measurement - x_pred
        S = P_pred + self.R
        threshold = self.k * (S ** 0.5)

        self.last_residual = residual
        self.last_threshold = threshold

        in_warmup = self.n_updates <= self.warmup_cycles
        is_anomaly = (not in_warmup) and (abs(residual) > threshold)

        # Update step. Only fold the measurement in if not anomalous,
        # so attack values do not poison the baseline.
        if not is_anomaly:
            K = P_pred / S
            self.x = x_pred + K * residual
            self.P = (1 - K) * P_pred

        return is_anomaly, residual, threshold

    def state(self) -> dict:
        """Snapshot of internal state, useful for Figure 3.7."""
        return {
            "estimate": self.x,
            "covariance": self.P,
            "Q": self.Q,
            "R": self.R,
            "k": self.k,
            "n_updates": self.n_updates,
            "last_measurement": self.last_measurement,
            "last_residual": self.last_residual,
            "last_threshold": self.last_threshold,
        }