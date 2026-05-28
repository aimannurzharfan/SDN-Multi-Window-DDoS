#!/usr/bin/env python3
"""
Online Adaptive Kalman Filter (OAKF) for adaptive threshold computation.

Based on Ahmad and Alkhammash (2024), "Online Adaptive Kalman Filtering for
Real-Time Anomaly Detection in Wireless Sensor Networks."

Change from original: zero-valued measurements are skipped without updating
filter state. A window with zero packets carries no information about the
signal's normal distribution; seeding the baseline at 0 causes every
subsequent non-zero measurement to appear anomalous. Skipping zeros lets the
warmup_cycles count start only once real traffic is observed — consistent with
the spirit of the warm-up period described in Chapter 3.
"""


class OAKF:
    """One-dimensional adaptive Kalman filter for threshold estimation."""

    def __init__(self,
                 process_noise: float = 1e-3,
                 measurement_noise: float = 1.0,
                 deviation_multiplier: float = 3.0,
                 warmup_cycles: int = 3):
        self.Q = process_noise
        self.R = measurement_noise
        self.k = deviation_multiplier
        self.warmup_cycles = warmup_cycles

        self.x = 0.0
        self.P = 1.0
        self.n_updates = 0          # counts only non-zero measurements
        self.last_residual = 0.0
        self.last_threshold = 0.0
        self.last_measurement = 0.0

    def update(self, measurement: float):
        """
        Feed a new measurement.

        Zero-valued measurements (no packets in window) are ignored: they
        contain no distributional information and would lock the baseline at 0.

        Returns:
            (is_anomaly, residual, threshold)
        """
        self.last_measurement = measurement

        # No traffic this cycle — skip without touching filter state.
        # Return the last computed threshold so callers can still log it.
        if measurement == 0.0:
            return False, 0.0, self.last_threshold

        self.n_updates += 1

        # First non-zero measurement seeds the estimate.
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

        # Only fold non-anomalous measurements back in.
        if not is_anomaly:
            K = P_pred / S
            self.x = x_pred + K * residual
            self.P = (1 - K) * P_pred

        return is_anomaly, residual, threshold

    def state(self) -> dict:
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
