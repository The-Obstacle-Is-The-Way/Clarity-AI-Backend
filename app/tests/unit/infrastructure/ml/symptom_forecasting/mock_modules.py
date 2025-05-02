"""
Mock implementation of third-party libraries for testing.

This module provides mock implementations of optuna, xgboost, and other
external dependencies to enable testing without requiring these packages
to be installed in the test environment.
"""

import sys

import numpy as np


class MockTPESampler:
    """Mock implementation of optuna's TPESampler."""
    def __init__(self, *args, **kwargs):
        pass


class MockTrial:
    """Mock implementation of optuna's Trial object."""
    def suggest_float(self, name, low, high, *args, **kwargs):
        return 0.1
        
    def suggest_int(self, name, low, high, *args, **kwargs):
        return min(high, max(low, 3))


class MockStudy:
    """Mock implementation of optuna's Study object."""
    def __init__(self):
        pass
        
    def optimize(self, objective, n_trials=None, *args, **kwargs):
        return None


class MockOptuna:
    """Mock implementation of the optuna module."""
    def __init__(self):
        self.trial = MockTrial
        self.samplers = type('obj', (object,), {'TPESampler': MockTPESampler})
        
    def create_study(self, *args, **kwargs):
        return MockStudy()


class MockBooster:
    """Mock implementation of XGBoost's Booster object."""
    def __init__(self, *args, **kwargs):
        pass
        
    def get_score(self, importance_type="gain"):
        return {
            "feature1": 10.0,
            "feature2": 5.0,
            "feature3": 3.0
        }
        
    def predict(self, data):
        # Return a simple array matching the expected shape
        return np.array([0.5, 0.3, 0.8])


class MockDMatrix:
    """Mock implementation of XGBoost's DMatrix object."""
    def __init__(self, *args, **kwargs):
        pass


class MockXGB:
    """Mock implementation of the xgboost module."""
    def __init__(self):
        self.DMatrix = MockDMatrix
        
    def train(self, params, dtrain, num_boost_round=10, *args, **kwargs):
        return MockBooster()


# Install the mock modules in sys.modules
sys.modules['optuna'] = MockOptuna()
sys.modules['optuna.samplers'] = type('obj', (object,), {'TPESampler': MockTPESampler})
sys.modules['xgboost'] = MockXGB()
