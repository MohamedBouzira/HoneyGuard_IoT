# ================================================================
# Reward Engine — Computes rewards for RL agent actions
# Integrates real defensive models in hard mode
# ================================================================
import numpy as np
import os
import sys
import warnings

warnings.filterwarnings('ignore')

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))
from config import DETECTION_RATES, DIFFICULTY_CONFIGS, FEATURE_RANGES


class RewardEngine:
    """
    Reward engine for the offensive RL agent.

    Modes:
    - simulation: Rewards based on dataset-derived probabilities
    - live: Rewards based on real honeypot responses
    - adversarial: Rewards scored by defensive AI models (XGBoost + Autoencoder)
    """

    def __init__(self, difficulty='medium', mode='simulation'):
        self.difficulty = difficulty
        self.mode = mode
        self.config = DIFFICULTY_CONFIGS[difficulty]
        self.detection_prob = self.config['detection_probability']

        # Defensive models (loaded on demand for hard mode / adversarial)
        self._binary_model = None
        self._multiclass_model = None
        self._autoencoder = None
        self._scaler = None
        self._feature_names = None

    def _load_defensive_models(self):
        """Load trained defensive models for adversarial scoring."""
        models_dir = os.path.join(os.path.dirname(__file__), '..', '..', '..', 'Defensive')

        # Load XGBoost binary classifier
        try:
            import joblib
            binary_path = os.path.join(models_dir, 'Xgboost_binary', 'xgboost_binary.pkl')
            if os.path.exists(binary_path):
                self._binary_model = joblib.load(binary_path)
                print(f'[RewardEngine] Loaded binary model from {binary_path}')
            else:
                print(f'[RewardEngine] Binary model not found at {binary_path}')
        except Exception as e:
            print(f'[RewardEngine] Could not load binary model: {e}')

        # Load XGBoost multiclass classifier
        try:
            import joblib
            multi_path = os.path.join(models_dir, 'Xgboost_multi', 'xgboost_multiclass.pkl')
            if os.path.exists(multi_path):
                self._multiclass_model = joblib.load(multi_path)
                print(f'[RewardEngine] Loaded multiclass model from {multi_path}')
            else:
                print(f'[RewardEngine] Multiclass model not found at {multi_path}')
        except Exception as e:
            print(f'[RewardEngine] Could not load multiclass model: {e}')

        # Load autoencoder
        try:
            from tensorflow import keras
            import pickle
            ae_path = os.path.join(models_dir, 'Autoencoder', 'autoencoder_anomaly.keras')
            if os.path.exists(ae_path):
                self._autoencoder = keras.models.load_model(ae_path)
                print(f'[RewardEngine] Loaded autoencoder from {ae_path}')
            else:
                print(f'[RewardEngine] Autoencoder not found at {ae_path}')
            scaler_path = os.path.join(models_dir, 'Autoencoder', 'scaler_anomaly.pkl')
            if os.path.exists(scaler_path):
                with open(scaler_path, 'rb') as f:
                    self._scaler = pickle.load(f)
                print(f'[RewardEngine] Loaded scaler from {scaler_path}')
        except Exception as e:
            print(f'[RewardEngine] Could not load autoencoder: {e}')

    def compute_reward(self, state, action, next_state, info):
        """
        Compute reward for a state transition.

        Returns:
            reward (float): Scalar reward value
            detected (bool): Whether the agent was detected
        """
        if self.mode == 'adversarial':
            return self._adversarial_reward(state, action, next_state, info)
        elif self.mode == 'live':
            return self._live_reward(state, action, next_state, info)
        else:
            return self._simulation_reward(state, action, next_state, info)

    def _simulation_reward(self, state, action, next_state, info):
        """
        Simulation-based reward using dataset-derived probabilities.
        """
        reward = 0.0
        detected = False

        action_type = info.get('action_type', 'unknown')
        success = info.get('success', False)
        stealth = info.get('stealth_score', 0.5)

        # Base reward for successful action
        if success:
            reward += 1.0 * self.config['reward_scale']

            # Bonus for multi-step attack progression
            progress = info.get('attack_progress', 0)
            reward += progress * 0.5

        # Penalty for detection
        noise_level = info.get('noise_level', 0.5)
        detection_roll = np.random.random()
        # Detection requires both high noise AND low stealth simultaneously
        effective_detection = self.detection_prob * (noise_level ** 1.5) * ((1 - stealth) ** 2)

        if detection_roll < effective_detection:
            detected = True
            reward -= 3.0 * self.config['reward_scale']

        # Small reward for information gathering (even if not "successful")
        if action_type in ['scan', 'enumerate', 'reconnaisance']:
            reward += 0.2

        # Penalty for repeated failed actions (encourages exploration)
        if not success and info.get('consecutive_failures', 0) > 2:
            reward -= 0.5

        return reward, detected

    def _adversarial_reward(self, state, action, next_state, info):
        """
        Adversarial reward: Agent gets high reward for evading defensive models.
        Uses real XGBoost + Autoencoder to score the agent's traffic.
        """
        # Load models on first call
        if self._binary_model is None and self._autoencoder is None:
            self._load_defensive_models()

        reward = 0.0
        detected = False

        # Build feature vector from state (matches defensive model input)
        feature_vector = self._state_to_features(next_state, info)

        # Score with binary classifier
        binary_score = self._score_binary(feature_vector)
        # Score with autoencoder
        anomaly_score = self._score_autoencoder(feature_vector)

        # Agent wants to EVADE detection (low detection probability = good)
        # binary_score: probability of being classified as attack
        # anomaly_score: reconstruction error (high = anomalous)

        evasion_score = 0.0

        if binary_score is not None:
            # Reward for fooling binary classifier (classified as benign)
            evasion_score += (1.0 - binary_score) * 3.0
            if binary_score > 0.5:
                detected = True

        if anomaly_score is not None:
            # Reward for low reconstruction error (appears normal)
            # Normalize anomaly score to [0, 1] range
            norm_anomaly = min(anomaly_score / 0.1, 1.0)  # 0.1 is typical threshold
            evasion_score += (1.0 - norm_anomaly) * 2.0
            if norm_anomaly > 0.7:
                detected = True

        # Action success still matters
        if info.get('success', False):
            reward += 2.0

        # Combine: reward evasion + penalize detection
        reward += evasion_score
        if detected:
            reward -= 5.0

        return reward * self.config['reward_scale'], detected

    def _live_reward(self, state, action, next_state, info):
        """
        Live mode reward based on real honeypot responses.
        """
        reward = 0.0
        detected = False

        response = info.get('response', {})
        response_code = response.get('status_code', 0)
        response_time = response.get('response_time', 0)

        # Successful connection/response
        if response_code in [200, 201, 204]:
            reward += 1.5
        elif response_code in [401, 403]:
            reward += 0.3  # At least we got a response (service exists)
        elif response_code in [404]:
            reward += 0.1
        elif response_code >= 500:
            reward += 2.0  # Server error — potential exploit
        elif response_code == 0:
            reward -= 0.5  # No response (blocked/timeout)

        # Fast response suggests honeypot (real services have varied latency)
        if 0 < response_time < 0.01:
            reward -= 0.3  # Suspiciously fast — likely honeypot trap

        # SSH specific
        if info.get('protocol') == 'SSH':
            if info.get('auth_success', False):
                reward += 10.0  # Major success: shell access
            elif info.get('banner_grabbed', False):
                reward += 0.5

        # MQTT specific
        if info.get('protocol') == 'MQTT':
            if info.get('subscribed', False):
                reward += 2.0
            if info.get('messages_received', 0) > 0:
                reward += 1.0

        return reward, detected

    def _state_to_features(self, state, info):
        """Convert RL state vector to feature vector matching defensive models."""
        # Map state dimensions back to dataset features
        feature_vector = np.zeros(50)  # Approximate feature dim after one-hot

        # Map numeric state features
        feature_vector[0] = state[0] * FEATURE_RANGES['bytes_sent']['max']
        feature_vector[1] = state[1] * FEATURE_RANGES['bytes_received']['max']
        feature_vector[2] = state[2] * FEATURE_RANGES['payload_size']['max']
        feature_vector[3] = state[3] * FEATURE_RANGES['msg_rate_per_min']['max']
        feature_vector[4] = state[4] * FEATURE_RANGES['req_rate_per_min']['max']
        feature_vector[5] = state[5] * FEATURE_RANGES['session_duration_s']['max']
        feature_vector[6] = state[6] * FEATURE_RANGES['pps']['max']

        # Protocol one-hot (indices 7-12)
        protocol_idx = info.get('protocol_idx', 0)
        feature_vector[7 + protocol_idx] = 1.0

        return feature_vector.reshape(1, -1)

    def _score_binary(self, feature_vector):
        """Score with XGBoost binary classifier. Returns P(attack)."""
        if self._binary_model is None:
            # Fallback: simulate based on dataset detection rate
            return np.random.beta(8, 2)  # Biased toward high detection (99% model)
        try:
            proba = self._binary_model.predict_proba(feature_vector)
            return float(proba[0, 1])  # P(attack)
        except Exception:
            return np.random.beta(8, 2)

    def _score_autoencoder(self, feature_vector):
        """Score with autoencoder. Returns reconstruction error."""
        if self._autoencoder is None or self._scaler is None:
            # Fallback: simulate reconstruction error
            return np.random.exponential(0.05)
        try:
            scaled = self._scaler.transform(feature_vector)
            reconstructed = self._autoencoder.predict(scaled, verbose=0)
            error = np.mean((scaled - reconstructed) ** 2)
            return float(error)
        except Exception:
            return np.random.exponential(0.05)
