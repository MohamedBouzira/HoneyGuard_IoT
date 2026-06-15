# ================================================================
# Honeypot Pentest Environment — Gymnasium-Compatible
# Simulates multi-protocol IoT honeypot attack surface
# Modes: simulation | live | adversarial
# ================================================================
import gymnasium as gym
from gymnasium import spaces
import numpy as np
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))
from config import (
    NUM_ACTIONS, STATE_DIM, DIFFICULTY_CONFIGS, MAX_STEPS_PER_EPISODE,
    PROTOCOLS, ATTACK_TYPES, FEATURE_RANGES, ALL_ATTACK_TYPES,
)
from src.reward_engine.reward import RewardEngine
from src.environment.live_connector import LiveConnector
from src.utils.dataset_stats import (
    compute_attack_success_rates,
    compute_transition_matrix,
    compute_detection_thresholds,
    get_protocol_action_map,
)


class HoneypotPentestEnv(gym.Env):
    """
    RL Environment simulating an IoT honeypot attack scenario.

    Observation Space (24-dim continuous):
        [0-6]   Current traffic features (normalized)
        [7-12]  Protocol one-hot (6 protocols)
        [13]    Current stealth level (0-1)
        [14]    Attack progress (0-1)
        [15]    Steps remaining (normalized)
        [16]    Consecutive successes
        [17]    Consecutive failures
        [18]    Detection alert level (0-1)
        [19-23] Action history embedding (last 5 actions normalized)

    Action Space (18 discrete):
        0-4:   MQTT actions (connect, subscribe_wildcard, publish_flood, topic_enum, large_payload)
        5-9:   HTTP actions (get_scan, post_exploit, path_traversal, brute_force, large_payload)
        10-12: CoAP actions (get_discover, path_scan, flood)
        13-16: TCP actions (syn_scan, port_scan, ssh_brute, exploit_attempt)
        17:    Network action (icmp_ping_sweep)

    Difficulty: easy | medium | hard
    Mode: simulation | live | adversarial
    """

    metadata = {'render_modes': ['human', 'ansi']}

    def __init__(self, difficulty='medium', mode='simulation', render_mode=None):
        super().__init__()

        self.difficulty = difficulty
        self.mode = mode
        self.render_mode = render_mode
        self.config = DIFFICULTY_CONFIGS[difficulty]

        # Spaces
        self.action_space = spaces.Discrete(NUM_ACTIONS)
        self.observation_space = spaces.Box(
            low=0.0, high=1.0, shape=(STATE_DIM,), dtype=np.float32
        )

        # Reward engine
        self.reward_engine = RewardEngine(difficulty=difficulty, mode=mode)

        # Live connector (only for live mode)
        self._live_connector = None
        if mode == 'live':
            from config import HONEYPOT_TARGET
            self._live_connector = LiveConnector(
                target_ip=HONEYPOT_TARGET['ip'],
                ssh_port=HONEYPOT_TARGET['ssh_port'],
                mqtt_port=HONEYPOT_TARGET['mqtt_port'],
                http_port=HONEYPOT_TARGET['http_port'],
                coap_port=HONEYPOT_TARGET['coap_port'],
                timeout=1,
            )

        # Action map
        self.action_map = get_protocol_action_map()
        self.action_names = self._build_action_names()

        # Dataset-derived parameters
        self._success_rates = None
        self._transition_matrix = None
        self._detection_thresholds = None
        self._load_dataset_stats()

        # Episode state
        self.current_step = 0
        self.max_steps = self.config['max_steps']
        self.state = None
        self.attack_history = []
        self.total_reward = 0.0
        self.detected = False

    def _build_action_names(self):
        """Flatten action map to list indexed by action ID."""
        names = [''] * NUM_ACTIONS
        for proto, actions in self.action_map.items():
            for idx, name in actions.items():
                names[idx] = name
        return names

    def _load_dataset_stats(self):
        """Load precomputed dataset statistics."""
        try:
            from src.utils.dataset_stats import load_dataset
            df = load_dataset()
            self._success_rates = compute_attack_success_rates(df)
            self._transition_matrix = compute_transition_matrix(df)
            self._detection_thresholds = compute_detection_thresholds(df)
        except Exception as e:
            print(f'[HoneypotEnv] Using fallback stats: {e}')
            self._success_rates = {at: 0.3 for at in ALL_ATTACK_TYPES}
            self._transition_matrix = {p: {q: 1.0/len(PROTOCOLS) for q in PROTOCOLS} for p in PROTOCOLS}
            self._detection_thresholds = {}

    def reset(self, seed=None, options=None):
        """Reset environment for new episode."""
        super().reset(seed=seed)

        self.current_step = 0
        self.total_reward = 0.0
        self.detected = False
        self.attack_history = []

        # Initialize state: agent starts with reconnaissance
        self.state = np.zeros(STATE_DIM, dtype=np.float32)
        self.state[13] = 1.0  # Full stealth at start
        self.state[15] = 1.0  # All steps remaining

        # Random initial protocol (weighted by dataset distribution)
        initial_proto = self.np_random.choice(
            len(PROTOCOLS),
            p=[0.25, 0.38, 0.18, 0.17, 0.01, 0.01]
        )
        self.state[7 + initial_proto] = 1.0
        self._current_protocol_idx = initial_proto

        info = {'episode_start': True, 'protocol': PROTOCOLS[initial_proto]}
        return self.state.copy(), info

    def step(self, action):
        """Execute one attack action."""
        assert self.action_space.contains(action), f'Invalid action: {action}'

        self.current_step += 1
        action_name = self.action_names[action]

        # Determine action properties
        info = self._execute_action(action, action_name)

        # Compute reward
        reward, detected = self.reward_engine.compute_reward(
            self.state, action, self.state, info
        )

        # Update state based on action outcome
        self._update_state(action, info)

        # Check termination
        self.detected = detected
        terminated = detected  # Episode ends if detected
        truncated = self.current_step >= self.max_steps

        self.total_reward += reward
        self.attack_history.append({
            'step': self.current_step,
            'action': action_name,
            'reward': reward,
            'detected': detected,
            'success': info.get('success', False),
        })

        info['total_reward'] = self.total_reward
        info['steps_taken'] = self.current_step

        return self.state.copy(), reward, terminated, truncated, info

    def _execute_action(self, action, action_name):
        """
        Simulate action execution. Returns info dict with outcome.
        In live mode, dispatches real network packets via LiveConnector.
        """
        info = {
            'action_type': self._get_action_category(action_name),
            'action_name': action_name,
            'protocol': PROTOCOLS[self._current_protocol_idx],
            'protocol_idx': self._current_protocol_idx,
        }

        # --- Live mode: use real connector ---
        if self.mode == 'live' and self._live_connector is not None:
            live_result = self._live_connector.execute(action_name)
            info['success'] = live_result.get('success', False)
            info['response'] = live_result.get('response', {})
            info['noise_level'] = self._get_noise_level(action_name)
            info['stealth_score'] = float(self.state[13])
            # Carry over protocol-specific fields
            for key in ['subscribed', 'messages_received', 'auth_success',
                        'banner_grabbed', 'protocol']:
                if key in live_result:
                    info[key] = live_result[key]
            # Track consecutive outcomes
            if info['success']:
                info['consecutive_failures'] = 0
                consecutive_success = int(self.state[16] * 10) + 1
                info['attack_progress'] = min(consecutive_success / 10.0, 1.0)
            else:
                info['consecutive_failures'] = int(self.state[17] * 10) + 1
                info['attack_progress'] = float(self.state[14])
            return info

        # --- Simulation / adversarial mode ---

        # Determine success based on dataset-derived rates
        success_prob = self._get_success_probability(action, action_name)

        # Stealth affects success (aggressive actions more likely to fail)
        noise_level = self._get_noise_level(action_name)
        info['noise_level'] = noise_level
        info['stealth_score'] = float(self.state[13])

        # Roll for success
        success = self.np_random.random() < success_prob
        info['success'] = success

        # Track consecutive outcomes
        if success:
            info['consecutive_failures'] = 0
            consecutive_success = int(self.state[16] * 10) + 1
            info['attack_progress'] = min(consecutive_success / 10.0, 1.0)
        else:
            info['consecutive_failures'] = int(self.state[17] * 10) + 1
            info['attack_progress'] = float(self.state[14])

        return info

    def _update_state(self, action, info):
        """Update state vector after action execution."""
        # Update traffic features (simulate realistic values)
        self._simulate_traffic_features(action, info)

        # Update protocol one-hot (may switch protocol)
        if self.np_random.random() < 0.2:  # 20% chance to switch protocol
            self.state[7:13] = 0.0
            new_proto = self.np_random.choice(len(PROTOCOLS))
            self.state[7 + new_proto] = 1.0
            self._current_protocol_idx = new_proto

        # Update stealth (decreases with noisy actions, recovers with quiet ones)
        noise = info.get('noise_level', 0.5)
        if noise < 0.3:
            # Quiet actions allow partial stealth recovery
            self.state[13] = np.clip(self.state[13] + 0.03, 0.0, 1.0)
        else:
            self.state[13] = np.clip(self.state[13] - noise * 0.05, 0.0, 1.0)

        # Update attack progress
        if info.get('success', False):
            self.state[14] = np.clip(self.state[14] + 0.1, 0.0, 1.0)
            self.state[16] = np.clip(self.state[16] + 0.1, 0.0, 1.0)  # Consecutive success
            self.state[17] = 0.0  # Reset failures
        else:
            self.state[17] = np.clip(self.state[17] + 0.1, 0.0, 1.0)  # Consecutive failure

        # Update steps remaining
        self.state[15] = 1.0 - (self.current_step / self.max_steps)

        # Update detection alert level
        if info.get('noise_level', 0) > 0.7:
            self.state[18] = np.clip(self.state[18] + 0.08, 0.0, 1.0)
        elif info.get('noise_level', 0) < 0.3:
            self.state[18] = np.clip(self.state[18] - 0.1, 0.0, 1.0)
        else:
            self.state[18] = np.clip(self.state[18] - 0.02, 0.0, 1.0)

        # Update action history (last 5 actions, normalized)
        normalized_action = action / NUM_ACTIONS
        self.state[19:23] = self.state[20:24]  # Shift left
        self.state[23] = normalized_action

    def _simulate_traffic_features(self, action, info):
        """Generate realistic traffic features based on action type."""
        action_name = self.action_names[action]

        # Base feature generation (normalized to [0, 1])
        if 'flood' in action_name or 'ddos' in action_name or 'large_payload' in action_name:
            self.state[0] = np.clip(self.np_random.beta(5, 2), 0, 1)   # High bytes_sent
            self.state[2] = np.clip(self.np_random.beta(4, 2), 0, 1)   # High payload
            self.state[4] = np.clip(self.np_random.beta(6, 1), 0, 1)   # High req rate
        elif 'scan' in action_name or 'enum' in action_name:
            self.state[0] = np.clip(self.np_random.beta(2, 5), 0, 1)   # Low bytes
            self.state[2] = np.clip(self.np_random.beta(1, 5), 0, 1)   # Low payload
            self.state[4] = np.clip(self.np_random.beta(3, 2), 0, 1)   # Medium-high rate
        elif 'brute' in action_name:
            self.state[0] = np.clip(self.np_random.beta(2, 4), 0, 1)   # Low-medium bytes
            self.state[4] = np.clip(self.np_random.beta(5, 2), 0, 1)   # High rate
            self.state[5] = np.clip(self.np_random.beta(3, 3), 0, 1)   # Medium duration
        elif 'exploit' in action_name or 'traversal' in action_name:
            self.state[0] = np.clip(self.np_random.beta(3, 3), 0, 1)   # Medium bytes
            self.state[2] = np.clip(self.np_random.beta(3, 2), 0, 1)   # Medium-high payload
            self.state[4] = np.clip(self.np_random.beta(2, 4), 0, 1)   # Low rate (stealthy)
        else:
            # Default: low-profile action
            self.state[0] = np.clip(self.np_random.beta(1, 5), 0, 1)
            self.state[2] = np.clip(self.np_random.beta(1, 5), 0, 1)
            self.state[4] = np.clip(self.np_random.beta(1, 3), 0, 1)

        # bytes_received (always low for attacker)
        self.state[1] = np.clip(self.np_random.beta(1, 10), 0, 1)
        # pps
        self.state[6] = np.clip(self.np_random.beta(2, 8), 0, 1)

    def _get_success_probability(self, action, action_name):
        """Get success probability based on dataset-derived rates."""
        # Map action to closest attack type
        action_to_attack = {
            'mqtt_connect': 'unknown_client',
            'mqtt_subscribe_wildcard': 'wildcard_scan',
            'mqtt_publish_flood': 'ddos',
            'mqtt_topic_enum': 'topic_anomaly',
            'mqtt_large_payload': 'large_payload',
            'http_get_scan': 'endpoint_scan',
            'http_post_exploit': 'exploit',
            'http_path_traversal': 'path_traversal',
            'http_brute_force': 'brute_force',
            'http_large_payload': 'large_payload',
            'coap_get_discover': 'path_scan',
            'coap_path_scan': 'path_scan',
            'coap_flood': 'ddos',
            'tcp_syn_scan': 'scan',
            'tcp_port_scan': 'port_scan',
            'tcp_ssh_brute': 'brute_force',
            'tcp_exploit_attempt': 'exploit',
            'icmp_ping_sweep': 'scan',
        }

        attack_type = action_to_attack.get(action_name, 'unknown')
        base_rate = self._success_rates.get(attack_type, 0.3)

        # Modify by difficulty
        if self.difficulty == 'easy':
            return min(base_rate * 1.5, 0.95)
        elif self.difficulty == 'hard':
            return max(base_rate * 0.6, 0.05)
        return base_rate

    def _get_noise_level(self, action_name):
        """Determine how noisy/detectable an action is."""
        noisy_actions = ['flood', 'ddos', 'large_payload', 'brute']
        medium_actions = ['scan', 'enum', 'port_scan', 'syn_scan']
        quiet_actions = ['connect', 'get', 'discover', 'subscribe']

        if any(n in action_name for n in noisy_actions):
            return 0.8 + self.np_random.random() * 0.2
        elif any(n in action_name for n in medium_actions):
            return 0.4 + self.np_random.random() * 0.3
        elif any(n in action_name for n in quiet_actions):
            return 0.1 + self.np_random.random() * 0.2
        return 0.5

    def _get_action_category(self, action_name):
        """Categorize action for reward computation."""
        if 'scan' in action_name or 'enum' in action_name or 'discover' in action_name:
            return 'reconnaisance'
        elif 'brute' in action_name:
            return 'brute_force'
        elif 'exploit' in action_name or 'traversal' in action_name:
            return 'exploit'
        elif 'flood' in action_name or 'ddos' in action_name:
            return 'dos'
        return 'unknown'

    def render(self):
        """Render current state."""
        if self.render_mode == 'human':
            proto = PROTOCOLS[self._current_protocol_idx]
            last_action = self.attack_history[-1] if self.attack_history else None
            print(f'Step {self.current_step}/{self.max_steps} | '
                  f'Protocol: {proto} | '
                  f'Stealth: {self.state[13]:.2f} | '
                  f'Progress: {self.state[14]:.2f} | '
                  f'Alert: {self.state[18]:.2f} | '
                  f'Reward: {self.total_reward:.2f}')
            if last_action:
                status = '✓' if last_action['success'] else '✗'
                print(f'  Last: {last_action["action"]} [{status}]')

    def get_episode_summary(self):
        """Return summary of the episode."""
        return {
            'total_reward': self.total_reward,
            'steps_taken': self.current_step,
            'detected': self.detected,
            'actions_taken': len(self.attack_history),
            'successful_actions': sum(1 for a in self.attack_history if a['success']),
            'final_stealth': float(self.state[13]),
            'final_progress': float(self.state[14]),
            'attack_history': self.attack_history,
        }
