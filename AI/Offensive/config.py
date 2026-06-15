# ================================================================
# Offensive RL Pentest — Configuration
# All magic numbers derived from honeypot dataset analysis
# ================================================================
import os

# --- Paths ---
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, '..', 'Data')
MODELS_DIR = os.path.join(BASE_DIR, '..', 'Defensive')
DATASET_PATH = os.path.join(BASE_DIR, '..', 'honeypot_dataset.csv')

# --- Dataset-Derived Constants ---
# Protocols and their distributions (from dataset analysis)
PROTOCOLS = ['MQTT', 'HTTP', 'CoAP', 'TCP', 'ICMP', 'UDP']
PROTOCOL_WEIGHTS = {
    'HTTP': 0.378, 'MQTT': 0.250, 'TCP': 0.195,
    'CoAP': 0.176, 'ICMP': 0.001, 'UDP': 0.0002
}

# Attack types per protocol (from dataset groupby)
ATTACK_TYPES = {
    'MQTT': ['wildcard_scan', 'topic_anomaly', 'unknown_client', 'ddos'],
    'HTTP': ['endpoint_scan', 'large_payload', 'path_traversal',
             'unknown_external', 'ddos', 'unknown', 'brute_force'],
    'CoAP': ['path_scan', 'unknown', 'ddos'],
    'TCP': ['scan', 'port_scan', 'exploit', 'brute_force', 'ddos'],
    'ICMP': ['ddos'],
    'UDP': ['ddos'],
}

ALL_ATTACK_TYPES = [
    'endpoint_scan', 'path_scan', 'wildcard_scan', 'unknown_external',
    'ddos', 'topic_anomaly', 'scan', 'brute_force', 'path_traversal',
    'exploit', 'unknown', 'unknown_client', 'port_scan', 'large_payload'
]

# Numeric feature ranges (from df.describe())
FEATURE_RANGES = {
    'bytes_sent':        {'min': 0, 'max': 199785, 'mean': 6177.8, 'std': 28506.3},
    'bytes_received':    {'min': 0, 'max': 1000, 'mean': 0.41, 'std': 16.3},
    'payload_size':      {'min': 0, 'max': 4988, 'mean': 30.7, 'std': 81.7},
    'msg_rate_per_min':  {'min': 0, 'max': 498, 'mean': 2.05, 'std': 6.4},
    'req_rate_per_min':  {'min': 0, 'max': 3000, 'mean': 80.4, 'std': 336.1},
    'session_duration_s': {'min': 0, 'max': 87245.7, 'mean': 11941.9, 'std': 22162.6},
    'pps':               {'min': 0, 'max': 24.6, 'mean': 0.044, 'std': 0.24},
}

# Detection rates (from defensive model evaluation)
DETECTION_RATES = {
    'binary_accuracy': 0.99,
    'multiclass_accuracy': 0.94,
    'autoencoder_auc': 0.96,
}

# --- Environment Parameters ---
MAX_STEPS_PER_EPISODE = 50
NUM_ACTIONS = 18  # Total discrete actions available to agent

# State space dimensions
STATE_DIM = 24  # Features describing current attack state

# Difficulty settings
DIFFICULTY_CONFIGS = {
    'easy': {
        'detection_probability': 0.3,
        'reward_scale': 1.0,
        'max_steps': 100,
        'defense_model': None,
    },
    'medium': {
        'detection_probability': 0.6,
        'reward_scale': 1.5,
        'max_steps': 75,
        'defense_model': 'binary',
    },
    'hard': {
        'detection_probability': 0.9,
        'reward_scale': 2.0,
        'max_steps': 50,
        'defense_model': 'all',  # binary + multiclass + autoencoder
    },
}

# --- Live Mode (Phase 1) ---
HONEYPOT_TARGET = {
    'ip': '34.175.36.181',  # Public IP of GCP honeypot VM
    'ssh_port': 22,        # Cowrie SSH
    'mqtt_port': 1883,     # MQTT broker
    'http_port': 8080,     # HTTP honeypot
    'coap_port': 5683,     # CoAP honeypot
}

# --- Training Hyperparameters ---
DQN_CONFIG = {
    'learning_rate': 1e-4,
    'buffer_size': 100000,
    'batch_size': 64,
    'gamma': 0.99,
    'exploration_fraction': 0.3,
    'exploration_final_eps': 0.05,
    'target_update_interval': 1000,
    'train_freq': 4,
    'gradient_steps': 1,
    'learning_starts': 1000,
    'policy_kwargs': {'net_arch': [256, 256, 128]},
}
