# Offensive RL Pentest Simulation
## PFE 2025 — AI-Driven IoT Smart-Home Honeypot

---

### Overview

Reinforcement Learning agent built with DQN (Deep Q-Network) via `stable-baselines3` that learns to attack an IoT honeypot across multiple protocols (MQTT, HTTP, CoAP, SSH, CoAP, Network). The agent was trained on a real honeypot dataset collected from a GCP-hosted multi-protocol honeypot and operates in three distinct modes.

**Important framing:** while the agent is capable of executing real attack primitives against the live honeypot, its primary purpose in this project is to act as a **defensive model stress-tester** — generating adversarial traffic that challenges the detection pipeline built in the `defensive/` module. The offensive system is the evaluation tool; the defensive AI is the core contribution.

The agent does not simulate a full penetration test kill-chain (reconnaissance → exploitation → privilege escalation → exfiltration). It operates at the individual action level, selecting attack primitives to maximise reward. This is intentional — the goal is to generate diverse, adversarially optimised traffic against the defensive models, not to replicate human attacker methodology.

---

### Architecture

```
Offensive/
├── config.py                        # Dataset-derived constants & hyperparameters
├── train.py                         # Main training script
├── evaluate.py                      # Evaluation & visualization
├── requirements.txt                 # Python dependencies
├── src/
│   ├── environment/
│   │   ├── honeypot_env.py          # Gymnasium-compatible RL environment
│   │   └── live_connector.py        # Real packet translation (Phase 1)
│   ├── agents/
│   │   └── dqn_agent.py            # DQN agent (stable-baselines3)
│   ├── reward_engine/
│   │   └── reward.py               # Reward computation with defensive model integration
│   └── utils/
│       └── dataset_stats.py        # Dataset analysis & statistics extraction
├── models/                          # Saved trained models
└── results/                         # Evaluation plots & metrics
```

---

### Two-Phase Testing

#### Phase 1 — Live Honeypot (`mode=live`)
The agent sends real network packets to the hosted honeypot machine using:
- `paramiko` for SSH brute-force and command execution
- `paho-mqtt` for MQTT connect, subscribe, publish, and topic enumeration
- `requests` for HTTP scanning, path traversal, and brute-force
- `socket` for TCP SYN scan, port scan, and CoAP probing

Requires SSH tunnel open:
```bash
ssh -L 9200:172.22.0.2:9200 honeypot-gcp@35.205.229.51 -p 22222
```

#### Phase 2 — Against Defensive AI (`mode=adversarial`)
The reward engine loads the three trained defensive models from `defensive/`:
- XGBoost binary classifier (`xgboost_binary.pkl`)
- XGBoost multiclass classifier (`xgboost_multiclass.pkl`)
- Keras autoencoder anomaly detector (`autoencoder_anomaly.keras`)

Every state transition is scored by all three models. If any model flags the action as an attack, an additional detection penalty is applied. The agent must learn to act in a way that fools all three simultaneously.

---

### Modes

| Mode | Description |
|------|-------------|
| `simulation` | Agent trains against dataset-derived probabilities (coin-flip style) |
| `live` | Agent sends real packets to the hosted honeypot machine |
| `adversarial` | Agent scored by the real defensive AI models in real time |

### Difficulty Levels

| Level | Detection Prob | Max Steps | Defense Model |
|-------|---------------|-----------|---------------|
| `easy` | 30% | 100 | None |
| `medium` | 60% | 75 | Binary XGBoost |
| `hard` | 90% | 50 | Binary + Multiclass + Autoencoder |

---

### Usage

```bash
# Install dependencies
pip install -r requirements.txt

# Train (single difficulty)
python train.py --difficulty medium --mode simulation --timesteps 50000

# Progressive training (easy → medium → hard → adversarial)
python train.py --progressive

# Evaluate
python evaluate.py --model models/dqn_hard_simulation --difficulty hard --episodes 50

# Compare difficulties
python evaluate.py --model models/dqn_hard_simulation --compare

# Live mode (requires SSH tunnel to honeypot)
python train.py --difficulty hard --mode live --timesteps 10000
```

---

### Action Space (18 discrete actions)

| ID | Action | Protocol | Noise Level |
|----|--------|----------|-------------|
| 0 | mqtt_connect | MQTT | Low |
| 1 | mqtt_subscribe_wildcard | MQTT | Medium |
| 2 | mqtt_publish_flood | MQTT | High |
| 3 | mqtt_topic_enum | MQTT | Medium |
| 4 | mqtt_large_payload | MQTT | High |
| 5 | http_get_scan | HTTP | Medium |
| 6 | http_post_exploit | HTTP | Medium |
| 7 | http_path_traversal | HTTP | Medium |
| 8 | http_brute_force | HTTP | High |
| 9 | http_large_payload | HTTP | High |
| 10 | coap_get_discover | CoAP | Low |
| 11 | coap_path_scan | CoAP | Medium |
| 12 | coap_flood | CoAP | High |
| 13 | tcp_syn_scan | TCP | Medium |
| 14 | tcp_port_scan | TCP | Medium |
| 15 | tcp_ssh_brute | TCP | High |
| 16 | tcp_exploit_attempt | TCP | Medium |
| 17 | icmp_ping_sweep | Network | Low |

---

### Observation Space (24-dim continuous)

| Dims | Feature | Description |
|------|---------|-------------|
| 0–6 | Traffic features | bytes_sent, bytes_received, payload, msg_rate, req_rate, duration, pps (normalized) |
| 7–12 | Protocol one-hot | Current protocol being targeted |
| 13 | Stealth level | 1.0 = fully stealthy, 0.0 = fully exposed |
| 14 | Attack progress | Cumulative success indicator |
| 15 | Steps remaining | Normalized countdown |
| 16 | Consecutive successes | Momentum indicator |
| 17 | Consecutive failures | Encourages strategy change |
| 18 | Detection alert | Defensive system suspicion level |
| 19–23 | Action history | Last 5 actions (normalized) |

---

### Evaluation Results — HARD Difficulty (50 episodes)

Three models were trained and evaluated at `hard` difficulty, one per mode.

#### Simulation (`dqn_hard_simulation`)

| Metric | Value |
|--------|-------|
| Avg Reward | 45.50 ± 15.18 |
| Avg Steps | 47.3 / 50 |
| Detection Rate | 8% |
| Action Success Rate | 39.4% |

The agent learned to favour low-noise recon actions (`tcp_syn_scan`, `coap_get_discover`, `mqtt_subscribe_wildcard`) to stay below the detection threshold. 92% of episodes completed without detection. The few detected episodes were caused by high-noise actions early in training that the agent later learned to avoid.

#### Live (`dqn_hard_live`)

| Metric | Value |
|--------|-------|
| Avg Reward | 43.04 ± 14.20 |
| Avg Steps | 50.0 / 50 (always full episode) |
| Detection Rate | 0% |
| Action Success Rate | 64.7% |

The agent operated against the real hosted honeypot machine and was never detected across all 50 episodes. It completed the full 50-step episode every time. Preferred actions were `mqtt_topic_enum`, `http_path_traversal`, `mqtt_connect`, and `tcp_port_scan` — real low-noise recon and enumeration primitives that successfully interacted with the live services. The 64.7% real-world success rate confirms the agent's actions landed on real honeypot services and produced valid responses.

Note: the agent did not execute chained attack sequences (e.g. SSH login → privilege escalation → exfiltration). It selected individual attack primitives independently. This is consistent with the agent's role as a defensive model stress-tester rather than a full kill-chain pentester.

#### Adversarial (`dqn_hard_adversarial`)

| Metric | Value |
|--------|-------|
| Avg Reward | −4.32 ± 2.20 |
| Avg Steps | 1.0 / 50 |
| Detection Rate | 100% |
| Action Success Rate | 48% |

The agent was detected and terminated on the first step of every single episode. This is the most important result of the entire offensive module — not as a failure of the agent, but as **validation of the defensive AI**.

The XGBoost classifier and autoencoder anomaly detector identified and flagged the agent's behavior before it could execute a second action, across 100% of episodes. Even an adversarially optimised RL attacker — one that had already learned to evade probabilistic rules (simulation) and operate undetected against the live machine (live) — could not survive a single step against the trained defensive models.

> **This result is the conclusion of the project.** The defensive AI is strong enough to neutralise an adaptive, trained attacker instantly and consistently.

---

### Summary Table

| Mode | Avg Reward | Detection Rate | Avg Steps | Interpretation |
|------|-----------|----------------|-----------|----------------|
| Simulation | 45.50 | 8% | 47.3 | Agent learned stealth against probabilistic rules |
| Live | 43.04 | 0% | 50.0 | Agent operated undetected on real honeypot |
| Adversarial | −4.32 | 100% | 1.0 | Defensive AI neutralised agent on first step every time |

---

### Key Design Decisions

1. **Dataset-driven**: all feature ranges, success probabilities, protocol weights, and detection thresholds are extracted from the real 244K-row honeypot dataset — no hardcoded guesses
2. **Real defensive integration**: in adversarial mode, the reward engine loads the actual trained XGBoost and autoencoder models and scores every state transition in real time
3. **Protocol-aware actions**: each of the 18 actions maps to a real protocol operation, enabling seamless transition from simulation to live mode
4. **Progressive curriculum**: training easy → medium → hard teaches the agent basic exploitation before requiring stealth
5. **Timeout-safe live connector**: all network calls run inside a thread pool with hard wall-clock timeouts — no hanging on unresponsive services
