<p align="center">
  <img src="https://img.shields.io/badge/Status-Active-success" alt="Status">
  <img src="https://img.shields.io/badge/Python-3.11-blue" alt="Python">
  <img src="https://img.shields.io/badge/AI-XGBoost%20%7C%20TensorFlow%20%7C%20DQN-orange" alt="AI">
  <img src="https://img.shields.io/badge/Infrastructure-Docker%20%7C%20ELK-blueviolet" alt="Infra">
  <img src="https://img.shields.io/badge/Protocols-MQTT%20%7C%20CoAP%20%7C%20HTTP%20%7C%20SSH-red" alt="Protocols">
  <img src="https://img.shields.io/badge/License-MIT-lightgrey" alt="License">
</p>

# HoneyGuard_IoT 🔐

**AI-Driven IoT Smart-Home Honeypot for Defensive Detection & Offensive Attack Simulation**

HoneyGuard_IoT is a full-stack cybersecurity research platform that deploys a realistic **multi-protocol IoT smart-home honeypot**, collects real attacker traffic in the wild, and uses **machine learning** to detect intrusions while simultaneously training a **reinforcement learning pentest agent** to probe its own defenses.

---

## Architecture

```
                            ┌──────────────────────────────────────┐
                            │         INTERNET / ATTACKERS         │
                            └──────────────┬───────────────────────┘
                                           │ SSH ─ MQTT ─ CoAP ─ HTTP
                                           ▼
┌──────────────────────────────────────────────────────────────────────┐
│                          honeypot_net (172.20.0.0/24)                │
│                                                                      │
│  ┌─────────────────────────────────────────────────────────────┐     │
│  │                     main-server (172.20.0.2)                │     │
│  │  ┌────────┐  ┌──────────┐  ┌──────────┐  ┌──────────────┐ │     │
│  │  │ Cowrie │  │ Mosquitto│  │ CoAP     │  │ Flask HTTP   │ │     │
│  │  │SSH/Tel │  │ MQTT     │  │ (aiocoap) │  │ IoT Platform │ │     │
│  │  │ :22/23 │  │ :1883    │  │ :5683/udp│  │ :80 / :8080  │ │     │
│  │  └────────┘  └──────────┘  └──────────┘  └──────────────┘ │     │
│  │  ┌──────────┐  ┌──────────┐  ┌──────────────────────────┐ │     │
│  │  │ TShark   │  │ MQTT     │  │ Supervisor (orchestrator)│ │     │
│  │  │ Capture  │  │ Logger   │  └──────────────────────────┘ │     │
│  │  └──────────┘  └──────────┘                               │     │
│  └─────────────────────────────────────────────────────────────┘     │
│                                                                      │
│  ┌────────┐  ┌──────┐  ┌───────────┐  ┌─────────┐                 │
│  │ Camera │  │ Lock │  │ Thermostat│  │ Alarm   │  ... 8 IoT      │
│  │ HTTP   │  │ MQTT │  │ MQTT      │  │ MQTT    │      devices    │
│  └────────┘  └──────┘  └───────────┘  └─────────┘                 │
└────────────────────────────┬─────────────────────────────────────────┘
                             │ Filebeat
                             ▼
┌──────────────────────────────────────────────────────────────────────┐
│                      elk_net (172.22.0.0/24)                         │
│                    (internal — no internet route)                     │
│                                                                      │
│  ┌──────────────────────────────────────────────────────────┐       │
│  │                    ELK Stack (sebp/elk:8.6.0)            │       │
│  │  ┌──────────────┐  ┌──────────┐  ┌──────────────────┐   │       │
│  │  │ Logstash     │→ │Elastic   │→ │ Kibana (:5601)   │   │       │
│  │  │ (:5044)      │  │search    │  │ Visualize & Query │   │       │
│  │  └──────────────┘  │(:9200)   │  └──────────────────┘   │       │
│  │                     └──────────┘                        │       │
│  └──────────────────────────────────────────────────────────┘       │
└──────────────────────────────────────────────────────────────────────┘
                             │ export_data.py
                             ▼
              ┌─────────────────────────────┐
              │  honeypot_dataset.csv        │
              │  244,085 rows × 46 columns   │
              └──────────┬──────────────────┘
                         │
              ┌──────────┴──────────┐
              ▼                     ▼
┌─────────────────────┐   ┌──────────────────────┐
│  DEFENSIVE AI       │   │  OFFENSIVE RL (DQN)  │
│  ┌───────────────┐  │   │  ┌────────────────┐  │
│  │ XGBoost       │  │   │  │ Gymnasium Env  │  │
│  │ Binary        │──┼───┼─▶│ 18 actions     │  │
│  │ (99% AUC)     │  │   │  │ 24-dim state   │  │
│  ├───────────────┤  │   │  │ 3 difficulty   │  │
│  │ XGBoost       │  │   │  │ levels          │  │
│  │ Multiclass    │  │   │  └────────────────┘  │
│  │ (94% F1)      │  │   │  ┌────────────────┐  │
│  ├───────────────┤  │   │  │ 3 Modes:       │  │
│  │ Autoencoder   │  │   │  │ • Simulation   │  │
│  │ Anomaly Det.  │  │   │  │ • Live Attack  │  │
│  │ (96% AUC)     │  │   │  │ • Adversarial  │  │
│  └───────────────┘  │   │  └────────────────┘  │
└─────────────────────┘   └──────────────────────┘
```

---

## Quick Start

### Prerequisites

- Docker & Docker Compose v2
- Minimum 8 GB RAM (16 GB recommended)
- 20 GB free disk space

### Deploy the Honeypot

```bash
cd Conception
sudo docker-compose up --build -d
```

This spins up **11 containers**:

| Container       | IP             | Role                          |
|-----------------|----------------|-------------------------------|
| main-server     | 172.20.0.2    | Cowrie, Mosquitto, CoAP, HTTP |
| sim-camera      | 172.20.0.10   | HTTP camera simulator         |
| sim-lock        | 172.20.0.11   | MQTT smart lock               |
| sim-alarm       | 172.20.0.12   | MQTT alarm system             |
| sim-thermostat  | 172.20.0.13   | MQTT thermostat               |
| sim-smartplug   | 172.20.0.14   | MQTT smart plug               |
| sim-motion      | 172.20.0.15   | CoAP motion sensor            |
| sim-doorbell    | 172.20.0.16   | HTTP doorbell                 |
| sim-lightbulb   | 172.20.0.17   | CoAP lightbulb                |
| elk             | 172.22.0.2    | Elasticsearch + Logstash + Kibana |
| filebeat        | 172.20.0.20   | Log shipping (dual-network)   |

### Access Services

| Service       | Host Port     | Protocol            |
|---------------|---------------|---------------------|
| SSH Honeypot  | `2222`        | SSH                 |
| Telnet Honeypot| `2323`       | Telnet              |
| MQTT Broker   | `1883`        | MQTT                |
| CoAP Server   | `5683/udp`    | CoAP                |
| IoT Dashboard | `80`          | HTTP (SmartHome UI) |
| Device API    | `8080`        | HTTP                |
| Kibana        | `5601`        | via SSH tunnel      |

```bash
# Access Kibana through SSH tunnel
ssh -L 5601:172.22.0.2:5601 user@your-vm
# Then open http://localhost:5601
```

---

## Project Structure

```
HoneyGuard_IoT/
├── Conception/                      # Docker infrastructure
│   ├── docker-compose.yml           # 11-container orchestration
│   ├── Network_Topology.txt         # Full network map
│   ├── main-server/                 # Central honeypot server
│   │   ├── Dockerfile               # Ubuntu 22.04 + all services
│   │   ├── supervisord.conf         # 7 supervised processes
│   │   └── configs/
│   │       ├── cowrie.cfg           # SSH/Telnet honeypot config
│   │       ├── mosquitto.conf       # MQTT broker config
│   │       ├── coap_server.py       # CoAP honeypot server
│   │       ├── http_server.py       # Flask HTTP honeypot
│   │       ├── mqtt_logger.py      # MQTT subscription logger
│   │       ├── tshark_to_json.py    # Network packet capture
│   │       └── IoT_platform/        # Smart-home dashboard
│   ├── IoT-devices/                 # 8 simulated IoT devices
│   │   ├── camera/                  # HTTP + RTSP (MediaMTX)
│   │   ├── lock/                    # MQTT smart lock
│   │   ├── alarm/                   # MQTT alarm system
│   │   ├── thermostat/              # MQTT temperature sensor
│   │   ├── smartplug/               # MQTT smart plug
│   │   ├── motion/                  # CoAP motion sensor
│   │   ├── doorbell/                # HTTP doorbell
│   │   └── lightbulb/               # CoAP lightbulb
│   └── elk/                         # Log management
│       ├── filebeat.yml             # Log shipping config
│       ├── logstash.conf            # Log parsing pipeline
│       └── elk-init.sh              # ES template initialization
│
├── AI/
│   ├── honeypot_dataset.csv         # 244K balanced labeled dataset
│   ├── Data/                        # Data export & preprocessing
│   │   ├── export_data.py           # Elasticsearch → CSV
│   │   ├── clean_and_balance.py     # SMOTE + downsampling
│   │   └── Report_datascience.md    # Full data science report
│   │
│   ├── Defensive/                   # Detection models
│   │   ├── Xgboost_binary/          # Attack/benign (99% AUC)
│   │   ├── Xgboost_multi/           # 15-class attack type (94% F1)
│   │   └── Autoencoder/             # Anomaly detection (96% AUC)
│   │
│   └── Offensive/                   # RL pentest agent (DQN)
│       ├── train.py                 # Training script
│       ├── evaluate.py              # Evaluation + visualizations
│       ├── src/
│       │   ├── environment/         # Gymnasium RL environment
│       │   ├── agents/              # DQN agent (stable-baselines3)
│       │   └── reward_engine/       # 3-mode reward computation
│       ├── models/                  # Pre-trained checkpoints
│       └── results/                 # Evaluation metrics & plots
│
└── website/                         # Prediction API + demo site
    ├── predict_api.py               # Flask API serving all 3 models
    ├── honeypot-site.html           # Project showcase website
    └── requirements_api.txt         # API dependencies
```

---

## 🤖 AI / ML Models

### Defensive (Detection)

| Model | Task | Features | Performance |
|-------|------|----------|-------------|
| **XGBoost Binary** | Attack vs Benign | 36 | **99% ROC AUC**, 99% accuracy |
| **XGBoost Multiclass** | 15 attack types | 36 | **94% macro F1** |
| **Autoencoder** | Anomaly detection | 35 | **96% ROC AUC** |

**Attack types classified:** `benign`, `brute_force`, `ddos`, `endpoint_scan`, `exploit`, `large_payload`, `path_scan`, `path_traversal`, `port_scan`, `scan`, `topic_anomaly`, `wildcard_scan`, and 3 unknown variants.

**Interactive notebooks** are provided under each model's `notebook/` folder for training from scratch.

### Offensive (Reinforcement Learning)

A **DQN agent** (stable-baselines3) trained to autonomously probe the honeypot across 5 protocol families:

| Protocol   | Attack Actions                                          |
|------------|---------------------------------------------------------|
| **MQTT**   | Connect brute-force, wildcard subscribe, publish flood, topic enumeration |
| **HTTP**   | Endpoint scan, POST exploit, path traversal, brute force, large payload |
| **SSH**    | Credential brute force, command execution               |
| **TCP**    | SYN scan, port scan                                     |
| **CoAP**   | Resource discovery, path scan, message flood            |
| **ICMP**   | Ping sweep                                              |

**3 operation modes:**
- `simulation` — attacks succeed/fail based on dataset probabilities (avg reward: 45.5, detection rate: 8%)
- `live` — sends real packets to the running honeypot (avg reward: 43.0, detection rate: 0%)
- `adversarial` — pitted directly against the defensive AI (detection rate: 100% — validates the defense)

```bash
# Train the RL agent
cd AI/Offensive
python train.py --mode simulation --difficulty hard

# Evaluate a trained model
python evaluate.py --model models/dqn_hard_simulation.zip --mode simulation
```

### Prediction API

```bash
cd website
pip install -r requirements_api.txt
python predict_api.py    # Serves on :5000
```

All three defensive models are served via a single Flask API.

---

## Dataset

`AI/honeypot_dataset.csv` — **244,085 rows × 46 columns** (87.9 MB)

- **Source:** Real attacker traffic from a cloud-deployed honeypot (Google Cloud, April 2026)
- **Raw data:** 2,682,396 rows (98.7% benign, 1.3% attack)
- **Balancing:** Downsampled benign (2.65M → 75,600) + SMOTE oversampled attack classes (12,000 each)
- **Protocols:** MQTT, HTTP, CoAP, SSH/Telnet (Cowrie), Network (tshark), IoT Platform
- **Log pipeline:** Honeypot → JSON logs → Filebeat → Logstash → Elasticsearch → CSV

A **masked version** (with `src_ip` anonymized via hash) is also available for privacy-safe sharing.

---

## Security & Network Isolation

- **Dual-network architecture:** `honeypot_net` (exposed) vs `elk_net` (internal, no internet route)
- **Filebeat** is the only container with dual-network access (reads logs, ships to ELK)
- **Kibana** accessible only via SSH tunnel
- **Cowrie** logs all SSH/Telnet interactions including command history
- **TShark** captures all network-level traffic on the honeypot interface

---

## Built With

- [Cowrie](https://github.com/cowrie/cowrie) — SSH/Telnet honeypot
- [Mosquitto](https://mosquitto.org/) — MQTT broker
- [MediaMTX](https://github.com/bluenviron/mediamtx) — RTSP server
- [ELK Stack](https://www.elastic.co/what-is/elk-stack) — Elasticsearch, Logstash, Kibana
- [Docker Compose](https://docs.docker.com/compose/) — Container orchestration
- [XGBoost](https://xgboost.readthedocs.io/) — Gradient boosting classifiers
- [TensorFlow/Keras](https://www.tensorflow.org/) — Autoencoder anomaly detection
- [stable-baselines3](https://stable-baselines3.readthedocs.io/) — DQN reinforcement learning
- [Gymnasium](https://gymnasium.farama.org/) — RL environment framework
- [Flask](https://flask.palletsprojects.com/) — Web servers & API

---

## Authors

- **Mohamed Bouzira** — [@moncefdevsec](https://github.com/moncefdevsec)
- **Bakhti Rayane Abderaouef**

ESTIN — PFE 2025

---

## License

MIT
