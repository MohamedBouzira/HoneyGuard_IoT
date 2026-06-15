#!/usr/bin/env python3
# ================================================================
# Offensive RL Pentest — Training Script
# Trains DQN agent across difficulty levels and modes
# ================================================================
import os
import sys
import json
import argparse
import numpy as np
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from config import DIFFICULTY_CONFIGS
from src.environment.honeypot_env import HoneypotPentestEnv
from src.agents.dqn_agent import DQNAgent


def train(difficulty='medium', mode='simulation', timesteps=50000, seed=42):
    """Train the DQN agent on the honeypot environment."""
    print('=' * 60)
    print(f'  OFFENSIVE RL PENTEST — TRAINING')
    print(f'  Difficulty: {difficulty} | Mode: {mode}')
    print(f'  Timesteps: {timesteps:,} | Seed: {seed}')
    print('=' * 60)

    # Create environment
    env = HoneypotPentestEnv(difficulty=difficulty, mode=mode)

    # Create agent
    agent = DQNAgent(env, verbose=1)

    # Train
    agent.train(
        total_timesteps=timesteps,
        eval_freq=max(timesteps // 10, 1000),
        n_eval_episodes=10,
    )

    # Save model
    model_name = f'dqn_{difficulty}_{mode}'
    model_path = os.path.join(os.path.dirname(__file__), 'models', model_name)
    agent.save(model_path)

    # Evaluate
    print('\n' + '=' * 60)
    print('  POST-TRAINING EVALUATION')
    print('=' * 60)
    metrics = agent.evaluate(n_episodes=20)

    # Save results
    results_dir = os.path.join(os.path.dirname(__file__), 'results')
    os.makedirs(results_dir, exist_ok=True)
    results_path = os.path.join(results_dir, f'{model_name}_results.json')

    results = {
        'timestamp': datetime.now().isoformat(),
        'difficulty': difficulty,
        'mode': mode,
        'timesteps': timesteps,
        'seed': seed,
        'metrics': {k: v for k, v in metrics.items() if k != 'episodes'},
        'config': DIFFICULTY_CONFIGS[difficulty],
    }

    with open(results_path, 'w') as f:
        json.dump(results, f, indent=2, default=str)
    print(f'\nResults saved to: {results_path}')

    return metrics


def train_progressive():
    """Train agent progressively from easy to hard."""
    print('\n' + '=' * 60)
    print('  PROGRESSIVE TRAINING: easy → medium → hard')
    print('=' * 60)

    all_metrics = {}

    for difficulty in ['easy', 'medium', 'hard']:
        steps = {'easy': 20000, 'medium': 40000, 'hard': 60000}[difficulty]
        metrics = train(difficulty=difficulty, mode='simulation', timesteps=steps)
        all_metrics[difficulty] = metrics

    # Final adversarial training
    print('\n' + '=' * 60)
    print('  ADVERSARIAL TRAINING (vs Defensive AI)')
    print('=' * 60)
    adv_metrics = train(difficulty='hard', mode='adversarial', timesteps=30000)
    all_metrics['adversarial'] = adv_metrics

    return all_metrics


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Train RL Pentest Agent')
    parser.add_argument('--difficulty', type=str, default='medium',
                        choices=['easy', 'medium', 'hard'])
    parser.add_argument('--mode', type=str, default='simulation',
                        choices=['simulation', 'live', 'adversarial'])
    parser.add_argument('--timesteps', type=int, default=50000)
    parser.add_argument('--seed', type=int, default=42)
    parser.add_argument('--progressive', action='store_true',
                        help='Train progressively easy→medium→hard→adversarial')

    args = parser.parse_args()

    if args.progressive:
        train_progressive()
    else:
        train(
            difficulty=args.difficulty,
            mode=args.mode,
            timesteps=args.timesteps,
            seed=args.seed,
        )
