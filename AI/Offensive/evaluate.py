#!/usr/bin/env python3
# ================================================================
# Offensive RL Pentest — Evaluation & Visualization
# Generates plots and reports from trained agent
# ================================================================
import os
import sys
import json
import argparse
import numpy as np

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from config import DIFFICULTY_CONFIGS, NUM_ACTIONS
from src.environment.honeypot_env import HoneypotPentestEnv
from src.agents.dqn_agent import DQNAgent


def evaluate_agent(model_path, difficulty='medium', mode='simulation',
                   n_episodes=50, render=False):
    """Evaluate a trained agent and generate visualizations."""
    import matplotlib
    matplotlib.use('Agg')
    import matplotlib.pyplot as plt
    import seaborn as sns
    sns.set_style('whitegrid')

    print('=' * 60)
    print(f'  EVALUATION: {model_path}')
    print(f'  Difficulty: {difficulty} | Mode: {mode} | Episodes: {n_episodes}')
    print('=' * 60)

    # Create environment and load agent
    env = HoneypotPentestEnv(
        difficulty=difficulty, mode=mode,
        render_mode='human' if render else None
    )
    agent = DQNAgent(env, model_path=model_path, verbose=0)

    # Run evaluation episodes
    all_rewards = []
    all_steps = []
    all_detections = []
    all_actions = []
    all_success_rates = []
    action_counts = np.zeros(NUM_ACTIONS)

    for ep in range(n_episodes):
        obs, info = env.reset()
        episode_actions = []
        done = False

        while not done:
            action = agent.predict(obs)
            obs, reward, terminated, truncated, info = env.step(action)
            episode_actions.append(action)
            action_counts[action] += 1
            done = terminated or truncated

            if render:
                env.render()

        summary = env.get_episode_summary()
        all_rewards.append(summary['total_reward'])
        all_steps.append(summary['steps_taken'])
        all_detections.append(summary['detected'])
        all_actions.append(episode_actions)
        sr = summary['successful_actions'] / max(summary['actions_taken'], 1)
        all_success_rates.append(sr)

    # --- Generate Plots ---
    results_dir = os.path.join(os.path.dirname(__file__), 'results')
    os.makedirs(results_dir, exist_ok=True)

    fig, axes = plt.subplots(2, 3, figsize=(18, 10))
    fig.suptitle(f'RL Pentest Agent Evaluation — {difficulty.upper()} / {mode}',
                 fontsize=14, fontweight='bold')

    # 1. Reward distribution
    axes[0, 0].hist(all_rewards, bins=20, color='#3498db', edgecolor='white', alpha=0.8)
    axes[0, 0].axvline(np.mean(all_rewards), color='red', linestyle='--',
                       label=f'Mean: {np.mean(all_rewards):.2f}')
    axes[0, 0].set_title('Episode Reward Distribution')
    axes[0, 0].set_xlabel('Total Reward')
    axes[0, 0].legend()

    # 2. Steps per episode
    axes[0, 1].hist(all_steps, bins=20, color='#2ecc71', edgecolor='white', alpha=0.8)
    axes[0, 1].axvline(np.mean(all_steps), color='red', linestyle='--',
                       label=f'Mean: {np.mean(all_steps):.1f}')
    axes[0, 1].set_title('Steps per Episode')
    axes[0, 1].set_xlabel('Steps')
    axes[0, 1].legend()

    # 3. Detection rate over episodes (rolling window)
    window = max(n_episodes // 10, 1)
    rolling_detection = np.convolve(all_detections,
                                     np.ones(window)/window, mode='valid')
    axes[0, 2].plot(rolling_detection, color='#e74c3c', linewidth=2)
    axes[0, 2].fill_between(range(len(rolling_detection)), rolling_detection,
                            alpha=0.2, color='#e74c3c')
    axes[0, 2].set_title(f'Detection Rate (rolling {window}-ep window)')
    axes[0, 2].set_ylabel('Detection Rate')
    axes[0, 2].set_xlabel('Episode')
    axes[0, 2].set_ylim(0, 1)

    # 4. Action frequency
    action_names = env.action_names
    nonzero = action_counts > 0
    if nonzero.any():
        sorted_idx = np.argsort(action_counts)[::-1]
        top_n = min(12, int(nonzero.sum()))
        top_idx = sorted_idx[:top_n]
        top_names = [action_names[i][:20] for i in top_idx]
        top_counts = action_counts[top_idx]
        axes[1, 0].barh(range(top_n), top_counts, color='#9b59b6')
        axes[1, 0].set_yticks(range(top_n))
        axes[1, 0].set_yticklabels(top_names, fontsize=8)
        axes[1, 0].set_title('Action Frequency (Top Actions)')
        axes[1, 0].set_xlabel('Count')
        axes[1, 0].invert_yaxis()

    # 5. Success rate over episodes
    axes[1, 1].plot(all_success_rates, color='#f39c12', alpha=0.5, linewidth=1)
    rolling_sr = np.convolve(all_success_rates,
                             np.ones(window)/window, mode='valid')
    axes[1, 1].plot(range(len(rolling_sr)), rolling_sr,
                    color='#e67e22', linewidth=2, label=f'Rolling mean')
    axes[1, 1].set_title('Action Success Rate per Episode')
    axes[1, 1].set_ylabel('Success Rate')
    axes[1, 1].set_xlabel('Episode')
    axes[1, 1].set_ylim(0, 1)
    axes[1, 1].legend()

    # 6. Reward vs Detection scatter
    colors = ['#e74c3c' if d else '#2ecc71' for d in all_detections]
    axes[1, 2].scatter(all_steps, all_rewards, c=colors, alpha=0.6, s=30)
    axes[1, 2].set_title('Reward vs Steps (🔴=Detected, 🟢=Undetected)')
    axes[1, 2].set_xlabel('Steps')
    axes[1, 2].set_ylabel('Total Reward')

    plt.tight_layout()
    plot_path = os.path.join(results_dir, f'eval_{difficulty}_{mode}.png')
    plt.savefig(plot_path, dpi=150, bbox_inches='tight')
    print(f'\nPlot saved: {plot_path}')
    plt.close()

    # --- Save metrics ---
    metrics = {
        'avg_reward': float(np.mean(all_rewards)),
        'std_reward': float(np.std(all_rewards)),
        'avg_steps': float(np.mean(all_steps)),
        'detection_rate': float(np.mean(all_detections)),
        'avg_success_rate': float(np.mean(all_success_rates)),
        'total_episodes': n_episodes,
        'difficulty': difficulty,
        'mode': mode,
    }

    metrics_path = os.path.join(results_dir, f'eval_{difficulty}_{mode}_metrics.json')
    with open(metrics_path, 'w') as f:
        json.dump(metrics, f, indent=2)
    print(f'Metrics saved: {metrics_path}')

    print(f'\n--- Summary ---')
    print(f'  Avg Reward:      {metrics["avg_reward"]:.2f} ± {metrics["std_reward"]:.2f}')
    print(f'  Avg Steps:       {metrics["avg_steps"]:.1f}')
    print(f'  Detection Rate:  {metrics["detection_rate"]:.1%}')
    print(f'  Success Rate:    {metrics["avg_success_rate"]:.1%}')

    return metrics


def compare_difficulties():
    """Compare agent performance across difficulty levels."""
    import matplotlib
    matplotlib.use('Agg')
    import matplotlib.pyplot as plt

    results_dir = os.path.join(os.path.dirname(__file__), 'results')
    models_dir = os.path.join(os.path.dirname(__file__), 'models')

    all_metrics = {}
    for diff in ['easy', 'medium', 'hard']:
        model_path = os.path.join(models_dir, f'dqn_{diff}_simulation')
        if os.path.exists(model_path + '.zip'):
            metrics = evaluate_agent(model_path, difficulty=diff, n_episodes=30)
            all_metrics[diff] = metrics

    if len(all_metrics) < 2:
        print('Not enough trained models to compare. Train first with --progressive.')
        return

    # Comparison bar chart
    diffs = list(all_metrics.keys())
    fig, axes = plt.subplots(1, 4, figsize=(16, 4))

    metric_names = ['avg_reward', 'avg_steps', 'detection_rate', 'avg_success_rate']
    titles = ['Avg Reward', 'Avg Steps', 'Detection Rate', 'Success Rate']
    colors = ['#3498db', '#2ecc71', '#e74c3c', '#f39c12']

    for i, (metric, title, color) in enumerate(zip(metric_names, titles, colors)):
        values = [all_metrics[d][metric] for d in diffs]
        axes[i].bar(diffs, values, color=color, edgecolor='white', alpha=0.8)
        axes[i].set_title(title)
        for j, v in enumerate(values):
            axes[i].text(j, v + 0.02 * max(values), f'{v:.2f}',
                         ha='center', fontsize=9)

    plt.suptitle('Agent Performance Across Difficulty Levels', fontweight='bold')
    plt.tight_layout()
    plt.savefig(os.path.join(results_dir, 'difficulty_comparison.png'),
                dpi=150, bbox_inches='tight')
    print(f'\nComparison plot saved: {results_dir}/difficulty_comparison.png')
    plt.close()


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Evaluate RL Pentest Agent')
    parser.add_argument('--model', type=str, required=True,
                        help='Path to trained model (without .zip)')
    parser.add_argument('--difficulty', type=str, default='medium',
                        choices=['easy', 'medium', 'hard'])
    parser.add_argument('--mode', type=str, default='simulation',
                        choices=['simulation', 'live', 'adversarial'])
    parser.add_argument('--episodes', type=int, default=50)
    parser.add_argument('--render', action='store_true')
    parser.add_argument('--compare', action='store_true',
                        help='Compare across difficulty levels')

    args = parser.parse_args()

    if args.compare:
        compare_difficulties()
    else:
        evaluate_agent(
            model_path=args.model,
            difficulty=args.difficulty,
            mode=args.mode,
            n_episodes=args.episodes,
            render=args.render,
        )
