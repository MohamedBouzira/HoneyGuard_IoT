# ================================================================
# DQN Agent — Wrapper around stable-baselines3 DQN
# Handles training, evaluation, and model persistence
# ================================================================
import os
import sys
import numpy as np

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))
from config import DQN_CONFIG


class DQNAgent:
    """
    DQN Agent for IoT honeypot penetration testing.
    Wraps stable-baselines3 DQN with project-specific configuration.
    """

    def __init__(self, env, model_path=None, verbose=1):
        from stable_baselines3 import DQN
        from stable_baselines3.common.callbacks import EvalCallback

        self.env = env
        self.verbose = verbose
        self.model_path = model_path

        # Check if tensorboard is available
        try:
            import tensorboard  # noqa: F401
            tb_log = os.path.join(
                os.path.dirname(__file__), '..', '..', 'results', 'tb_logs'
            )
        except ImportError:
            tb_log = None

        if model_path and (os.path.exists(model_path) or os.path.exists(model_path + '.zip')):
            print(f'[DQNAgent] Loading existing model from {model_path}')
            self.model = DQN.load(model_path, env=env)
        else:
            print(f'[DQNAgent] Creating new DQN model')
            self.model = DQN(
                'MlpPolicy',
                env,
                learning_rate=DQN_CONFIG['learning_rate'],
                buffer_size=DQN_CONFIG['buffer_size'],
                batch_size=DQN_CONFIG['batch_size'],
                gamma=DQN_CONFIG['gamma'],
                exploration_fraction=DQN_CONFIG['exploration_fraction'],
                exploration_final_eps=DQN_CONFIG['exploration_final_eps'],
                target_update_interval=DQN_CONFIG['target_update_interval'],
                train_freq=DQN_CONFIG['train_freq'],
                gradient_steps=DQN_CONFIG['gradient_steps'],
                learning_starts=DQN_CONFIG['learning_starts'],
                policy_kwargs=DQN_CONFIG['policy_kwargs'],
                verbose=verbose,
                tensorboard_log=tb_log,
            )

    def train(self, total_timesteps=50000, eval_freq=5000, n_eval_episodes=10):
        """Train the DQN agent."""
        from stable_baselines3.common.callbacks import EvalCallback

        eval_callback = EvalCallback(
            self.env,
            best_model_save_path=os.path.join(
                os.path.dirname(__file__), '..', '..', 'models'
            ),
            log_path=os.path.join(
                os.path.dirname(__file__), '..', '..', 'results', 'eval_logs'
            ),
            eval_freq=eval_freq,
            n_eval_episodes=n_eval_episodes,
            deterministic=True,
            verbose=self.verbose,
        )

        print(f'[DQNAgent] Training for {total_timesteps} timesteps...')
        self.model.learn(
            total_timesteps=total_timesteps,
            callback=eval_callback,
            progress_bar=True,
        )
        print('[DQNAgent] Training complete.')

    def predict(self, obs, deterministic=True):
        """Predict action for given observation."""
        action, _ = self.model.predict(obs, deterministic=deterministic)
        return int(action)

    def evaluate(self, n_episodes=20):
        """Evaluate agent performance over multiple episodes."""
        results = []
        for ep in range(n_episodes):
            obs, info = self.env.reset()
            total_reward = 0
            steps = 0
            done = False

            while not done:
                action = self.predict(obs)
                obs, reward, terminated, truncated, info = self.env.step(action)
                total_reward += reward
                steps += 1
                done = terminated or truncated

            summary = self.env.get_episode_summary()
            results.append(summary)

            if self.verbose:
                status = 'DETECTED' if summary['detected'] else 'COMPLETED'
                print(f'  Episode {ep + 1}/{n_episodes}: '
                      f'reward={summary["total_reward"]:.2f}, '
                      f'steps={summary["steps_taken"]}, '
                      f'success_rate={summary["successful_actions"]}/{summary["actions_taken"]}, '
                      f'stealth={summary["final_stealth"]:.2f} [{status}]')

        # Aggregate metrics
        avg_reward = np.mean([r['total_reward'] for r in results])
        avg_steps = np.mean([r['steps_taken'] for r in results])
        detection_rate = np.mean([r['detected'] for r in results])
        avg_success = np.mean([r['successful_actions'] / max(r['actions_taken'], 1)
                               for r in results])

        metrics = {
            'avg_reward': float(avg_reward),
            'avg_steps': float(avg_steps),
            'detection_rate': float(detection_rate),
            'avg_action_success_rate': float(avg_success),
            'episodes': results,
        }

        print(f'\n[DQNAgent] Evaluation Summary ({n_episodes} episodes):')
        print(f'  Avg Reward: {avg_reward:.2f}')
        print(f'  Avg Steps: {avg_steps:.1f}')
        print(f'  Detection Rate: {detection_rate:.1%}')
        print(f'  Avg Action Success: {avg_success:.1%}')

        return metrics

    def save(self, path=None):
        """Save model to disk."""
        save_path = path or os.path.join(
            os.path.dirname(__file__), '..', '..', 'models', 'dqn_pentest'
        )
        self.model.save(save_path)
        print(f'[DQNAgent] Model saved to {save_path}')

    def load(self, path):
        """Load model from disk."""
        from stable_baselines3 import DQN
        self.model = DQN.load(path, env=self.env)
        print(f'[DQNAgent] Model loaded from {path}')
