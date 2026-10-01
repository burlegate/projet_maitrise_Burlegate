"""Entraîne et évalue le modèle PPO adaptatif V5.2 de chasse H1."""

from __future__ import annotations

import argparse
import json
import platform
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List

import gymnasium
import numpy as np
import stable_baselines3
import torch
import sb3_contrib
from sb3_contrib import MaskablePPO
from stable_baselines3.common.env_checker import check_env
from stable_baselines3.common.utils import set_random_seed

from gym_hunting_env_v1 import (
    ACTION_COST,
    CONTINUATION_PROGRESS_BONUS,
    EFFICIENCY_BONUS_PER_UNUSED_STEP,
    INFORMATION_GAIN_SCALE,
    HTTP_FOLLOWUP_BONUS,
    SCENARIO_NAMES,
    ThreatHuntingEnv,
    VERDICT_READY_BONUS,
    WINDOWS_FOLLOWUP_BONUS,
)
from hunting_policy_contract_v5 import (
    ACTION_IDS,
    CONTRACT_VERSION,
    OBSERVATION_FEATURES,
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Entraîner PPO pour H1 avec le contrat V5.2 adaptatif.")
    parser.add_argument("--catalog", default="data/action_catalog_H1_ppo_v5.json")
    parser.add_argument("--output", default="outputs/ppo_hunting_h1_v5_2")
    parser.add_argument("--timesteps", type=int, default=300_000)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--max-steps", type=int, default=7)
    return parser.parse_args()


def evaluate_model(model: MaskablePPO, catalog: str, max_steps: int) -> Dict[str, Any]:
    episodes: List[Dict[str, Any]] = []
    for scenario in SCENARIO_NAMES:
        env = ThreatHuntingEnv(catalog_path=catalog, scenario=scenario, max_steps=max_steps)
        observation, _ = env.reset(seed=2026)
        terminated = False
        truncated = False
        total_reward = 0.0
        actions: List[str] = []
        decisions: List[Dict[str, str]] = []
        info: Dict[str, Any] = {}
        while not (terminated or truncated):
            action_index, _ = model.predict(
                observation,
                action_masks=env.action_masks(),
                deterministic=True,
            )
            proposed_action = ACTION_IDS[int(np.asarray(action_index).item())]
            action_id = proposed_action
            decision_source = "ppo"
            actions.append(action_id)
            decisions.append({
                "proposed_by_ppo": proposed_action,
                "executed_action": action_id,
                "decision_source": decision_source,
            })
            executed_index = list(ACTION_IDS).index(action_id)
            observation, reward, terminated, truncated, info = env.step(executed_index)
            total_reward += float(reward)
        stopped_by_ppo = bool(
            terminated
            and actions
            and actions[-1] == "A7"
            and decisions[-1]["decision_source"] == "ppo"
        )
        episodes.append({
            "scenario": scenario,
            "actions": actions,
            "decisions": decisions,
            "terminated_by_ppo_a7": stopped_by_ppo,
            "truncated": bool(truncated),
            "verdict": info.get("verdict"),
            "total_episode_reward": round(total_reward, 3),
        })

    premature = [episode["scenario"] for episode in episodes if episode["verdict"] == "arret_premature"]
    missing_stop = [episode["scenario"] for episode in episodes if not episode["terminated_by_ppo_a7"]]
    strong_failures = [
        episode["scenario"]
        for episode in episodes
        if episode["scenario"] in {"bots_strong", "strong_with_edr"}
        and episode["verdict"] != "hypothese_soutenue"
    ]
    episode_by_scenario = {episode["scenario"]: episode for episode in episodes}
    http_missing = [name for name in ("http_direct",) if "A2" not in episode_by_scenario[name]["actions"]]
    windows_missing = [name for name in ("windows_direct",) if "A5" not in episode_by_scenario[name]["actions"]]
    unique_paths = sorted({tuple(episode["actions"]) for episode in episodes})
    bots_actions = episode_by_scenario["bots_strong"]["actions"]
    bots_stop_is_efficient = bool(
        bots_actions[-1:] == ["A7"]
        and {"A1", "A3", "A4"}.issubset(bots_actions)
        and "A6" not in bots_actions
        and len(bots_actions) <= 4
    )
    return {
        "episodes": episodes,
        "acceptance": {
            "no_premature_stop": not premature,
            "all_episodes_stopped_by_ppo_a7": not missing_stop,
            "strong_scenarios_supported": not strong_failures,
            "http_scenarios_use_a2": not http_missing,
            "windows_scenarios_use_a5": not windows_missing,
            "at_least_three_distinct_paths": len(unique_paths) >= 3,
            "bots_strong_stops_without_a6": bots_stop_is_efficient,
            "premature_scenarios": premature,
            "missing_stop_scenarios": missing_stop,
            "strong_failure_scenarios": strong_failures,
            "http_scenarios_missing_a2": http_missing,
            "windows_scenarios_missing_a5": windows_missing,
            "distinct_path_count": len(unique_paths),
            "distinct_paths": [list(path) for path in unique_paths],
        },
    }


def main() -> int:
    args = parse_args()
    if args.timesteps < 1:
        raise ValueError("--timesteps doit être supérieur ou égal à 1.")

    set_random_seed(args.seed)
    check_environment = ThreatHuntingEnv(
        catalog_path=args.catalog,
        scenario="random",
        max_steps=args.max_steps,
        seed=args.seed,
    )
    check_env(check_environment, warn=True)

    env = ThreatHuntingEnv(
        catalog_path=args.catalog,
        scenario="random",
        max_steps=args.max_steps,
        seed=args.seed,
        warm_start=False,
    )
    model = MaskablePPO(
        "MlpPolicy",
        env,
        learning_rate=2.5e-4,
        n_steps=128,
        batch_size=64,
        n_epochs=10,
        gamma=0.97,
        gae_lambda=0.95,
        clip_range=0.2,
        ent_coef=0.01,
        vf_coef=0.5,
        max_grad_norm=0.5,
        seed=args.seed,
        device="cpu",
        verbose=0,
    )
    model.learn(total_timesteps=args.timesteps, progress_bar=False)

    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    evaluation = evaluate_model(model, args.catalog, args.max_steps)
    metadata = {
        "created_at_utc": datetime.now(timezone.utc).isoformat(),
        "contract_version": CONTRACT_VERSION,
        "action_ids": list(ACTION_IDS),
        "observation_features": list(OBSERVATION_FEATURES),
        "observation_shape": [len(OBSERVATION_FEATURES)],
        "training": {
            "total_timesteps_requested": args.timesteps,
            "total_timesteps_model": int(model.num_timesteps),
            "seed": args.seed,
            "max_steps": args.max_steps,
            "algorithm": "MaskablePPO",
            "policy": "MlpPolicy",
            "learning_rate": 2.5e-4,
            "n_steps": 128,
            "batch_size": 64,
            "n_epochs": 10,
            "gamma": 0.97,
            "gae_lambda": 0.95,
            "clip_range": 0.2,
            "ent_coef": 0.01,
            "curriculum_warm_start": False,
            "curriculum_probability": 0.0,
            "action_cost": ACTION_COST,
            "information_gain_scale": INFORMATION_GAIN_SCALE,
            "continuation_progress_bonus": CONTINUATION_PROGRESS_BONUS,
            "verdict_ready_bonus": VERDICT_READY_BONUS,
            "http_followup_bonus": HTTP_FOLLOWUP_BONUS,
            "windows_followup_bonus": WINDOWS_FOLLOWUP_BONUS,
            "efficiency_bonus_per_unused_step": EFFICIENCY_BONUS_PER_UNUSED_STEP,
            "essential_action_exploration_bonus": 0.0,
            "premature_stop_penalty": -30.0,
            "truncation_without_a7_penalty": -10.0,
        },
        "software": {
            "python": platform.python_version(),
            "stable_baselines3": stable_baselines3.__version__,
            "sb3_contrib": sb3_contrib.__version__,
            "gymnasium": gymnasium.__version__,
            "torch": torch.__version__,
            "numpy": np.__version__,
        },
        "evaluation": evaluation,
    }
    print(json.dumps(evaluation, ensure_ascii=False, indent=2))
    required_acceptance = (
        "no_premature_stop",
        "all_episodes_stopped_by_ppo_a7",
        "strong_scenarios_supported",
        "http_scenarios_use_a2",
        "windows_scenarios_use_a5",
        "at_least_three_distinct_paths",
        "bots_strong_stops_without_a6",
    )
    if not all(evaluation["acceptance"][key] for key in required_acceptance):
        print("ÉCHEC : critères non satisfaits; le modèle final existant n'a pas été remplacé.")
        return 1

    model.save(str(output_path))
    metadata_path = output_path.parent / f"{output_path.name}_metadata.json"
    with metadata_path.open("w", encoding="utf-8") as handle:
        json.dump(metadata, handle, ensure_ascii=False, indent=2)

    print(f"Modèle sauvegardé : {output_path}.zip")
    print(f"Métadonnées       : {metadata_path}")
    print("SUCCÈS : tous les critères d'acceptation sont satisfaits.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
