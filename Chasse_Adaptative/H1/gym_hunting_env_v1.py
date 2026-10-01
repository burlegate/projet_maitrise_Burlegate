"""Environnement Gymnasium V5.2 pour l'agent PPO adaptatif de chasse H1.

Les scénarios incluent des cas où HTTP (A2) et Windows Security (A5) sont
décisifs. Le reward valorise le gain d'information réel, facture chaque
recherche et récompense un A7 correct et rapide.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import gymnasium as gym
import numpy as np
from gymnasium import spaces

from hunting_policy_contract_v5 import (
    ACTION_IDS,
    OBSERVATION_FEATURES,
    classify_stop,
    complete_evidence_chain,
    normalized_evidence_index,
    observation_values,
    sufficient_investigation,
    supporting_source_count,
    valid_action_mask,
)


DEFAULT_CATALOG_PATH = "data/action_catalog_H1_ppo_v5.json"
SCENARIO_NAMES = (
    "bots_strong",
    "strong_with_edr",
    "uncorrelated_endpoint",
    "partial_network",
    "http_direct",
    "http_direct_with_endpoint",
    "windows_direct",
    "windows_direct_with_dns",
    "dns_only",
    "endpoint_only",
    "edr_only",
    "no_evidence",
)

ACTION_COST = 0.15
INFORMATION_GAIN_SCALE = 1.5
EFFICIENCY_BONUS_PER_UNUSED_STEP = 0.30
CONTINUATION_PROGRESS_BONUS = 0.75
VERDICT_READY_BONUS = 1.25
HTTP_FOLLOWUP_BONUS = 2.0
WINDOWS_FOLLOWUP_BONUS = 2.0


def contextual_followup_bonus(state: Dict[str, Any], action_id: str) -> float:
    """Valorise une source complémentaire seulement lorsqu'elle est pertinente."""
    executed = set(state.get("executed_actions", []))
    flow_checked_negative = "A3" in executed and not bool(state.get("network_flow_positive"))
    if action_id == "A2" and flow_checked_negative and bool(state.get("dns_positive")):
        return HTTP_FOLLOWUP_BONUS
    if action_id == "A5" and flow_checked_negative and bool(state.get("sysmon_positive")):
        return WINDOWS_FOLLOWUP_BONUS
    return 0.0


class ThreatHuntingEnv(gym.Env):
    """Simulation de la boucle action → résultat → reward → décision A7."""

    metadata = {"render_modes": ["human"]}

    def __init__(
        self,
        catalog_path: str = DEFAULT_CATALOG_PATH,
        scenario: str = "random",
        max_steps: int = 7,
        seed: Optional[int] = None,
        warm_start: bool = False,
    ) -> None:
        super().__init__()
        if max_steps < 1:
            raise ValueError("max_steps doit être supérieur ou égal à 1.")
        if scenario != "random" and scenario not in SCENARIO_NAMES:
            raise ValueError(f"Scénario inconnu : {scenario}")

        self.catalog_path = Path(catalog_path)
        self.scenario_mode = scenario
        self.max_steps = max_steps
        self.warm_start = warm_start
        self.catalog = self._load_catalog(self.catalog_path)
        self.actions = self._load_actions_for_ppo(self.catalog)
        action_ids = [action.get("id") for action in self.actions]
        if action_ids != list(ACTION_IDS):
            raise ValueError(f"Ordre d'actions incompatible avec le contrat V5 : {action_ids}")

        self.action_space = spaces.Discrete(len(ACTION_IDS))
        self.observation_space = spaces.Box(
            low=0.0,
            high=1.0,
            shape=(len(OBSERVATION_FEATURES),),
            dtype=np.float32,
        )
        self._seed = seed
        self.current_scenario = ""
        self.outcomes: Dict[str, Any] = {}
        self.state: Dict[str, Any] = {}

    @staticmethod
    def _load_catalog(path: Path) -> Dict[str, Any]:
        if not path.exists():
            raise FileNotFoundError(f"Catalogue introuvable : {path}")
        with path.open("r", encoding="utf-8") as handle:
            return json.load(handle)

    @staticmethod
    def _load_actions_for_ppo(catalog: Dict[str, Any]) -> List[Dict[str, Any]]:
        return list(catalog.get("actions_recommandees", []))

    def reset(
        self,
        *,
        seed: Optional[int] = None,
        options: Optional[Dict[str, Any]] = None,
    ) -> Tuple[np.ndarray, Dict[str, Any]]:
        super().reset(seed=self._seed if seed is None else seed)
        requested = (options or {}).get("scenario", self.scenario_mode)
        if requested == "random":
            requested = str(self.np_random.choice(SCENARIO_NAMES))
        if requested not in SCENARIO_NAMES:
            raise ValueError(f"Scénario inconnu : {requested}")

        self.current_scenario = requested
        self.outcomes = self._scenario_outcomes(requested)
        self.state = {
            "dns_positive": False,
            "http_positive": False,
            "http_context_found": False,
            "network_flow_positive": False,
            "sysmon_positive": False,
            "endpoint_positive": False,
            "windows_direct_found": False,
            "windows_context_found": False,
            "edr_indirect": False,
            "a3_a4_correlation": {"correlated": False},
            "evidence_score": 0.0,
            "executed_actions": [],
            "investigation_trace": [],
            "last_observation_text": "Début de la chasse simulée.",
            "verdict": "en_cours",
            "step_count": 0,
        }
        if self.warm_start and float(self.np_random.random()) < 0.50:
            self._apply_training_warm_start()
        return self._get_obs(), self._info()

    def _apply_training_warm_start(self) -> None:
        """Expose PPO à des états intermédiaires sans modifier l'évaluation."""
        prefixes = (
            (),
            ("A3",),
            ("A3", "A1"),
            ("A3", "A1", "A2"),
            ("A3", "A1", "A4"),
            ("A3", "A1", "A4", "A5"),
            ("A3", "A4"),
            ("A3", "A4", "A1"),
            ("A1",),
            ("A1", "A2"),
            ("A4", "A5"),
        )
        prefix = prefixes[int(self.np_random.integers(0, len(prefixes)))]
        for action_id in prefix:
            reward, message = self._simulate_action(action_id)
            self.state["executed_actions"].append(action_id)
            self.state["step_count"] += 1
            self.state["last_observation_text"] = f"État initial curriculum : {message}"

    def _scenario_outcomes(self, scenario: str) -> Dict[str, Any]:
        # Valeurs : direct/strong/target/indirect/context/none.
        matrix = {
            "bots_strong": dict(dns=True, http="none", flow="strong", sysmon="target", correlation=True, windows="none", edr="none"),
            "strong_with_edr": dict(dns=True, http="context", flow="strong", sysmon="target", correlation=True, windows="context", edr="indirect"),
            "uncorrelated_endpoint": dict(dns=True, http="none", flow="strong", sysmon="target", correlation=False, windows="direct", edr="none"),
            "partial_network": dict(dns=True, http="none", flow="strong", sysmon="none", correlation=False, windows="none", edr="none"),
            "http_direct": dict(dns=True, http="direct", flow="none", sysmon="none", correlation=False, windows="context", edr="none"),
            "http_direct_with_endpoint": dict(dns=True, http="direct", flow="none", sysmon="target", correlation=False, windows="none", edr="none"),
            "windows_direct": dict(dns=False, http="none", flow="none", sysmon="target", correlation=False, windows="direct", edr="none"),
            "windows_direct_with_dns": dict(dns=True, http="context", flow="none", sysmon="target", correlation=False, windows="direct", edr="none"),
            "dns_only": dict(dns=True, http="context", flow="none", sysmon="none", correlation=False, windows="context", edr="none"),
            "endpoint_only": dict(dns=False, http="none", flow="none", sysmon="target", correlation=False, windows="context", edr="none"),
            "edr_only": dict(dns=False, http="none", flow="none", sysmon="none", correlation=False, windows="none", edr="indirect"),
            "no_evidence": dict(dns=False, http="none", flow="none", sysmon="none", correlation=False, windows="none", edr="none"),
        }
        return dict(matrix[scenario])

    def step(self, action_index: int):
        if not self.action_space.contains(action_index):
            raise ValueError(f"Indice d'action invalide : {action_index}")
        action = self.actions[int(action_index)]
        action_id = str(action["id"])
        terminated = False
        truncated = False

        if action_id in self.state["executed_actions"] and action_id != "A7":
            reward = -3.0
            message = f"Action répétée inutile : {action_id}."
        elif action_id == "A7":
            reward, message = self._handle_stop()
            terminated = True
        else:
            was_sufficient = sufficient_investigation(self.state)
            before_index = normalized_evidence_index(self.state)
            followup_bonus = contextual_followup_bonus(self.state, action_id)
            evidence_reward, message = self._simulate_action(action_id)
            information_gain = max(0.0, normalized_evidence_index(self.state) - before_index)
            reward = evidence_reward - ACTION_COST + INFORMATION_GAIN_SCALE * information_gain
            readiness_bonus = 0.0
            if not was_sufficient:
                readiness_bonus = (
                    VERDICT_READY_BONUS
                    if sufficient_investigation({**self.state, "executed_actions": [*self.state["executed_actions"], action_id]})
                    else CONTINUATION_PROGRESS_BONUS
                )
                reward += readiness_bonus
            reward += followup_bonus
            message += (
                f" Reward PPO : preuve {evidence_reward:+.2f}, coût {-ACTION_COST:+.2f}, "
                f"gain d'information {INFORMATION_GAIN_SCALE * information_gain:+.2f}, "
                f"progression {readiness_bonus:+.2f}, suivi contextuel {followup_bonus:+.2f}."
            )

        self.state["step_count"] += 1
        self.state["executed_actions"].append(action_id)
        self.state["last_observation_text"] = message
        self._append_trace(action_id, reward, message)

        if self.state["step_count"] >= self.max_steps and not terminated:
            truncated = True
            self.state["verdict"] = "max_steps_atteint"
            # Sans coût terminal, une politique peut préférer répéter une
            # action jusqu'à la troncature plutôt que prendre une décision A7.
            reward -= 10.0
            message += " Pénalité : limite atteinte sans décision A7."
            self.state["last_observation_text"] = message

        return self._get_obs(), float(reward), terminated, truncated, self._info()

    def _simulate_action(self, action_id: str) -> Tuple[float, str]:
        before_correlation = complete_evidence_chain(self.state)

        if action_id == "A1":
            if self.outcomes["dns"]:
                self.state["dns_positive"] = True
                reward, message = 1.3, "A1 positif : indicateur DNS Coinhive exact."
            else:
                reward, message = -0.2, "A1 négatif : aucun indicateur DNS exact."

        elif action_id == "A2":
            outcome = self.outcomes["http"]
            if outcome == "direct":
                self.state["http_positive"] = True
                reward, message = 1.0, "A2 positif : preuve HTTP directe."
            elif outcome == "context":
                self.state["http_context_found"] = True
                reward, message = 0.1, "A2 contexte : activité web sans Coinhive direct."
            else:
                reward, message = 0.0, "A2 non concluant."

        elif action_id == "A3":
            outcome = self.outcomes["flow"]
            if outcome == "strong":
                self.state["network_flow_positive"] = True
                reward, message = 1.7, "A3 fort : source cible, Coinhive et pn=chrome.exe."
            elif outcome == "positive":
                self.state["network_flow_positive"] = True
                reward, message = 1.2, "A3 positif : flux Coinhive, processus incomplet."
            else:
                reward, message = -0.2, "A3 négatif : aucun flux cible → Coinhive."

        elif action_id == "A4":
            if self.outcomes["sysmon"] == "target":
                self.state["sysmon_positive"] = True
                self.state["endpoint_positive"] = True
                reward, message = 1.0, "A4 corroborant : Image=chrome.exe sur BSTOLL-L."
            else:
                reward, message = -0.2, "A4 négatif : aucun Image=chrome.exe sur BSTOLL-L."

        elif action_id == "A5":
            if self.outcomes["windows"] == "direct":
                self.state["windows_direct_found"] = True
                self.state["windows_context_found"] = True
                reward, message = 1.2, "A5 fort : contexte Windows et Coinhive dans le même événement."
            elif self.outcomes["windows"] == "context":
                self.state["windows_context_found"] = True
                reward, message = 0.4, "A5 contexte : identité cible sans preuve Coinhive directe."
            else:
                reward, message = 0.0, "A5 non concluant."

        elif action_id == "A6":
            if self.outcomes["edr"] == "indirect":
                self.state["edr_indirect"] = True
                reward, message = 0.5, "A6 indirect : blocage, Coinhive et cible dans le même événement."
            else:
                reward, message = 0.0, "A6 non concluant; absence de preuve non réfutante."
        else:
            reward, message = 0.0, f"Action inconnue : {action_id}."

        # La corrélation devient observable seulement après exécution de A3 et A4.
        executed_with_current = set(self.state["executed_actions"]) | {action_id}
        correlation = bool(
            self.outcomes["correlation"]
            and {"A3", "A4"}.issubset(executed_with_current)
            and self.state["network_flow_positive"]
            and self.state["sysmon_positive"]
        )
        self.state["a3_a4_correlation"] = {"correlated": correlation}

        # Lorsque A4 est la seconde action de la paire, son reward réel fort est 1.9.
        if action_id == "A4" and correlation and not before_correlation:
            reward = 1.9
            message = "A4 fort : même SHA-256 et proximité temporelle avec A3."

        self.state["evidence_score"] = round(float(self.state["evidence_score"]) + reward, 6)
        return reward, message

    def _handle_stop(self) -> Tuple[float, str]:
        verdict = classify_stop(self.state)
        self.state["verdict"] = verdict["verdict"]
        reward_by_verdict = {
            "hypothese_soutenue": 8.0,
            "hypothese_partiellement_soutenue": 5.0,
            "non_concluante": 3.0,
            "arret_premature": -30.0,
        }
        reward = reward_by_verdict[verdict["verdict"]]
        if verdict["verdict"] != "arret_premature":
            used = len(self.state.get("executed_actions", []))
            efficiency_bonus = max(0, self.max_steps - used) * EFFICIENCY_BONUS_PER_UNUSED_STEP
            reward += efficiency_bonus
        else:
            efficiency_bonus = 0.0
        return reward, (
            f"A7 : {verdict['verdict']} — {verdict['reason']} "
            f"Bonus d'efficacité : {efficiency_bonus:+.2f}."
        )

    def _get_obs(self) -> np.ndarray:
        return np.asarray(observation_values(self.state, self.max_steps), dtype=np.float32)

    def action_masks(self) -> np.ndarray:
        """Interface attendue par MaskablePPO (sb3-contrib)."""
        return np.asarray(valid_action_mask(self.state), dtype=bool)

    def _append_trace(self, action_id: str, reward: float, message: str) -> None:
        self.state["investigation_trace"].append({
            "step": int(self.state["step_count"]),
            "scenario": self.current_scenario,
            "action_id": action_id,
            "message": message,
            "reward": float(reward),
            "evidence_score": float(self.state["evidence_score"]),
            "ppo_evidence_index": normalized_evidence_index(self.state),
            "supporting_source_count": supporting_source_count(self.state),
            "correlation_confirmed": complete_evidence_chain(self.state),
        })

    def _info(self) -> Dict[str, Any]:
        return {
            "scenario": self.current_scenario,
            "verdict": self.state.get("verdict", "en_cours"),
            "cumulative_action_reward": round(float(self.state.get("evidence_score", 0.0)), 3),
            "ppo_evidence_index": normalized_evidence_index(self.state),
            "supporting_source_count": supporting_source_count(self.state),
            "executed_actions": list(self.state.get("executed_actions", [])),
            "last_observation_text": self.state.get("last_observation_text", ""),
            "investigation_trace": list(self.state.get("investigation_trace", [])),
        }

    def render(self) -> None:
        info = self._info()
        print(
            f"scenario={info['scenario']} verdict={info['verdict']} "
            f"score={info['cumulative_action_reward']} actions={info['executed_actions']}"
        )


def action_index_by_id(env: ThreatHuntingEnv, action_id: str) -> int:
    try:
        return list(ACTION_IDS).index(action_id)
    except ValueError as exc:
        raise KeyError(f"Action introuvable : {action_id}") from exc


if __name__ == "__main__":
    env = ThreatHuntingEnv(scenario="bots_strong")
    obs, info = env.reset(seed=42)
    print("Observation V5.2 :", dict(zip(OBSERVATION_FEATURES, obs.tolist())))
    print("Info :", info)
