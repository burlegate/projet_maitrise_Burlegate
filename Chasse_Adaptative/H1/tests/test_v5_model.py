from __future__ import annotations

import unittest
from pathlib import Path

import numpy as np
from sb3_contrib import MaskablePPO

from evidence_interpreter_h1 import analyze_result, final_verdict, initial_state, update_state
from gym_hunting_env_v1 import ThreatHuntingEnv
from hunting_policy_contract_v5 import ACTION_IDS
from run_hunt_H1_splunk import choose_action_with_ppo, validate_model_contract


PROJECT_ROOT = Path(__file__).resolve().parents[1]
MODEL_PATH = PROJECT_ROOT / "outputs" / "ppo_hunting_h1_v5_2.zip"
HASH_VALUE = "D" * 64


SYNTHETIC_RESULTS = {
    "A1": [{"src_ip": "192.168.247.131", "query": "ws001.coinhive.com"}],
    "A2": [],
    "A3": [{
        "sa": "192.168.247.131",
        "da": "37.187.167.21",
        "dh": "ws001.coinhive.com",
        "pn": "chrome.exe",
        "ph": HASH_VALUE,
        "fst": "Thu Aug 23 23:38:05 2018",
        "un": "BudStoll",
    }],
    "A4": [{
        "host": "BSTOLL-L",
        "Image": r"C:\Program Files\Google\Chrome\Application\chrome.exe",
        "User": r"AzureAD\BudStoll",
        "Hashes": f"SHA256={HASH_VALUE}",
        "UtcTime": "2018-08-23 23:37:58.600",
    }],
    "A5": [],
    "A6": [],
}


class ModelIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.model = MaskablePPO.load(str(MODEL_PATH))

    def test_model_contract(self):
        validate_model_contract(self.model)

    def test_model_reaches_ppo_stop_on_correlated_evidence(self):
        state = initial_state()
        decisions = []
        for _ in range(7):
            action_id, _, source = choose_action_with_ppo(self.model, state, max_steps=7)
            decisions.append((action_id, source))
            if action_id == "A7":
                break
            analysis = analyze_result(action_id, SYNTHETIC_RESULTS[action_id], query_limit=200, state=state)
            state = update_state(state, analysis)

        self.assertEqual(decisions[-1], ("A7", "ppo"))
        self.assertEqual([action for action, _ in decisions], ["A3", "A4", "A1", "A7"])
        self.assertTrue(state["a3_a4_correlation"]["correlated"])
        self.assertEqual(final_verdict(state)["verdict"], "hypothese_soutenue")

    def _scenario_actions(self, scenario):
        env = ThreatHuntingEnv(
            catalog_path=str(PROJECT_ROOT / "data" / "action_catalog_H1_ppo_v5.json"),
            scenario=scenario,
            max_steps=7,
        )
        observation, _ = env.reset(seed=2026)
        actions = []
        terminated = truncated = False
        while not (terminated or truncated):
            action_index, _ = self.model.predict(
                observation,
                action_masks=env.action_masks(),
                deterministic=True,
            )
            action_id = ACTION_IDS[int(np.asarray(action_index).item())]
            actions.append(action_id)
            observation, _, terminated, truncated, _ = env.step(
                ACTION_IDS.index(action_id)
            )
        return actions

    def test_model_uses_a2_for_relevant_http_scenario(self):
        self.assertEqual(
            self._scenario_actions("http_direct"),
            ["A3", "A4", "A1", "A2", "A7"],
        )

    def test_model_uses_a5_for_relevant_windows_scenario(self):
        self.assertEqual(
            self._scenario_actions("windows_direct"),
            ["A3", "A4", "A1", "A5", "A7"],
        )


if __name__ == "__main__":
    unittest.main()
