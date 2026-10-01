from __future__ import annotations

import unittest

from evidence_interpreter_h1 import (
    analyze_result,
    correlate_a3_a4,
    final_verdict,
    initial_state,
    update_state,
)
from hunting_policy_contract_v5 import (
    OBSERVATION_FEATURES,
    fallback_unexecuted_action,
    observation_values,
    valid_action_mask,
)
from spl_templates_controlled import build_spl, normalize_limit


HASH_A = "A" * 64
HASH_B = "B" * 64
HASH_C = "C" * 64


def flow_row(*, process="chrome.exe", parent="explorer.exe", sha256=HASH_A, time="Thu Aug 23 23:38:05 2018"):
    return {
        "sa": "192.168.247.131",
        "da": "37.187.167.21",
        "dh": "ws001.coinhive.com",
        "pn": process,
        "ppn": parent,
        "ph": sha256,
        "fst": time,
        "un": "BudStoll",
    }


def sysmon_row(*, image=r"C:\Program Files\Google\Chrome\Application\chrome.exe", parent=r"C:\Windows\explorer.exe", sha256=HASH_A, time="2018-08-23 23:37:58.600"):
    return {
        "host": "BSTOLL-L",
        "Image": image,
        "ParentImage": parent,
        "User": r"AzureAD\BudStoll",
        "Hashes": f"SHA256={sha256}",
        "UtcTime": time,
    }


class ExactMatchingTests(unittest.TestCase):
    def test_notcoinhive_is_not_an_indicator(self):
        analysis = analyze_result("A1", [{"query": "notcoinhive.com"}], query_limit=200)
        self.assertEqual(analysis["evidence_level"], "non_concluant")
        self.assertEqual(analysis["result_metrics"]["coinhive_indicator_count"], 0)

    def test_a3_parent_process_does_not_qualify_pn(self):
        analysis = analyze_result("A3", [flow_row(process="evil.exe", parent="chrome.exe")])
        self.assertNotEqual(analysis["evidence_level"], "forte")
        self.assertFalse(analysis["result_metrics"]["target_process_found"])

    def test_a4_parent_image_does_not_qualify_image(self):
        analysis = analyze_result(
            "A4",
            [sysmon_row(image=r"C:\Temp\evil.exe", parent=r"C:\Chrome\chrome.exe")],
        )
        self.assertEqual(analysis["evidence_level"], "non_concluant")
        self.assertFalse(analysis["result_metrics"]["target_process_found"])

    def test_a4_spl_qualifies_only_image(self):
        spl = build_spl("A4")
        search_lines = [line for line in spl.splitlines() if "| search (" in line]
        process_line = next(line for line in search_lines if "Image=" in line)
        self.assertEqual(
            process_line,
            r'| search (Image="chrome.exe" OR Image="*\\chrome.exe")',
        )
        self.assertNotIn("ParentImage=", process_line)
        self.assertNotIn("CommandLine=", process_line)


class CorrelationTests(unittest.TestCase):
    def test_hash_and_time_must_belong_to_same_pair(self):
        network = [
            {
                "row_index": 0,
                "sha256": HASH_A,
                "start_time_utc": "2018-08-23T11:00:00.000Z",
                "indicator_found": True,
                "source_is_target": True,
                "process_is_target": True,
            },
            {
                "row_index": 1,
                "sha256": HASH_B,
                "start_time_utc": "2018-08-23T10:00:10.000Z",
                "indicator_found": True,
                "source_is_target": True,
                "process_is_target": True,
            },
        ]
        endpoint = [
            {
                "row_index": 0,
                "sha256": HASH_A,
                "start_time_utc": "2018-08-23T10:00:00.000Z",
                "host_is_target": True,
                "process_is_target": True,
            },
            {
                "row_index": 1,
                "sha256": HASH_C,
                "start_time_utc": "2018-08-23T10:00:09.000Z",
                "host_is_target": True,
                "process_is_target": True,
            },
        ]
        correlation = correlate_a3_a4(network, endpoint)
        self.assertFalse(correlation["correlated"])
        self.assertIsNone(correlation["matched_pair"])

    def test_realistic_pair_is_correlated_at_6_4_seconds(self):
        state = initial_state()
        state = update_state(state, analyze_result("A1", [{"query": "ws001.coinhive.com"}], state=state))
        state = update_state(state, analyze_result("A3", [flow_row()], state=state))
        state = update_state(state, analyze_result("A4", [sysmon_row()], state=state))
        correlation = state["a3_a4_correlation"]
        self.assertTrue(correlation["correlated"])
        self.assertAlmostEqual(correlation["closest_time_delta_seconds"], 6.4, places=3)
        self.assertEqual(final_verdict(state)["verdict"], "hypothese_soutenue")


class ContractTests(unittest.TestCase):
    def test_verdict_does_not_change_when_a7_is_appended(self):
        state = initial_state()
        state["executed_actions"] = ["A1", "A3", "A4", "A6"]
        before = final_verdict(state)
        state["executed_actions"].append("A7")
        after = final_verdict(state)
        self.assertEqual(before, after)
        self.assertEqual(after["verdict"], "non_concluante")

    def test_observation_contract_has_correlation_dimension(self):
        state = initial_state()
        values = observation_values(state, max_steps=7)
        self.assertEqual(len(values), 21)
        self.assertEqual(len(values), len(OBSERVATION_FEATURES))
        self.assertEqual(OBSERVATION_FEATURES[12], "a3_a4_correlation")
        self.assertEqual(OBSERVATION_FEATURES[18], "sufficient_investigation")

    def test_http_and_windows_direct_are_observable(self):
        state = initial_state()
        state = update_state(
            state,
            analyze_result(
                "A2",
                [{"src_ip": "192.168.247.131", "url": "https://coinhive.com/lib.js"}],
                state=state,
            ),
        )
        state = update_state(
            state,
            analyze_result(
                "A5",
                [{"host": "BSTOLL-L", "user": "BudStoll", "message": "connection coinhive.com"}],
                state=state,
            ),
        )
        values = dict(zip(OBSERVATION_FEATURES, observation_values(state, max_steps=7)))
        self.assertEqual(values["http_positive"], 1.0)
        self.assertEqual(values["windows_direct"], 1.0)

    def test_limit_is_clamped_consistently(self):
        self.assertEqual(normalize_limit(99999), 5000)
        self.assertEqual(normalize_limit(0), 1)

    def test_action_mask_blocks_repetition_and_premature_a7(self):
        state = initial_state()
        state["executed_actions"] = ["A1", "A3"]
        mask = valid_action_mask(state)
        self.assertEqual(mask, [False, False, False, True, False, True, False])

        state["executed_actions"] = ["A1", "A2", "A3", "A4"]
        mask = valid_action_mask(state)
        self.assertTrue(mask[-1])

    def test_action_mask_opens_a2_and_a5_from_relevant_signals(self):
        state = initial_state()
        state["dns_positive"] = True
        mask = valid_action_mask(state)
        self.assertTrue(mask[1])
        self.assertFalse(mask[4])
        self.assertFalse(mask[5])

        state["sysmon_positive"] = True
        mask = valid_action_mask(state)
        self.assertTrue(mask[4])
        self.assertFalse(mask[5])

        state["executed_actions"] = ["A2", "A5"]
        self.assertTrue(valid_action_mask(state)[5])

    def test_fallback_respects_the_same_action_mask(self):
        state = initial_state()
        state["dns_positive"] = True
        state["executed_actions"] = ["A1"]
        self.assertEqual(fallback_unexecuted_action(state), "A2")


if __name__ == "__main__":
    unittest.main()
