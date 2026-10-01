"""Contrat partagé entre l'entraînement PPO et l'orchestrateur réel H1.

La V5.2 conserve les sept actions, mais supprime l'obligation fixe d'exécuter
A1/A3/A4/A6 avant A7. Une investigation devient suffisante soit lorsqu'une
chaîne forte est complète, soit lorsque plusieurs sources directes se
corroborent, soit après quatre recherches sans preuve suffisante.
"""

from __future__ import annotations

from typing import Any, Dict, Iterable, List


CONTRACT_VERSION = "H1_PPO_v5_2"

ACTION_IDS = ("A1", "A2", "A3", "A4", "A5", "A6", "A7")

ACTION_LABELS = {
    "A1": "DNS",
    "A2": "HTTP",
    "A3": "Cisco NVM Flow",
    "A4": "Sysmon",
    "A5": "Windows Security",
    "A6": "Symantec",
    "A7": "Stop / Verdict",
}

ACTION_TO_TEMPLATE = {
    "A1": "dns_lookup",
    "A2": "http_context_lookup",
    "A3": "cisco_nvm_flow_lookup",
    "A4": "sysmon_process_lookup",
    "A5": "windows_security_lookup",
    "A6": "symantec_alert_lookup",
    "A7": "stop_decision",
}

# Toute modification de l'ordre ou du nombre de variables exige un nouvel
# entraînement et un nouveau fichier de modèle.
OBSERVATION_FEATURES = (
    "dns_checked",
    "dns_positive",
    "http_checked",
    "http_positive",
    "flow_checked",
    "flow_positive",
    "sysmon_checked",
    "sysmon_positive",
    "windows_checked",
    "windows_direct",
    "edr_checked",
    "edr_positive",
    "a3_a4_correlation",
    "normalized_evidence_index",
    "supporting_source_count_norm",
    "step_count_norm",
    "has_dns_flow",
    "complete_chain",
    "sufficient_investigation",
    "http_context",
    "windows_context",
)

MIN_ACTIONS_FOR_PARTIAL = 3
MIN_ACTIONS_FOR_NONCONCLUSIVE = 4

PPO_EVIDENCE_COMPONENTS = (
    ("DNS", "dns_positive", 0.20),
    ("HTTP direct", "http_positive", 0.15),
    ("Cisco NVM", "network_flow_positive", 0.25),
    ("Sysmon", "sysmon_positive", 0.15),
    ("Corrélation A3-A4", "a3_a4_correlation", 0.20),
    ("Windows direct", "windows_direct_found", 0.05),
    ("HTTP contexte", "http_context_found", 0.01),
    ("Windows contexte", "windows_context_found", 0.01),
    ("Symantec", "edr_indirect", 0.025),
)


def investigation_actions(executed_actions: Iterable[str]) -> List[str]:
    """Retourne les actions de recherche, sans compter A7 comme une preuve."""
    return [action for action in executed_actions if action in ACTION_IDS[:-1]]


def correlation_confirmed(state: Dict[str, Any]) -> bool:
    value = state.get("a3_a4_correlation", False)
    if isinstance(value, dict):
        return bool(value.get("correlated", False))
    return bool(value)


def complete_evidence_chain(state: Dict[str, Any]) -> bool:
    """Chaîne principale forte H1, inchangée par rapport à la V5.1."""
    return bool(
        state.get("dns_positive")
        and state.get("network_flow_positive")
        and state.get("sysmon_positive", state.get("endpoint_positive", False))
        and correlation_confirmed(state)
    )


def supporting_source_count(state: Dict[str, Any]) -> int:
    """Compte les familles de preuves directes, dont HTTP et Windows."""
    values = (
        state.get("dns_positive", False),
        state.get("http_positive", False),
        state.get("network_flow_positive", False),
        state.get("sysmon_positive", state.get("endpoint_positive", False)),
        state.get("windows_direct_found", False),
    )
    return sum(bool(value) for value in values)


def sufficient_investigation(state: Dict[str, Any]) -> bool:
    """Indique si A7 peut produire un verdict sans arrêt prématuré."""
    if complete_evidence_chain(state):
        return True
    executed_count = len(investigation_actions(state.get("executed_actions", [])))
    score = float(state.get("evidence_score", 0.0))
    if (
        executed_count >= MIN_ACTIONS_FOR_PARTIAL
        and supporting_source_count(state) >= 2
        and score >= 1.5
    ):
        return True
    return executed_count >= MIN_ACTIONS_FOR_NONCONCLUSIVE


def normalized_evidence_index(state: Dict[str, Any]) -> float:
    total = 0.0
    for _, state_key, weight in PPO_EVIDENCE_COMPONENTS:
        active = correlation_confirmed(state) if state_key == "a3_a4_correlation" else bool(state.get(state_key))
        if active:
            total += weight
    return min(1.0, round(total, 6))


def observation_values(state: Dict[str, Any], max_steps: int) -> List[float]:
    """Construit les 21 variables normalisées du contrat V5.2."""
    if max_steps < 1:
        raise ValueError("--max-steps doit être supérieur ou égal à 1.")
    executed = set(investigation_actions(state.get("executed_actions", [])))
    correlation = correlation_confirmed(state)
    dns_positive = bool(state.get("dns_positive"))
    flow_positive = bool(state.get("network_flow_positive"))
    sysmon_positive = bool(state.get("sysmon_positive", state.get("endpoint_positive", False)))
    step_count = len(executed)
    values = [
        float("A1" in executed),
        float(dns_positive),
        float("A2" in executed),
        float(bool(state.get("http_positive"))),
        float("A3" in executed),
        float(flow_positive),
        float("A4" in executed),
        float(sysmon_positive),
        float("A5" in executed),
        float(bool(state.get("windows_direct_found"))),
        float("A6" in executed),
        float(bool(state.get("edr_indirect"))),
        float(correlation),
        normalized_evidence_index(state),
        min(1.0, supporting_source_count(state) / 5.0),
        min(1.0, step_count / float(max_steps)),
        float(dns_positive and flow_positive),
        float(complete_evidence_chain(state)),
        float(sufficient_investigation(state)),
        float(bool(state.get("http_context_found"))),
        float(bool(state.get("windows_context_found"))),
    ]
    if len(values) != len(OBSERVATION_FEATURES):
        raise AssertionError("Contrat d'observation V5.2 incohérent.")
    return values


def fallback_unexecuted_action(state: Dict[str, Any]) -> str:
    """Retourne une action admissible si une sortie PPO invalide survient."""
    for action_id, is_valid in zip(ACTION_IDS, valid_action_mask(state)):
        if is_valid:
            return action_id
    return "A7"


def valid_action_mask(state: Dict[str, Any]) -> List[bool]:
    """Applique répétition, prérequis de pertinence et validité d'A7.

    A2 est un suivi du signal DNS et A5 un suivi du signal endpoint. Le masque
    ne sélectionne aucune action : PPO choisit toujours parmi les actions
    admissibles. Dès que l'investigation est suffisante, A7 redevient disponible.
    """
    executed = set(investigation_actions(state.get("executed_actions", [])))
    http_followup_pending = bool(state.get("dns_positive")) and "A2" not in executed
    windows_followup_pending = bool(
        state.get("sysmon_positive", state.get("endpoint_positive", False))
    ) and "A5" not in executed
    direct_followup_pending = http_followup_pending or windows_followup_pending
    mask: List[bool] = []
    for action_id in ACTION_IDS:
        if action_id == "A7":
            valid = sufficient_investigation(state)
        elif action_id in executed:
            valid = False
        elif action_id == "A2":
            valid = bool(state.get("dns_positive"))
        elif action_id == "A5":
            valid = bool(state.get("sysmon_positive", state.get("endpoint_positive", False)))
        elif action_id == "A6":
            valid = not direct_followup_pending
        else:
            valid = True
        mask.append(valid)
    return mask


def classify_stop(state: Dict[str, Any]) -> Dict[str, str]:
    """Verdict déterministe partagé par l'entraînement et la production."""
    if complete_evidence_chain(state):
        return {
            "verdict": "hypothese_soutenue",
            "confidence": "forte",
            "reason": (
                "H1 est soutenue par DNS, flux Cisco NVM et processus Sysmon "
                "corrélé à A3 par le même SHA-256 et une proximité temporelle."
            ),
        }

    action_count = len(investigation_actions(state.get("executed_actions", [])))
    source_count = supporting_source_count(state)
    score = float(state.get("evidence_score", 0.0))
    if action_count >= MIN_ACTIONS_FOR_PARTIAL and source_count >= 2 and score >= 1.5:
        return {
            "verdict": "hypothese_partiellement_soutenue",
            "confidence": "moyenne",
            "reason": (
                "Au moins deux familles de preuves directes soutiennent H1, "
                "mais la chaîne principale DNS + Cisco NVM + Sysmon corrélé "
                "n'est pas complète."
            ),
        }

    if action_count >= MIN_ACTIONS_FOR_NONCONCLUSIVE:
        return {
            "verdict": "non_concluante",
            "confidence": "faible",
            "reason": (
                "Au moins quatre recherches ont été exécutées sans obtenir "
                "une chaîne de preuve suffisante."
            ),
        }

    return {
        "verdict": "arret_premature",
        "confidence": "faible",
        "reason": (
            "Les preuves sont encore insuffisantes : poursuivre jusqu'à une "
            "chaîne forte, deux sources directes corroborantes ou quatre recherches."
        ),
    }
