# run_hunt_H1_splunk.py
#
# Orchestration dynamique H1 :
# MaskablePPO choisit une action -> Python exécute Splunk -> analyse des preuves -> état mis à jour.
#
# Important :
# - Le LLM ne génère pas de SPL libre ici.
# - Les requêtes Splunk viennent uniquement de templates contrôlés.
# - Le reward dépend des résultats réellement retournés par Splunk.
# - Le masque applique non-répétition, pertinence A2/A5 et validité d'A7.
# - Dès qu'A7 est admissible, son choix reste une décision PPO.

from __future__ import annotations

import argparse
import getpass
import json
import os
from copy import deepcopy
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Tuple

import numpy as np
from spl_templates_controlled import TemplateError, build_spl, normalize_limit, normalize_template_id
from sb3_contrib import MaskablePPO

from evidence_interpreter_h1 import (
    analyze_result,
    final_verdict,
    initial_state,
    update_state,
)
from splunk_executor_v1 import run_splunk_export, str_to_bool
from hunting_policy_contract_v5 import (
    ACTION_IDS,
    ACTION_LABELS,
    ACTION_TO_TEMPLATE,
    CONTRACT_VERSION,
    OBSERVATION_FEATURES,
    PPO_EVIDENCE_COMPONENTS,
    correlation_confirmed,
    fallback_unexecuted_action,
    normalized_evidence_index,
    observation_values,
    valid_action_mask,
)


def evidence_score_for_ppo(state: Dict[str, Any]) -> float:
    """
    Le PPO a été entraîné avec un score entre 0 et 1.
    Ici, on transforme notre état réel en score normalisé.
    """

    return normalized_evidence_index(state)


def ppo_evidence_breakdown(state: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Détaille les contributions à l'indice de preuve fourni au PPO."""

    return [
        {
            "source": label,
            "state_key": state_key,
            "active": correlation_confirmed(state) if state_key == "a3_a4_correlation" else bool(state.get(state_key)),
            "contribution": weight if (correlation_confirmed(state) if state_key == "a3_a4_correlation" else state.get(state_key)) else 0.0,
        }
        for label, state_key, weight in PPO_EVIDENCE_COMPONENTS
    ]


def supporting_source_labels(state: Dict[str, Any]) -> List[str]:
    sources = []
    if state.get("dns_positive"):
        sources.append("A1 DNS")
    if state.get("http_positive"):
        sources.append("A2 HTTP")
    if state.get("network_flow_positive"):
        sources.append("A3 Cisco NVM")
    if state.get("sysmon_positive", state.get("endpoint_positive")):
        sources.append("A4 Sysmon")
    return sources


def context_source_labels(state: Dict[str, Any]) -> List[str]:
    sources = []
    if state.get("windows_context_found"):
        sources.append("A5 Windows Security")
    if state.get("edr_indirect"):
        sources.append("A6 Symantec")
    return sources


def scoring_summary(state: Dict[str, Any]) -> Dict[str, Any]:
    """Construit un résumé explicite et sérialisable des deux systèmes de score."""

    reward_breakdown = [
        {
            "action_id": item["action_id"],
            "reward": item["reward"],
        }
        for item in state.get("timeline", [])
    ]

    return {
        "cumulative_action_reward": round(state.get("evidence_score", 0.0), 6),
        "action_reward_breakdown": reward_breakdown,
        "ppo_normalized_evidence_index": round(evidence_score_for_ppo(state), 6),
        "ppo_evidence_breakdown": ppo_evidence_breakdown(state),
        "supporting_source_count": state.get("multi_source_count", 0),
        "supporting_sources": supporting_source_labels(state),
        "context_source_count": state.get("context_source_count", 0),
        "context_sources": context_source_labels(state),
    }


def format_signed(value: float) -> str:
    return f"{value:+g}"


def state_to_observation(state: Dict[str, Any], max_steps: int) -> np.ndarray:
    """
    Convertit l'état réel selon le contrat V5.2 partagé avec l'entraînement.
    La corrélation A3-A4 est une variable explicite; aucun ``stop_hint`` manuel
    n'est injecté dans l'observation.
    """

    return np.asarray(observation_values(state, max_steps), dtype=np.float32)


def fallback_next_action(state: Dict[str, Any]) -> str:
    """
    Garde-fou technique si PPO propose une action déjà exécutée.
    Ce n'est pas une séquence fixe : c'est seulement une protection contre les répétitions.
    """

    return fallback_unexecuted_action(state)


def validate_model_contract(model: MaskablePPO) -> None:
    """Refuse un ancien modèle ou des espaces incompatibles avec V5.2."""
    expected_shape = (len(OBSERVATION_FEATURES),)
    actual_shape = tuple(getattr(model.observation_space, "shape", ()) or ())
    actual_actions = getattr(model.action_space, "n", None)
    if actual_shape != expected_shape or actual_actions != len(ACTION_IDS):
        raise ValueError(
            "Modèle PPO incompatible avec le contrat V5.2 : "
            f"observation attendue={expected_shape}, reçue={actual_shape}; "
            f"actions attendues={len(ACTION_IDS)}, reçues={actual_actions}. "
            "Utilisez outputs/ppo_hunting_h1_v5_2.zip."
        )


def choose_action_with_ppo(model: MaskablePPO, state: Dict[str, Any], max_steps: int) -> Tuple[str, str, str]:
    """
    PPO propose une action.
    Le masque détermine les actions admissibles sans en sélectionner une.
    Toute action proposée par le modèle, y compris A7, est respectée.
    """

    obs = state_to_observation(state, max_steps=max_steps)

    action_index, _ = model.predict(
        obs,
        action_masks=np.asarray(valid_action_mask(state), dtype=bool),
        deterministic=True,
    )
    action_index = int(np.asarray(action_index).item())

    proposed_action = ACTION_IDS[action_index]
    executed = set(state.get("executed_actions", []))

    # Si PPO propose une action déjà faite, on applique un garde-fou.
    if proposed_action in executed and proposed_action != "A7":
        fallback = fallback_next_action(state)
        return fallback, f"PPO proposait {proposed_action}, déjà exécutée. Garde-fou -> {fallback}", "garde_fou"

    return proposed_action, f"PPO a choisi {proposed_action}", "ppo"


def save_json(path: Path, data: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)


def execute_splunk_action(
    action_id: str,
    args: argparse.Namespace,
    password: str,
) -> Tuple[List[Dict[str, Any]], Path, Dict[str, Any]]:
    """
    Exécute l'action dans Splunk avec un template SPL contrôlé.
    """

    template_id = ACTION_TO_TEMPLATE[action_id]

    try:
        normalized_template_id = normalize_template_id(template_id)
        spl = build_spl(
            normalized_template_id,
            {
                "index": args.index,
                "earliest": args.earliest,
                "latest": args.latest,
                "limit": args.limit,
            },
        )
    except TemplateError as exc:
        raise RuntimeError(f"Erreur template pour {action_id}: {exc}") from exc

    print("\n" + "-" * 80)
    print(f"Action {action_id} — {ACTION_LABELS[action_id]}")
    print(f"Template SPL : {normalized_template_id}")
    print("-" * 80)

    results, messages = run_splunk_export(
        spl=spl,
        host=args.host,
        port=args.port,
        username=args.username,
        password=password,
        scheme=args.scheme,
        verify_ssl=args.verify_ssl,
        timeout=args.timeout,
    )

    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    out_path = Path("outputs") / f"dynamic_{action_id}_{normalized_template_id}_{ts}.json"

    output_data = {
        "created_at_utc": datetime.now(timezone.utc).isoformat(),
        "action_id": action_id,
        "template_id": normalized_template_id,
        "spl": spl,
        "result_count": len(results),
        "message_count": len(messages),
        "messages": messages,
        "results": results,
    }

    save_json(out_path, output_data)

    return results, out_path, output_data


def print_step_summary(step: int, action_id: str, decision_note: str, analysis: Dict[str, Any], out_path: Path) -> None:
    metrics = analysis["result_metrics"]
    indicator_values = metrics["coinhive_domains_found"] + metrics["coinhive_ips_found"]

    print(f"Étape {step}")
    print(f"Décision        : {decision_note}")
    print(f"Action exécutée : {action_id} — {ACTION_LABELS[action_id]}")
    print("Résultats Splunk :")
    if action_id == "A6":
        print(f"- Événements correspondant à A6 : {metrics['splunk_row_count']}")
        print("- Critères A6                    : Coinhive ET BSTOLL-L/BudStoll dans le même événement")
        if metrics["splunk_row_count"] > 0:
            print(f"- Événements Symantec bloqués    : {metrics['blocked_event_count']}")
            print(f"- Blocages liés à Coinhive       : {metrics['coinhive_blocked_event_count']}")
            print(f"- Événements corrélés à H1       : {metrics['h1_correlated_event_count']}")
    else:
        print(f"- Lignes retournées              : {metrics['splunk_row_count']} {metrics['result_unit']}")

    # La limite reste conservée dans le JSON. Elle n'est affichée que si elle
    # peut avoir tronqué les résultats et donc modifier l'interprétation.
    if metrics["query_limit_reached"]:
        print(
            f"- Attention                      : limite de {metrics['query_limit']} lignes atteinte; "
            "le total réel peut être supérieur"
        )

    if action_id in {"A1", "A2", "A3"}:
        domain_count = len(metrics["coinhive_domains_found"])
        ip_count = len(metrics["coinhive_ips_found"])
        print(
            f"- Indicateurs Coinhive distincts : {metrics['coinhive_indicator_count']} "
            f"({domain_count} domaine(s), {ip_count} adresse(s) IP)"
        )
        if indicator_values:
            print(f"- Indicateurs observés           : {', '.join(indicator_values)}")

    observed_context = []
    if metrics["target_host_found"]:
        observed_context.append("hôte BSTOLL-L")
    if metrics["target_ip_found"]:
        observed_context.append("IP 192.168.247.131")
    if metrics["target_user_found"]:
        observed_context.append("utilisateur budstoll")
    if metrics["target_process_found"]:
        observed_context.append("processus chrome.exe")
    # Pour A6, les termes trouvés globalement dans plusieurs lignes ne forment
    # pas une corrélation. Les compteurs événement par événement ci-dessus sont
    # donc la seule synthèse de contexte affichée.
    if observed_context and action_id != "A6":
        print(f"- Contexte cible observé         : {', '.join(observed_context)}")

    if action_id == "A4":
        correlation = analysis.get("evidence_details", {}).get("a3_a4_correlation", {})
        if correlation.get("correlated"):
            matching_hash = correlation["matching_sha256"][0]
            print("- Corrélation A3–A4              : confirmée")
            print(f"- SHA-256 commun                 : {matching_hash}")
            print(
                "- Délai processus → premier flux : "
                f"{correlation['closest_time_delta_seconds']:.1f} seconde(s)"
            )
        else:
            print("- Corrélation A3–A4              : non confirmée")

    status_labels = {
        "preuve_directe_ou_principale_trouvee": "preuve directe ou principale trouvée",
        "contexte_trouve_sans_preuve_directe": "contexte trouvé, sans preuve directe",
        "preuve_indirecte_trouvee": "preuve indirecte trouvée",
        "preuve_endpoint_correlee_forte": "preuve endpoint corrélée à A3",
        "preuve_endpoint_corroborante": "preuve endpoint complémentaire trouvée",
        "signal_non_trouve": "signal recherché non trouvé",
        "non_concluant": "résultat non concluant",
    }
    print("Évaluation :")
    print(f"- Résultat de la recherche       : {status_labels[analysis['finding_status']]}")
    print(f"- Qualification de la preuve    : {analysis['evidence_category']}")
    print(f"- Récompense de cette action     : {format_signed(analysis['reward'])} point(s)")
    print(f"- Récompense cumulée             : {analysis['cumulative_reward_after_action']:g} point(s)")
    print(f"- Interprétation                 : {analysis['comment']}")
    print(f"Fichier JSON                     : {out_path}")


def print_final_report(state: Dict[str, Any], final_path: Path) -> None:
    """Affiche une synthèse courte; tous les détails restent disponibles en JSON."""
    verdict = (
        state.get("stop_decision", {}).get("verdict")
        if isinstance(state.get("stop_decision"), dict)
        else None
    ) or final_verdict(state)
    timeline = state.get("timeline", [])
    latest_by_action = {item["action_id"]: item for item in timeline}

    print("\n" + "=" * 80)
    print("SYNTHÈSE FINALE — CHASSE H1")
    print("=" * 80)

    print("Hypothèse :")
    print("H1 — Accès possible à une infrastructure liée à Coinhive ou à du minage embarqué visible par DNS.")

    print("\nVerdict automatique du système :")
    print(f"- Décision  : {verdict['verdict']}")
    print(f"- Confiance : {verdict['confidence']}")
    print(f"- Raison    : {verdict['reason']}")

    print("\nPreuves retenues :")
    evidence_printed = False

    if state.get("dns_positive") and "A1" in latest_by_action:
        item = latest_by_action["A1"]
        metrics = item["result_metrics"]
        print(
            f"- A1 DNS       : {metrics['coinhive_event_count']} événement(s) correspondant(s) "
            f"parmi {item['result_count']} ligne(s); "
            f"{len(metrics['coinhive_domains_found'])} domaine(s) et "
            f"{len(metrics['coinhive_ips_found'])} IP Coinhive distincts."
        )
        evidence_printed = True

    if state.get("network_flow_positive") and "A3" in latest_by_action:
        item = latest_by_action["A3"]
        metrics = item["result_metrics"]
        flow_records = item.get("evidence_details", {}).get("network_flow_evidence", [])
        exact_flow_count = sum(
            bool(record.get("indicator_found") and record.get("source_is_target") and record.get("process_is_target"))
            for record in flow_records
        )
        flow_context = []
        if metrics.get("target_process_found"):
            flow_context.append("chrome.exe")
        if metrics.get("target_user_found"):
            flow_context.append("BudStoll")
        context_text = " et ".join(flow_context) or "contexte processus incomplet"
        print(
            f"- A3 Cisco NVM : {exact_flow_count} flux exact(s) parmi {item['result_count']} ligne(s), "
            f"associé(s) à {context_text}."
        )
        evidence_printed = True

    correlation = state.get("a3_a4_correlation", {})
    if state.get("sysmon_positive", state.get("endpoint_positive")) and "A4" in latest_by_action:
        item = latest_by_action["A4"]
        endpoint_records = item.get("evidence_details", {}).get("endpoint_process_evidence", [])
        exact_endpoint_count = sum(
            bool(record.get("host_is_target") and record.get("process_is_target"))
            for record in endpoint_records
        )
        if correlation.get("correlated"):
            print(
                f"- A4 Sysmon    : {exact_endpoint_count} événement(s) exact(s) parmi "
                f"{item['result_count']} ligne(s); même SHA-256 qu'A3 "
                f"et flux observé environ {correlation['closest_time_delta_seconds']:.1f} seconde(s) "
                "après le lancement de chrome.exe sur BSTOLL-L."
            )
        else:
            metrics = item["result_metrics"]
            endpoint_context = []
            if metrics.get("target_process_found"):
                endpoint_context.append("chrome.exe")
            if metrics.get("target_host_found"):
                endpoint_context.append("BSTOLL-L")
            context_text = " sur ".join(endpoint_context) or "contexte endpoint incomplet"
            print(
                f"- A4 Sysmon    : {item['result_count']} événement(s) {context_text}; "
                "corrélation technique avec A3 non confirmée."
            )
        evidence_printed = True

    if not evidence_printed:
        print("- Aucune preuve principale retenue.")

    non_conclusive = [
        item for item in timeline
        if item.get("evidence_level") == "non_concluant"
    ]
    if non_conclusive:
        print("\nRésultats non concluants :")
        for item in non_conclusive:
            print(f"- {item['action_id']} : {item['comment']}")

    print("\nParcours des actions :")
    print(" -> ".join(state.get("executed_actions", [])))

    stop_decision = state.get("stop_decision")
    print("\nDécision d'arrêt / interruption :")
    if stop_decision:
        print(f"- Choisie par PPO : {'oui' if stop_decision['chosen_by_ppo'] else 'non'}")
        print(f"- Mode            : {stop_decision['mode']}")
        print(f"- Motif           : {stop_decision['reason']}")
    else:
        print("- Aucune décision d'arrêt enregistrée.")

    print("\nValidation humaine :")
    print("- Statut   : en attente")
    print("- Décision : à confirmer par l'analyste à partir des preuves ci-dessus")

    print(f"\nTrace JSON complète : {final_path}")
    print("=" * 80)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Orchestration dynamique PPO + Splunk pour H1.")

    parser.add_argument("--model", default="outputs/ppo_hunting_h1_v5_2.zip")
    parser.add_argument("--max-steps", type=int, default=7)

    parser.add_argument("--index", default="botsv3")
    parser.add_argument("--earliest", default="0")
    parser.add_argument("--latest", default="now")
    parser.add_argument("--limit", type=int, default=200)

    parser.add_argument("--host", default=os.getenv("SPLUNK_HOST", "localhost"))
    parser.add_argument("--port", type=int, default=int(os.getenv("SPLUNK_PORT", "8089")))
    parser.add_argument("--scheme", choices=["https", "http"], default=os.getenv("SPLUNK_SCHEME", "https"))
    parser.add_argument("--username", default=os.getenv("SPLUNK_USERNAME", "burlegate"))
    parser.add_argument("--password", default=os.getenv("SPLUNK_PASSWORD"))
    parser.add_argument("--verify-ssl", type=str_to_bool, default=False)
    parser.add_argument("--timeout", type=int, default=180)

    return parser.parse_args()


def main() -> int:
    args = parse_args()
    args.limit = normalize_limit(args.limit)
    if args.max_steps < 1:
        raise ValueError("--max-steps doit être supérieur ou égal à 1.")
    if args.port < 1 or args.port > 65535:
        raise ValueError("--port doit être compris entre 1 et 65535.")
    if args.timeout < 1:
        raise ValueError("--timeout doit être supérieur ou égal à 1.")

    model_path = Path(args.model)
    if not model_path.exists() and not Path(str(model_path) + ".zip").exists():
        raise FileNotFoundError(f"Modèle PPO introuvable : {model_path}")

    print("=" * 80)
    print("ORCHESTRATION DYNAMIQUE H1 — PPO + SPLUNK")
    print("=" * 80)
    print(f"Modèle PPO : {args.model}")
    print(f"Contrat PPO: {CONTRACT_VERSION} ({len(OBSERVATION_FEATURES)} variables)")
    print(f"Splunk     : {args.scheme}://{args.host}:{args.port}")
    print(f"Index      : {args.index}")
    print("=" * 80)

    try:
        model = MaskablePPO.load(str(model_path))
    except Exception as exc:
        raise ValueError(
            "Impossible de charger le modèle comme MaskablePPO V5.2. "
            "Vérifiez que --model pointe vers outputs/ppo_hunting_h1_v5_2.zip."
        ) from exc
    validate_model_contract(model)

    password = args.password
    if not password:
        password = getpass.getpass(f"Mot de passe Splunk pour {args.username}: ")
    state = initial_state()

    run_trace = []
    execution_error = None

    for step in range(1, args.max_steps + 1):
        action_id, decision_note, decision_source = choose_action_with_ppo(
            model,
            state,
            max_steps=args.max_steps,
        )

        if action_id == "A7":
            verdict = final_verdict(state)
            chosen_by_ppo = decision_source == "ppo"
            stop_mode = "choisi_par_ppo" if chosen_by_ppo else "selectionne_par_garde_fou"
            stop_reason = decision_note
            print("\n" + "-" * 80)
            print(f"Décision d'arrêt A7 — étape {step}")
            print(f"Mode            : {stop_mode}")
            print(f"Choisie par PPO : {'oui' if chosen_by_ppo else 'non'}")
            print(f"Décision        : {decision_note}")
            print(f"Verdict automatique : {verdict['verdict']}")
            print(f"Raison          : {verdict['reason']}")
            state["stop_decision"] = {
                "mode": stop_mode,
                "chosen_by_ppo": chosen_by_ppo,
                "decision_source": decision_source,
                "step": step,
                "reason": stop_reason,
                "verdict": deepcopy(verdict),
            }
            state["executed_actions"].append("A7")
            run_trace.append(
                {
                    "step": step,
                    "ppo_decision": decision_note,
                    "action_id": "A7",
                    "action_label": ACTION_LABELS["A7"],
                    "stop_mode": stop_mode,
                    "chosen_by_ppo": chosen_by_ppo,
                    "decision_source": decision_source,
                    "reason": stop_reason,
                    "verdict": verdict,
                    "state_after_action": deepcopy(state),
                }
            )
            break

        try:
            results, out_path, raw_output = execute_splunk_action(
                action_id=action_id,
                args=args,
                password=password,
            )
        except Exception as exc:  # La trace partielle doit survivre à une panne Splunk.
            execution_error = {
                "step": step,
                "action_id": action_id,
                "exception_type": type(exc).__name__,
                "message": str(exc),
            }
            run_trace.append({
                "step": step,
                "ppo_decision": decision_note,
                "action_id": action_id,
                "action_label": ACTION_LABELS[action_id],
                "decision_source": decision_source,
                "execution_error": deepcopy(execution_error),
                "state_before_failed_action": deepcopy(state),
            })
            print(f"\nERREUR Splunk pendant {action_id} : {exc}")
            print("La chasse est interrompue; un rapport partiel va être sauvegardé.")
            break

        analysis = analyze_result(
            action_id,
            results,
            query_limit=args.limit,
            state=state,
        )
        state = update_state(state, analysis)

        # Ajoute l'analyse explicite au fichier JSON de l'action.
        raw_output["analysis"] = analysis
        save_json(out_path, raw_output)

        print_step_summary(step, action_id, decision_note, analysis, out_path)

        run_trace.append(
            {
                "step": step,
                "ppo_decision": decision_note,
                "action_id": action_id,
                "action_label": ACTION_LABELS[action_id],
                "decision_source": decision_source,
                "output_file": str(out_path),
                "analysis": analysis,
                "state_after_action": deepcopy(state),
            }
        )

    if execution_error is not None:
        verdict = {
            "verdict": "investigation_interrompue",
            "confidence": "non_evaluee",
            "reason": (
                f"Le résultat de H1 ne peut pas être évalué : l'exécution Splunk "
                f"a échoué pendant {execution_error['action_id']}."
            ),
        }
        state["stop_decision"] = {
            "mode": "interruption_erreur_splunk",
            "chosen_by_ppo": False,
            "decision_source": "orchestrateur_securite",
            "step": execution_error["step"],
            "reason": f"Exécution interrompue pendant {execution_error['action_id']} : {execution_error['message']}",
            "verdict": deepcopy(verdict),
        }
    elif state.get("stop_decision") is None:
        forced_step = len(state.get("executed_actions", [])) + 1
        forced_reason = f"limite technique de {args.max_steps} étapes atteinte"
        verdict = final_verdict(state)
        state["stop_decision"] = {
            "mode": "limite_max_steps",
            "chosen_by_ppo": False,
            "decision_source": "orchestrateur",
            "step": forced_step,
            "reason": forced_reason,
            "verdict": deepcopy(verdict),
        }
        if "A7" not in state["executed_actions"]:
            state["executed_actions"].append("A7")
        run_trace.append(
            {
                "step": forced_step,
                "ppo_decision": None,
                "action_id": "A7",
                "action_label": ACTION_LABELS["A7"],
                "stop_mode": "limite_max_steps",
                "chosen_by_ppo": False,
                "decision_source": "orchestrateur",
                "reason": forced_reason,
                "verdict": verdict,
                "state_after_action": deepcopy(state),
            }
        )

    # Le verdict calculé au moment d'A7 est conservé tel quel. Le contrat V5.2
    # exclut déjà A7 du comptage, mais cette copie rend la trace immuable.
    final = deepcopy(state["stop_decision"]["verdict"])

    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    final_path = Path("outputs") / f"dynamic_hunt_H1_report_{ts}.json"

    save_json(
        final_path,
        {
            "created_at_utc": datetime.now(timezone.utc).isoformat(),
            "hypothesis": "H1 Coinhive",
            "policy_contract": {
                "version": CONTRACT_VERSION,
                "observation_features": list(OBSERVATION_FEATURES),
                "action_ids": list(ACTION_IDS),
            },
            "final_verdict": final,
            "final_state": state,
            "scoring_summary": scoring_summary(state),
            "human_validation": {
                "status": "en_attente",
                "decision": None,
                "comment": "Le verdict automatique doit être confirmé par un analyste humain.",
            },
            "execution_error": execution_error,
            "run_trace": run_trace,
        },
    )

    print_final_report(state, final_path)

    return 1 if execution_error is not None else 0


if __name__ == "__main__":
    raise SystemExit(main())
