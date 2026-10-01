"""
Normalise un ancien catalogue d'actions généré par OpenAI
vers une structure contrôlée compatible avec la chasse V5.2.

Usage :
py normalize_action_catalog_v2.py ^
  --old outputs/action_catalog_H3_v2.json ^
  --hypothesis data/hypothesis_H3_prechasse.json ^
  --out outputs/actions_controllees_H3.json

IMPORTANT :
- Ce script ne rappelle PAS OpenAI.
- Il ne crée PAS de nouvelle action.
- Il ne change PAS le PPO.
- Il ne change PAS le modèle V5.2.
- Il ne change PAS le verdict.

Il sert seulement à :
- conserver l'hypothèse originale de pré-chasse ;
- supprimer les champs SPL libres ;
- convertir vers des template_id contrôlés ;
- retirer une éventuelle ancienne action timeline ;
- remettre les IDs A1...A7 selon la sémantique V5.2 ;
- conserver les dépendances entre actions.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Dict, List


# ============================================================
# Contrat des actions V5.2
# ============================================================

ACTION_ID_BY_TEMPLATE = {
    "dns_lookup": "A1",
    "http_context_lookup": "A2",
    "cisco_nvm_flow_lookup": "A3",
    "sysmon_process_lookup": "A4",
    "windows_security_lookup": "A5",
    "symantec_alert_lookup": "A6",
    "stop_decision": "A7",
}

ALLOWED_TEMPLATE_IDS = set(ACTION_ID_BY_TEMPLATE.keys())


# ============================================================
# Compatibilité avec les anciens catalogues
# ============================================================

TEMPLATE_BY_TYPE = {
    "dns": "dns_lookup",
    "http": "http_context_lookup",
    "network_flow": "cisco_nvm_flow_lookup",
    "endpoint": "sysmon_process_lookup",
    "windows_security": "windows_security_lookup",
    "security": "windows_security_lookup",
    "edr": "symantec_alert_lookup",
    "stop": "stop_decision",
}

TEMPLATE_BY_SOURCE = {
    "stream:dns": "dns_lookup",
    "stream:http": "http_context_lookup",
    "syslog/cisconvmflowdata": "cisco_nvm_flow_lookup",
    "cisconvmflowdata": "cisco_nvm_flow_lookup",
    "XmlWinEventLog:Microsoft-Windows-Sysmon/Operational":
        "sysmon_process_lookup",
    "WinEventLog:Security":
        "windows_security_lookup",
    "symantec*":
        "symantec_alert_lookup",
}


# ============================================================
# Fonctions utilitaires
# ============================================================

def load_json(path: Path) -> Dict[str, Any]:
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def get_hypothesis_text(h: Dict[str, Any]) -> str:
    """
    Récupère le texte original de l'hypothèse de pré-chasse.
    """

    for key in (
        "hypothese_originale",
        "rappel_hypothese",
        "affirmation",
        "description",
    ):
        value = h.get(key)

        if isinstance(value, str) and value.strip():
            return value.strip()

    raise ValueError(
        "Impossible de trouver le texte de l'hypothèse "
        "dans le fichier hypothesis."
    )


def get_hypothesis_id(
    old: Dict[str, Any],
    hypothesis: Dict[str, Any],
) -> str:
    """
    Récupère l'identifiant H1, H2, H3, etc.
    """

    candidates = [
        old.get("hypothese_id"),
        hypothesis.get("hypothese_id"),
        hypothesis.get("id"),
    ]

    for value in candidates:
        if isinstance(value, str) and value.strip():
            return value.strip()

    raise ValueError(
        "Impossible de déterminer l'identifiant de l'hypothèse."
    )


def as_list(value: Any) -> List[Any]:
    """
    Garantit qu'une valeur est retournée sous forme de liste.
    """

    if value is None:
        return []

    if isinstance(value, list):
        return value

    return [value]


# ============================================================
# Détermination du template contrôlé
# ============================================================

def choose_template(action: Dict[str, Any]) -> str:
    """
    Détermine le template_id contrôlé correspondant à une action.

    Ordre de priorité :
    1. template_id déjà valide ;
    2. source exacte ;
    3. source reconnue partiellement ;
    4. type_action.

    Une action inconnue déclenche une erreur.
    On ne transforme jamais automatiquement une action inconnue
    en timeline ou en stop.
    """

    existing_template = str(
        action.get("template_id", "")
    ).strip()

    # Si le catalogue possède déjà un template contrôlé.
    if existing_template:

        # Ancienne timeline :
        # elle sera supprimée plus tard.
        if existing_template == "timeline_builder":
            return "timeline_builder"

        if existing_template in ALLOWED_TEMPLATE_IDS:
            return existing_template

        raise ValueError(
            f"template_id non autorisé : {existing_template}"
        )

    action_type = str(
        action.get("type_action", "")
    ).strip().lower()

    source = str(
        action.get(
            "source",
            action.get("source_cible", "")
        )
    ).strip()

    # Ancienne timeline explicite.
    if action_type in {
        "timeline",
        "chronologie",
    }:
        return "timeline_builder"

    # --------------------------------------------------------
    # Source précise AVANT type_action.
    # Important pour distinguer Sysmon de Windows Security.
    # --------------------------------------------------------

    if source in TEMPLATE_BY_SOURCE:
        return TEMPLATE_BY_SOURCE[source]

    source_lower = source.lower()

    if "symantec" in source_lower:
        return "symantec_alert_lookup"

    if (
        "wineventlog:security" in source_lower
        or "windows security" in source_lower
    ):
        return "windows_security_lookup"

    if "sysmon" in source_lower:
        return "sysmon_process_lookup"

    if (
        "cisconvm" in source_lower
        or "cisco nvm" in source_lower
    ):
        return "cisco_nvm_flow_lookup"

    if "stream:dns" in source_lower:
        return "dns_lookup"

    if "stream:http" in source_lower:
        return "http_context_lookup"

    # --------------------------------------------------------
    # Ensuite seulement le type générique.
    # --------------------------------------------------------

    if action_type in TEMPLATE_BY_TYPE:
        return TEMPLATE_BY_TYPE[action_type]

    raise ValueError(
        "Impossible de déterminer un template contrôlé pour "
        f"l'action {action.get('id', '<sans id>')} "
        f"(type_action={action_type!r}, source={source!r})."
    )


# ============================================================
# Normalisation des actions
# ============================================================

def normalize_actions(
    old_actions: List[Dict[str, Any]],
) -> tuple[List[Dict[str, Any]], int]:
    """
    Normalise les actions sans en inventer.

    La timeline est retirée car elle n'est plus une action PPO
    dans V5.2.

    Les IDs sont déterminés par le template :
        DNS              -> A1
        HTTP             -> A2
        Cisco NVM        -> A3
        Sysmon           -> A4
        Windows Security -> A5
        Symantec         -> A6
        Stop             -> A7
    """

    prepared = []

    old_id_to_new_id: Dict[str, str] = {}

    seen_templates = set()

    timeline_removed = 0

    # --------------------------------------------------------
    # Première passe :
    # déterminer le template et le nouvel ID.
    # --------------------------------------------------------

    for action in old_actions:

        if not isinstance(action, dict):
            raise ValueError(
                "Chaque action doit être un objet JSON."
            )

        template_id = choose_template(action)

        # Timeline historique :
        # elle n'entre plus dans les actions PPO V5.2.
        if template_id == "timeline_builder":
            timeline_removed += 1
            continue

        if template_id in seen_templates:
            raise ValueError(
                f"Template dupliqué : {template_id}"
            )

        seen_templates.add(template_id)

        new_id = ACTION_ID_BY_TEMPLATE[template_id]

        old_id = str(
            action.get("id", "")
        ).strip()

        if old_id:
            old_id_to_new_id[old_id] = new_id

        prepared.append({
            "old_action": action,
            "id": new_id,
            "template_id": template_id,
        })

    # --------------------------------------------------------
    # Deuxième passe :
    # reconstruction propre.
    # --------------------------------------------------------

    normalized = []

    for item in prepared:

        action = item["old_action"]

        new_id = item["id"]

        template_id = item["template_id"]

        # ----------------------------------------------------
        # Dépendances
        # ----------------------------------------------------

        old_dependencies = as_list(
            action.get(
                "dependances",
                action.get("depends_on", [])
            )
        )

        dependencies = []

        for dependency in old_dependencies:

            dep = str(dependency).strip()

            if not dep:
                continue

            # Remapper ancien ID -> ID V5.2.
            dep = old_id_to_new_id.get(
                dep,
                dep
            )

            # Éviter dépendance vers soi-même.
            if dep == new_id:
                continue

            if dep not in dependencies:
                dependencies.append(dep)

        # ----------------------------------------------------
        # Reward
        # ----------------------------------------------------

        reward = action.get(
            "reward_suggere",
            {
                "positif": 0.5,
                "neutre": 0.0,
                "negatif": -0.1,
            }
        )

        if not isinstance(reward, dict):
            raise ValueError(
                f"reward_suggere invalide pour {new_id}"
            )

        # ----------------------------------------------------
        # Reconstruction.
        #
        # On NE copie PAS :
        # requete_spl_modele
        # spl
        # query
        # etc.
        # ----------------------------------------------------

        normalized_action = {

            "id": new_id,

            "nom": action.get(
                "nom",
                action.get(
                    "nom_action",
                    f"Action {new_id}"
                )
            ),

            "type_action": action.get(
                "type_action",
                "other"
            ),

            "source": action.get(
                "source",
                action.get(
                    "source_cible",
                    "other"
                )
            ),

            "objectif": action.get(
                "objectif",
                "Valider ou affaiblir l'hypothèse."
            ),

            "template_id": template_id,

            "cout_estime": int(
                action.get(
                    "cout_estime",
                    1
                ) or 1
            ),

            "dependances": dependencies,

            "preuve_attendue": as_list(
                action.get(
                    "preuve_attendue",
                    []
                )
            ),

            "condition_succes": action.get(
                "condition_succes",
                (
                    "La preuve réduit l'incertitude "
                    "sur l'hypothèse."
                )
            ),

            "reward_suggere": reward,

            "risques_limites": as_list(
                action.get(
                    "risques_limites",
                    []
                )
            ),
        }

        normalized.append(
            normalized_action
        )

    # --------------------------------------------------------
    # Ordre stable A1 -> A7.
    # --------------------------------------------------------

    action_order = {
        "A1": 1,
        "A2": 2,
        "A3": 3,
        "A4": 4,
        "A5": 5,
        "A6": 6,
        "A7": 7,
    }

    normalized.sort(
        key=lambda a: action_order[a["id"]]
    )

    return normalized, timeline_removed


# ============================================================
# Programme principal
# ============================================================

def main() -> None:

    parser = argparse.ArgumentParser(
        description=(
            "Normaliser un catalogue d'actions "
            "OpenAI vers V5.2 contrôlée"
        )
    )

    parser.add_argument(
        "--old",
        required=True,
        help="Catalogue JSON généré par OpenAI"
    )

    parser.add_argument(
        "--hypothesis",
        required=True,
        help="Hypothèse originale de pré-chasse"
    )

    parser.add_argument(
        "--out",
        required=True,
        help="Fichier JSON de sortie normalisé"
    )

    args = parser.parse_args()

    old_path = Path(args.old)

    hypothesis_path = Path(
        args.hypothesis
    )

    out_path = Path(
        args.out
    )

    old = load_json(
        old_path
    )

    hypothesis = load_json(
        hypothesis_path
    )

    hypothesis_text = get_hypothesis_text(
        hypothesis
    )

    hypothesis_id = get_hypothesis_id(
        old,
        hypothesis
    )

    old_actions = old.get(
        "actions_recommandees",
        []
    )

    if (
        not isinstance(old_actions, list)
        or not old_actions
    ):
        raise ValueError(
            "Le catalogue ne contient aucune "
            "liste actions_recommandees."
        )

    normalized_actions, timeline_removed = (
        normalize_actions(
            old_actions
        )
    )

    corrected = {

        "hypothese_source":
            "pre_chasse",

        "hypothese_id":
            hypothesis_id,

        "hypothese_originale":
            hypothesis_text,

        "role_agent_chasse": (
            "Recommander des actions de validation "
            "sans inventer ni reformuler l'hypothèse."
        ),

        "indicateurs_source": old.get(
            "indicateurs_source",
            (
                "Indicateurs issus de la pré-chasse "
                "et des observations intermédiaires, "
                "pas de la vérité terrain."
            )
        ),

        "objectif_chasse": old.get(
            "objectif_chasse",
            (
                "Valider ou affaiblir l'hypothèse "
                "par corrélation multi-sources."
            )
        ),

        "actions_recommandees":
            normalized_actions,

        "conditions_arret": old.get(
            "conditions_arret",
            {
                "hypothese_soutenue": (
                    "Arrêter si les preuves "
                    "sont suffisantes."
                ),

                "hypothese_non_concluante": (
                    "Arrêter si les sources utiles "
                    "ont été explorées mais que les "
                    "preuves restent insuffisantes."
                ),

                "continuer": (
                    "Continuer si une action disponible "
                    "peut encore réduire l'incertitude."
                ),
            }
        ),

        "notes_pour_ppo":
            old.get(
                "notes_pour_ppo",
                {}
            ),

        "controle_correction": {

            "hypothese_inventee_pendant_chasse":
                "non",

            "hypothese_source_pre_chasse":
                "oui",

            "requete_spl_libre_supprimee":
                "oui",

            "template_id_controles":
                "oui",

            "timeline_action_supprimee":
                (
                    "oui"
                    if timeline_removed > 0
                    else "non_presente"
                ),

            "nombre_timeline_supprimee":
                timeline_removed,

            "ppo_choisit_ordre_execution":
                "oui",
        }
    }

    out_path.parent.mkdir(
        parents=True,
        exist_ok=True
    )

    out_path.write_text(
        json.dumps(
            corrected,
            ensure_ascii=False,
            indent=2
        ),
        encoding="utf-8"
    )

    print(
        f"OK - Catalogue normalisé sauvegardé : "
        f"{out_path}"
    )

    print(
        "Actions conservées : "
        + " -> ".join(
            (
                f"{a['id']}:"
                f"{a['template_id']}"
            )
            for a in normalized_actions
        )
    )

    if timeline_removed > 0:
        print(
            f"Info - {timeline_removed} ancienne "
            "action timeline a été retirée."
        )


if __name__ == "__main__":
    main()