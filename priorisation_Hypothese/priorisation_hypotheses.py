#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
priorisation_hypotheses.py

Phase 2 du pipeline :
    1) La v9 génère les hypothèses candidates.
    2) Ce script charge EXACTEMENT ces hypothèses.
    3) OpenAI les étudie et les classe, sans pouvoir les réécrire.
    4) Le script vérifie le classement et sauvegarde le résultat.

Important :
- Aucun CSV n'est envoyé ici.
- Aucune nouvelle hypothèse ne doit être créée.
- Aucune hypothèse existante ne doit être supprimée, fusionnée ou modifiée.
- La vérité terrain BOTS v3 n'est jamais fournie au modèle.
"""

from __future__ import annotations

import argparse
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from openai import OpenAI


DEFAULT_MODEL = "gpt-5.4-mini"
VERSION_PRIORISATION = "v1_priorisation_hypotheses_v9"


def charger_json(path: Path) -> dict[str, Any]:
    if not path.exists():
        raise FileNotFoundError(f"Fichier introuvable : {path}")

    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def extraire_contexte_v9(
    rapport_json: dict[str, Any],
    expected_count: int,
) -> tuple[dict[str, Any], list[dict[str, Any]], list[str]]:
    rapport = rapport_json.get("rapport")
    if not isinstance(rapport, dict):
        raise ValueError("Le JSON ne contient pas l'objet 'rapport' attendu.")

    hypotheses = rapport.get("hypotheses_candidates")
    if not isinstance(hypotheses, list) or not hypotheses:
        raise ValueError(
            "Le rapport ne contient aucune liste 'hypotheses_candidates'."
        )

    if expected_count > 0 and len(hypotheses) != expected_count:
        raise ValueError(
            f"Nombre d'hypothèses inattendu : {len(hypotheses)}. "
            f"Attendu : {expected_count}."
        )

    ids = []
    for h in hypotheses:
        hid = h.get("id")
        if not isinstance(hid, str) or not hid.strip():
            raise ValueError("Une hypothèse ne possède pas d'identifiant valide.")
        ids.append(hid.strip())

    if len(ids) != len(set(ids)):
        raise ValueError(f"Identifiants d'hypothèses dupliqués : {ids}")

    contexte = {
        "resume_dataset": rapport.get("resume_dataset", {}),
        "socle_dns_dominant_ou_attendu": rapport.get(
            "socle_dns_dominant_ou_attendu", []
        ),
        "indices_dns_observes": rapport.get("indices_dns_observes", []),
        "hypotheses_candidates": hypotheses,
        "limites_generation": rapport.get("limites", []),
        "conclusion_pre_chasse": rapport.get("conclusion_pre_chasse", ""),
    }

    return contexte, hypotheses, ids


def construire_schema(ids: list[str]) -> dict[str, Any]:
    n = len(ids)

    niveau = {
        "type": "string",
        "enum": ["faible", "modere", "eleve"],
    }

    return {
        "type": "object",
        "additionalProperties": False,
        "required": [
            "methode",
            "classement",
            "synthese_priorisation",
        ],
        "properties": {
            "methode": {
                "type": "string",
                "description": (
                    "Description courte de la méthode qualitative appliquée."
                ),
            },
            "classement": {
                "type": "array",
                "minItems": n,
                "maxItems": n,
                "items": {
                    "type": "object",
                    "additionalProperties": False,
                    "required": [
                        "hypothese_id",
                        "rang",
                        "interet_securite",
                        "appui_observations",
                        "specificite_signal",
                        "risque_faux_positif",
                        "valeur_pour_chasse",
                        "justification_rang",
                        "points_forts",
                        "limites",
                    ],
                    "properties": {
                        "hypothese_id": {
                            "type": "string",
                            "enum": ids,
                        },
                        "rang": {
                            "type": "integer",
                            "minimum": 1,
                            "maximum": n,
                        },
                        "interet_securite": niveau,
                        "appui_observations": niveau,
                        "specificite_signal": niveau,
                        "risque_faux_positif": niveau,
                        "valeur_pour_chasse": niveau,
                        "justification_rang": {
                            "type": "string",
                        },
                        "points_forts": {
                            "type": "array",
                            "minItems": 1,
                            "maxItems": 4,
                            "items": {"type": "string"},
                        },
                        "limites": {
                            "type": "array",
                            "minItems": 1,
                            "maxItems": 4,
                            "items": {"type": "string"},
                        },
                    },
                },
            },
            "synthese_priorisation": {
                "type": "string",
            },
        },
    }


def construire_instructions(ids: list[str]) -> str:
    ids_txt = ", ".join(ids)

    return f"""
Tu es le MODULE DE PRIORISATION d'un agent de pré-chasse aux menaces DNS.

Ta mission est UNIQUEMENT de classer les hypothèses candidates déjà générées
par une phase précédente.

Hypothèses autorisées : {ids_txt}

RÈGLES ABSOLUES
1. Tu dois classer EXACTEMENT les hypothèses fournies.
2. Tu ne dois créer aucune nouvelle hypothèse.
3. Tu ne dois supprimer aucune hypothèse.
4. Tu ne dois fusionner aucune hypothèse.
5. Tu ne dois pas modifier le sens ou le contenu des hypothèses.
6. Tu ne dois pas renommer les identifiants.
7. Chaque identifiant doit apparaître exactement une fois dans le classement.
8. Les rangs doivent être uniques et continus de 1 à {len(ids)}.
9. Tu n'as accès à aucune vérité terrain BOTS v3.
10. Tu ne dois pas chercher à deviner la vérité terrain.
11. Tu ne dois utiliser aucun enrichissement externe, aucune recherche Web
    et aucune information absente du rapport fourni.
12. Un nom connu ou évocateur ne constitue pas à lui seul une preuve :
    le classement doit rester ancré dans les observables fournis.

CRITÈRES DE PRIORISATION
A. Intérêt sécurité :
   intérêt de l'hypothèse pour une investigation de sécurité.

B. Appui dans les observations :
   force des éléments réellement présents dans le rapport de génération.

C. Spécificité du signal :
   capacité de l'hypothèse à isoler un comportement distinct du bruit de fond.

D. Risque de faux positif :
   importance et plausibilité des explications légitimes déjà identifiées.

E. Valeur pour la chasse :
   intérêt de consacrer la prochaine phase de chasse à cette hypothèse.

PRINCIPE
La priorité ne signifie PAS que l'hypothèse est vraie.
Le rang 1 signifie seulement qu'elle constitue, parmi les candidats fournis,
la piste à investiguer en premier au regard des observations disponibles.

Tu dois produire uniquement la structure JSON demandée.
""".strip()


def valider_classement(
    resultat: dict[str, Any],
    ids_attendus: list[str],
) -> list[str]:
    classement = resultat.get("classement")
    if not isinstance(classement, list):
        raise ValueError("La réponse ne contient pas de 'classement' valide.")

    ids_recus = [x.get("hypothese_id") for x in classement]
    rangs = [x.get("rang") for x in classement]

    if len(classement) != len(ids_attendus):
        raise ValueError(
            f"Classement incomplet : {len(classement)} éléments reçus, "
            f"{len(ids_attendus)} attendus."
        )

    if set(ids_recus) != set(ids_attendus):
        raise ValueError(
            "Les IDs du classement ne correspondent pas exactement "
            f"aux hypothèses d'origine.\n"
            f"Attendus : {ids_attendus}\n"
            f"Reçus    : {ids_recus}"
        )

    if len(ids_recus) != len(set(ids_recus)):
        raise ValueError("Une hypothèse apparaît plusieurs fois dans le classement.")

    rangs_attendus = list(range(1, len(ids_attendus) + 1))
    if sorted(rangs) != rangs_attendus:
        raise ValueError(
            f"Rangs invalides. Attendus : {rangs_attendus}, reçus : {rangs}"
        )

    classement_ordre = sorted(classement, key=lambda x: x["rang"])
    return [x["hypothese_id"] for x in classement_ordre]


def prioriser(
    rapport_path: Path,
    output_dir: Path,
    model: str,
    reasoning_effort: str,
    max_output_tokens: int,
    max_retries: int,
    expected_count: int,
) -> Path:
    source = charger_json(rapport_path)
    contexte, hypotheses_originales, ids = extraire_contexte_v9(
        source,
        expected_count=expected_count,
    )

    schema = construire_schema(ids)
    instructions = construire_instructions(ids)

    print("=" * 80)
    print("PRIORISATION DES HYPOTHÈSES DNS — PHASE 2")
    print("=" * 80)
    print(f"Source                : {rapport_path}")
    print(f"Hypothèses figées     : {', '.join(ids)}")
    print(f"Modèle                : {model}")
    print(f"Raisonnement          : {reasoning_effort}")
    print(f"Max output tokens     : {max_output_tokens}")
    print("CSV brut              : NON envoyé")
    print("Vérité terrain        : NON fournie")
    print("=" * 80)

    client = OpenAI(max_retries=max_retries)

    input_payload = json.dumps(
        contexte,
        ensure_ascii=False,
        indent=2,
    )

    response = client.responses.create(
        model=model,
        reasoning={"effort": reasoning_effort},
        instructions=instructions,
        input=[
            {
                "role": "user",
                "content": (
                    "Voici le rapport de génération v9 à prioriser.\n\n"
                    + input_payload
                ),
            }
        ],
        max_output_tokens=max_output_tokens,
        text={
            "format": {
                "type": "json_schema",
                "name": "priorisation_hypotheses_dns",
                "strict": True,
                "schema": schema,
            }
        },
        store=False,
    )

    status = getattr(response, "status", None)
    print(f"\nStatut OpenAI         : {status}")

    if status != "completed":
        incomplete = getattr(response, "incomplete_details", None)
        error = getattr(response, "error", None)
        usage = getattr(response, "usage", None)

        print(f"Incomplete details    : {incomplete}")
        print(f"Erreur                : {error}")
        print(f"Usage                 : {usage}")

        raise RuntimeError(
            "La priorisation OpenAI n'est pas terminée.\n"
            f"status={status}\n"
            f"incomplete_details={incomplete}\n"
            f"error={error}\n"
            f"usage={usage}"
        )

    output_text = getattr(response, "output_text", "") or ""
    if not output_text.strip():
        raise RuntimeError("OpenAI a terminé sans produire de JSON exploitable.")

    try:
        priorisation_openai = json.loads(output_text)
    except json.JSONDecodeError as exc:
        raise RuntimeError(
            f"La sortie OpenAI n'est pas un JSON valide : {exc}"
        ) from exc

    ordre = valider_classement(priorisation_openai, ids)
    hypothese_prioritaire_id = ordre[0]

    # Les hypothèses sont recopiées depuis la v9 par le SCRIPT.
    # OpenAI ne les régénère pas dans la sortie finale.
    resultat_final = {
        "metadata": {
            "date_utc": datetime.now(timezone.utc).isoformat(),
            "version_priorisation": VERSION_PRIORISATION,
            "model": model,
            "reasoning_effort": reasoning_effort,
            "max_output_tokens": max_output_tokens,
            "source_rapport": str(rapport_path),
            "source_version_agent": source.get("metadata", {}).get(
                "version_agent"
            ),
            "response_id": getattr(response, "id", None),
            "principe": (
                "Les hypothèses sont figées depuis la v9. "
                "OpenAI classe uniquement les candidats existants."
            ),
        },
        "hypotheses_originales_v9": hypotheses_originales,
        "priorisation_openai": priorisation_openai,
        "resultat_priorisation": {
            "hypothese_prioritaire_id": hypothese_prioritaire_id,
            "ordre_ids": ordre,
        },
    }

    output_dir.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    output_path = output_dir / f"priorisation_hypotheses_{timestamp}.json"

    with output_path.open("w", encoding="utf-8") as f:
        json.dump(
            resultat_final,
            f,
            ensure_ascii=False,
            indent=2,
        )

    usage = getattr(response, "usage", None)

    print("\n" + "=" * 80)
    print("PRIORISATION TERMINÉE")
    print("=" * 80)
    print(f"Ordre                 : {' > '.join(ordre)}")
    print(f"Hypothèse prioritaire : {hypothese_prioritaire_id}")
    print(f"Usage                 : {usage}")
    print(f"Résultat               : {output_path}")
    print("=" * 80)

    return output_path


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Priorise les hypothèses candidates produites par agent_dns v9 "
            "sans les régénérer."
        )
    )

    parser.add_argument(
        "--rapport",
        required=True,
        type=Path,
        help="Chemin vers le fichier JSON produit par la v9.",
    )

    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path("resultats_priorisation"),
        help="Dossier de sortie (défaut : resultats_priorisation).",
    )

    parser.add_argument(
        "--model",
        default=DEFAULT_MODEL,
        help=f"Modèle OpenAI (défaut : {DEFAULT_MODEL}).",
    )

    parser.add_argument(
        "--raisonnement",
        choices=["low", "medium", "high"],
        default="medium",
        help="Effort de raisonnement (défaut : medium).",
    )

    parser.add_argument(
        "--max-output-tokens",
        type=int,
        default=12000,
        help="Limite de sortie incluant le raisonnement (défaut : 12000).",
    )

    parser.add_argument(
        "--max-retries",
        type=int,
        default=2,
        help=(
            "Nombre de retries gérés par le SDK après la tentative initiale "
            "(défaut : 2)."
        ),
    )

    parser.add_argument(
        "--expected-count",
        type=int,
        default=5,
        help="Nombre d'hypothèses attendu dans la v9 (défaut : 5).",
    )

    return parser.parse_args()


def main() -> None:
    args = parse_args()

    if not os.getenv("OPENAI_API_KEY"):
        raise RuntimeError(
            "La variable d'environnement OPENAI_API_KEY n'est pas définie."
        )

    prioriser(
        rapport_path=args.rapport.expanduser().resolve(),
        output_dir=args.output_dir.expanduser().resolve(),
        model=args.model,
        reasoning_effort=args.raisonnement,
        max_output_tokens=args.max_output_tokens,
        max_retries=args.max_retries,
        expected_count=args.expected_count,
    )


if __name__ == "__main__":
    main()
