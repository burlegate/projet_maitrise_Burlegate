"""
Agent intelligent de recommandation d'actions de chasse - V2 corrigée.

Objectif :
- L'hypothèse vient de la pré-chasse. L'agent de chasse ne doit pas inventer H1.
- L'agent recommande uniquement des actions de validation.
- Les requêtes SPL ne sont pas exécutées directement depuis OpenAI.
- La sortie utilise des template_id contrôlés qui seront exécutés plus tard par Python/Splunk.
"""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
from typing import Any, Dict

from openai import OpenAI


SYSTEM_PROMPT = """
Tu es un agent intelligent de chasse aux menaces.

REGLES OBLIGATOIRES :
1. L'hypothèse fournie provient déjà de la phase de pré-chasse.
2. Tu ne dois pas créer de nouvelle hypothèse.
3. Tu ne dois pas reformuler l'hypothèse comme une conclusion.
4. Tu dois recommander uniquement des actions de validation ou d'affaiblissement.
5. Tu ne dois pas conclure une compromission à partir du DNS seul.
6. Tu ne dois pas utiliser la vérité terrain BOTS v3, des réponses CTF, ou des connaissances spécifiques non fournies.
7. Les indicateurs fournis viennent de la pré-chasse ou des observations intermédiaires, pas de la vérité terrain.
8. Tu ne dois pas générer de requête SPL libre à exécuter directement.
9. Pour chaque action, choisis seulement un template_id parmi la liste autorisée.
10. La sortie doit respecter strictement le schéma JSON demandé.

ROLE :
- Analyser l'hypothèse fixe.
- Lire les sources disponibles pour la chasse.
- Utiliser le RAG général uniquement comme connaissance de domaine.
- Recommander un catalogue d'actions utilisable ensuite par PPO.

PPO choisira plus tard l'ordre d'exécution. Toi, tu proposes les actions possibles.
"""

ALLOWED_TEMPLATE_IDS = [
    "dns_lookup",
    "http_context_lookup",
    "cisco_nvm_flow_lookup",
    "sysmon_process_lookup",
    "windows_security_lookup",
    "symantec_alert_lookup",
    "stop_decision",
]


def load_json(path: Path) -> Dict[str, Any]:
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def load_rag_dir(rag_dir: Path) -> str:
    chunks = []
    for p in sorted(rag_dir.glob("*.md")):
        chunks.append(f"\n# Fichier RAG: {p.name}\n" + p.read_text(encoding="utf-8"))
    return "\n".join(chunks).strip()


def build_user_prompt(hypothesis: Dict[str, Any], sources: Dict[str, Any], rag_text: str) -> str:
    return f"""
Tu dois produire un catalogue d'actions de chasse pour PPO.

IMPORTANT : l'hypothèse ci-dessous est fixe et provient de la pré-chasse.
Tu ne dois pas l'inventer, la remplacer, ni la transformer en verdict.

# Hypothèse issue de la pré-chasse
{json.dumps(hypothesis, ensure_ascii=False, indent=2)}

# Sources disponibles pour la phase de chasse
{json.dumps(sources, ensure_ascii=False, indent=2)}

# Template IDs autorisés
{json.dumps(ALLOWED_TEMPLATE_IDS, ensure_ascii=False, indent=2)}

# RAG général de chasse
{rag_text}

# Travail demandé
Produit un JSON structuré avec :
- hypothese_source = "pre_chasse"
- hypothese_id
- hypothese_originale exactement comme l'entrée, sans la transformer en conclusion
- role_agent_chasse = recommandation d'actions seulement
- actions_recommandees avec template_id contrôlé, preuve_attendue, dépendances, coût, reward suggéré
- conditions_arret pour hypothèse soutenue, non concluante, continuer
- notes_pour_ppo avec état recommandé, règles interdites, stratégie reward

Ne mets pas de champ requete_spl_modele.
"""


def main() -> None:
    parser = argparse.ArgumentParser(description="Agent action planner V2 corrigé")
    parser.add_argument("--hypothesis", required=True, help="Fichier JSON d'hypothèse issue de pré-chasse")
    parser.add_argument("--sources", required=True, help="Fichier JSON des sources de chasse disponibles")
    parser.add_argument("--rag_dir", required=True, help="Dossier RAG général")
    parser.add_argument("--schema", default="schemas/action_catalog_schema_v2.json", help="Schéma JSON strict")
    parser.add_argument("--out", required=True, help="Fichier de sortie JSON")
    parser.add_argument("--model", default=os.getenv("OPENAI_MODEL", "gpt-5.4-mini"))
    args = parser.parse_args()

    hypothesis_path = Path(args.hypothesis)
    sources_path = Path(args.sources)
    rag_dir = Path(args.rag_dir)
    schema_path = Path(args.schema)
    out_path = Path(args.out)

    if not os.getenv("OPENAI_API_KEY"):
        raise RuntimeError("OPENAI_API_KEY est absent. Ajoute la clé dans PowerShell avant de lancer le script.")

    hypothesis = load_json(hypothesis_path)
    sources = load_json(sources_path)
    schema = load_json(schema_path)
    rag_text = load_rag_dir(rag_dir)

    client = OpenAI()
    prompt = build_user_prompt(hypothesis, sources, rag_text)

    response = client.responses.create(
        model=args.model,
        instructions=SYSTEM_PROMPT,
        input=prompt,
        text={
            "format": {
                "type": "json_schema",
                "name": "action_catalog_v2",
                "schema": schema,
                "strict": True,
            }
        },
        store=False,
    )

    raw = response.output_text
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError as e:
        raise RuntimeError(f"La réponse OpenAI n'est pas un JSON valide: {e}\nRéponse brute:\n{raw}") from e

    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(parsed, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"OK - Catalogue corrigé sauvegardé: {out_path}")


if __name__ == "__main__":
    main()
