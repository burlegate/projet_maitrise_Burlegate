"""
Agent intelligent de recommandation d'actions de chasse - V2 corrigée.

Objectif :
- L'hypothèse vient de la pré-chasse. L'agent de chasse ne doit pas inventer une hypothèse.
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

import getpass
import re
import math
import hashlib
import sys
from datetime import datetime, timezone


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
- Recommander un catalogue candidat à vérifier avant intégration dans PPO.

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



H3_INSTRUCTIONS = """
ADAPTATION H3 :
- Le classement donne une priorité d'investigation, pas un verdict.
- Les comptages de l'indice I4 sont rapportés par la pré-chasse et restent à vérifier.
- Prévoir la vérification du libellé NIMLOC dans les événements bruts, des champs
  extraits, du type numérique, du transport et des ports SI ces données existent.
- Examiner les labels, leur structure, la répartition temporelle et par véritable
  hôte source. Ne pas assimiler automatiquement le champ host au client DNS.
- Ne pas déduire un protocole, un DGA ou un tunneling du seul libellé NIMLOC.
- Corréler les entités et périodes effectivement découvertes avec les autres
  sources pertinentes. Ne pas imposer une recherche HTTP sans justification.
- Les template_id désignent les familles de recherche de V5.2. Leurs requêtes
  actuelles ciblent H1 : elles NE SONT PAS exécutables pour H3 sans adaptation.
  Décrire ces adaptations et les paramètres à découvrir ; ne pas inventer leur valeur.
- Les IDs des recommandations (R1, R2...) ne sont pas les IDs PPO A1...A7.
  Plusieurs recommandations peuvent relever d'une même famille de recherche.
- Ne pas fournir de SPL libre, ni résultat de recherche inventé.
- Distinguer la confirmation du phénomène observé, une explication légitime étayée,
  des éléments soutenant une interprétation malveillante et un résultat non concluant.
  L'absence d'alerte n'établit pas la légitimité.
- Les coûts et rewards proposés sont indicatifs, jamais des règles déjà validées.
  Récompenser l'information utile, y compris celle soutenant une explication légitime.
- L'arrêt d'une investigation et le passage à l'hypothèse suivante sont distincts
  de l'arrêt de toute la campagne. Ne pas décider de ce dernier ici.
- Retourner l'hypothese_originale exactement comme le champ homonyme fourni.
"""


def validate_schema(value: Any, schema: dict[str, Any], path: str = "$" ) -> None:
    """Valide le sous-ensemble de JSON Schema employé ci-dessus, sans dépendance."""
    kind = schema["type"]
    correct = {"object": type(value) is dict, "array": type(value) is list,
               "string": type(value) is str, "integer": type(value) is int, "number": type(value) in (int, float) and math.isfinite(value)}[kind]
    if not correct:
        raise ValueError(f"{path} : type {kind} attendu")
    if "enum" in schema and value not in schema["enum"]:
        raise ValueError(f"{path} : valeur non autorisée")
    if kind == "object":
        required = set(schema["required"])
        if set(value) != required:
            raise ValueError(f"{path} : champs manquants {sorted(required-set(value))}, "
                             f"champs supplémentaires {sorted(set(value)-required)}")
        for key, item in value.items():
            validate_schema(item, schema["properties"][key], f"{path}.{key}")
    elif kind == "array":
        if len(value) < schema.get("minItems", 0) or len(value) > schema.get("maxItems", sys.maxsize):
            raise ValueError(f"{path} : nombre d'éléments incorrect")
        for i, item in enumerate(value):
            validate_schema(item, schema["items"], f"{path}[{i}]")
    elif kind == "string":
        if not value.strip():
            raise ValueError(f"{path} : texte vide")
        if "pattern" in schema and re.fullmatch(schema["pattern"], value) is None:
            raise ValueError(f"{path} : format invalide")
    elif kind in ("integer", "number"):
        if value < schema.get("minimum", -sys.maxsize) or value > schema.get("maximum", sys.maxsize):
            raise ValueError(f"{path} : valeur hors limites")


def check_catalog(catalog, hypothesis, schema):
    validate_schema(catalog, schema)
    if catalog['hypothese_originale'] != hypothesis['hypothese_originale']:
        raise ValueError("Le modèle a modifié l'hypothèse originale.")
    actions = catalog['actions_recommandees']
    ids = [a['id'] for a in actions]
    if len(ids) != len(set(ids)):
        raise ValueError("Identifiants d'actions dupliqués.")
    graph = {a['id']: a['dependances'] for a in actions}
    active, done = set(), set()
    def visit(node):
        if node not in graph:
            raise ValueError("Dépendance inconnue : " + node)
        if node in active:
            raise ValueError("Cycle dans les dépendances.")
        if node in done:
            return
        active.add(node)
        for dep in graph[node]:
            visit(dep)
        active.remove(node)
        done.add(node)
    for node in graph:
        visit(node)


def save_json(path, value):
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def main():
    base = Path(__file__).resolve().parent
    parser = argparse.ArgumentParser(description="Recommandation d'actions H3, adaptée du planificateur H1 V5.2")
    parser.add_argument('--hypothesis', type=Path, default=base/'data/hypothesis_H3_prechasse.json')
    parser.add_argument('--sources', type=Path, default=base/'data/sources_chasse.json')
    parser.add_argument('--rag_dir', type=Path, default=base/'rag')
    parser.add_argument('--schema', type=Path, default=base/'schemas/action_catalog_schema_H3.json')
    parser.add_argument('--out', type=Path, help='Fichier JSON facultatif, ne doit pas déjà exister')
    parser.add_argument('--model', default=os.getenv('OPENAI_MODEL', 'gpt-5.4-mini'))
    parser.add_argument('--raisonnement', choices=['low','medium','high'], default='medium')
    parser.add_argument('--max-output-tokens', type=int, default=16000)
    parser.add_argument('--verifier-entree', action='store_true', help='Vérification locale sans appel API')
    args = parser.parse_args()
    hypothesis, sources, schema = (load_json(p) for p in [args.hypothesis,args.sources,args.schema])
    rag = load_rag_dir(args.rag_dir)
    if hypothesis.get('hypothese_id') != 'H3' or not hypothesis.get('hypothese_originale') or not rag:
        raise ValueError('Entrée H3 ou guide manquant.')
    if args.max_output_tokens <= 0:
        raise ValueError('La limite de sortie doit être positive.')
    if args.out and args.out.exists():
        raise ValueError('Le fichier --out existe déjà. Choisir un autre nom.')
    if args.verifier_entree:
        print('Entrées chargées : H3, indice(s), sources, guide et schéma.')
        print(hypothesis['hypothese_originale'])
        print('Aucun appel API effectué. Sortie par défaut :', base/'outputs')
        return
    try:
        from openai import OpenAI
    except ImportError:
        raise RuntimeError('Installer les dépendances : python -m pip install -r requirements.txt') from None
    key = os.getenv('OPENAI_API_KEY')
    if not key:
        if not sys.stdin.isatty():
            raise RuntimeError('OPENAI_API_KEY absent. Lancer dans un terminal interactif ou définir cette variable.')
        key = getpass.getpass('Clé API OpenAI (saisie masquée) : ').strip()
    if not key:
        raise ValueError('Clé API vide.')
    request = dict(model=args.model, instructions=SYSTEM_PROMPT + H3_INSTRUCTIONS,
        input=build_user_prompt(hypothesis,sources,rag),
        reasoning={'effort':args.raisonnement}, max_output_tokens=args.max_output_tokens,
        text={'format':{'type':'json_schema','name':'action_catalog_H3','schema':schema,'strict':True}}, store=False)
    stamp = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%fZ')
    run_dir = base/'outputs'/stamp
    run_dir.mkdir(parents=True, exist_ok=False)
    save_json(run_dir/'demande_openai.json',request)
    save_json(run_dir/'parametres_execution.json',{
        'date_utc':stamp,'version_script':'H3_planner_1.0','python':sys.version,
        'openai_version':__import__('openai').__version__,
        'model':args.model,'reasoning':args.raisonnement,'max_output_tokens':args.max_output_tokens,
        'sha256_script':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        'sha256_demande':hashlib.sha256((run_dir/'demande_openai.json').read_bytes()).hexdigest(),
        'statut':'recommandations uniquement, aucun accès Splunk'})
    print('Appel OpenAI en cours. Dossier de cette exécution :',run_dir,flush=True)
    try:
        client = OpenAI(api_key=key, max_retries=0, timeout=300.0)
        response = client.responses.create(**request)
        save_json(run_dir/'reponse_openai.json', response.model_dump(mode='json'))
        if response.status != 'completed':
            raise RuntimeError('Réponse incomplète : consulter reponse_openai.json et incomplete_details. '
                               'Si la limite est atteinte, relancer avec --max-output-tokens 24000.')
        if not response.output_text:
            raise RuntimeError('Réponse sans texte exploitable ; consulter reponse_openai.json.')
        catalog = json.loads(response.output_text)
        check_catalog(catalog,hypothesis,schema)
        target = run_dir/'action_catalog_H3_recommande.json'
        save_json(target,catalog)
        if args.out:
            args.out.parent.mkdir(parents=True,exist_ok=True)
            with args.out.open('x',encoding='utf-8') as f:
                json.dump(catalog,f,ensure_ascii=False,indent=2)
        print('OK — Recommandations enregistrées :',target)
        print('À examiner avant adaptation des requêtes SPL, des règles et de PPO pour H3.')
    except Exception as exc:
        message = str(exc).replace(key,'[CLE_MASQUEE]')
        save_json(run_dir/'erreur.json',{'type':type(exc).__name__,'message':message})
        raise RuntimeError(message + '\nDiagnostic conservé dans : ' + str(run_dir)) from None


if __name__ == '__main__':
    try:
        main()
    except Exception as exc:
        print('ERREUR :',str(exc),file=sys.stderr)
        sys.exit(1)
