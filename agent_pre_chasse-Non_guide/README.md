# Agent de pré-chasse non guidé

Ce dépôt contient l'implémentation de la configuration non guidée
de l'agent de pré-chasse développée dans le cadre du projet de maîtrise :

**Conception et évaluation d’un système intelligent en deux phases
pour l’automatisation de la pré-chasse et de la chasse aux menaces**

## Objectif

L'agent analyse des journaux DNS issus de BOTS v3 afin de produire
des hypothèses candidates de chasse aux menaces.

Dans cette configuration, aucun guide de connaissances DNS
complémentaire n'est fourni au modèle.

## Fonctionnement

1. Le script charge les consignes et le schéma JSON.
2. Le fichier CSV est transmis à l'API OpenAI.
3. Le LLM utilise Code Interpreter pour explorer les données.
4. Les observations sont utilisées pour formuler des hypothèses candidates.
5. Le rapport final est enregistré au format JSON.

## Structure

- `agent_non_guide.py` : point d'entrée
- `core_prechasse.py` : appel API et orchestration
- `prompts/non_guide.txt` : consignes de l'agent
- `schema_sortie.json` : structure JSON attendue
- `data/` : emplacement du fichier DNS
- `resultats/` : résultats conservés

## Installation

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
