# Agent de pré-chasse guidé par mini-RAG DNS

Ce dépôt contient l'implémentation de la configuration guidée de l'agent de pré-chasse développée dans le cadre du projet de maîtrise :

**Conception et évaluation d’un système intelligent en deux phases pour l’automatisation de la pré-chasse et de la chasse aux menaces**

## Objectif

L'agent analyse des journaux DNS issus du jeu de données BOTS v3 afin de produire plusieurs hypothèses candidates de chasse aux menaces.

Cette configuration est enrichie par un guide de connaissances DNS générales utilisé comme contexte complémentaire par le modèle. Le guide ne contient ni vérité terrain ni indicateur propre au scénario étudié.

## Fonctionnement

Le script `agent_dns_v9_mini_rag.py` :

1. charge le fichier CSV DNS ;
2. charge les consignes définies dans `prompts/agent_dns_v9_mini_rag.txt` ;
3. charge le guide DNS `knowledge/guide_dns_threat_hunting_general.txt` ;
4. charge le schéma de sortie `schema_sortie_v9.json` ;
5. transmet le CSV au modèle avec Code Interpreter ;
6. récupère le rapport structuré au format JSON ;
7. enregistre le résultat dans le dossier `resultats/`.

Le guide DNS sert uniquement de grille de lecture générale. Il fournit notamment des repères sur la rareté, les familles de sous-domaines, les réponses NXDomain, les types DNS atypiques, les FQDN structurés et la concentration par hôte.

## Structure du dépôt

```text
agent_prechasse_guidee-mini_rag/
├── agent_dns_v9_mini_rag.py
├── schema_sortie_v9.json
├── requirements.txt
├── .gitignore
├── README.md
├── data/
│   └── README.md
├── knowledge/
│   └── guide_dns_threat_hunting_general.txt
├── prompts/
│   └── agent_dns_v9_mini_rag.txt
└── resultats/
    └── prechasse_v9_dns_mini_rag_20260804T042327Z.json

