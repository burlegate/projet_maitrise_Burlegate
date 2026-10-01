# Chasse adaptative H1 — Coinhive — Version V5.2

Ce dossier contient le prototype utilisé pour investiguer l’hypothèse H1 issue de la phase de pré-chasse. H1 concerne un accès possible à une infrastructure liée à Coinhive ou à des ressources tierces de type minage embarqué, observables initialement dans les journaux DNS de BOTS v3.

L’objectif de cette partie du prototype est de vérifier progressivement H1 à l’aide de recherches contrôlées dans Splunk, puis de laisser un agent MaskablePPO sélectionner les actions de chasse à exécuter selon l’état courant de l’investigation.

## Rôle de la version V5.2

Dans ce dossier, V5.2 désigne la version expérimentale du prototype de chasse adaptative utilisée pour l’entraînement, les tests et l’exécution de H1.

Cette version regroupe :

- le catalogue d’actions A1 à A7 ;
- les modèles de requêtes SPL contrôlés ;
- les règles déterministes d’interprétation des résultats ;
- la représentation de l’état de l’investigation ;
- la fonction de récompense ;
- le masque des actions invalides ;
- la politique MaskablePPO entraînée ;
- les tests de validation associés.

V5.2 est donc un identifiant interne de version du prototype. Il ne s’agit pas d’une version de Splunk, de BOTS v3, de MITRE ATT&CK ou du modèle de langage.

## Catalogue des actions

Le prototype utilise sept actions :

| Action | Source ou fonction | Objectif |
|---|---|---|
| A1 | DNS | Vérifier les résolutions vers les domaines associés à Coinhive. |
| A2 | HTTP | Rechercher un contexte de navigation associé aux destinations étudiées. |
| A3 | Cisco NVM | Examiner les communications réseau et leur origine. |
| A4 | Sysmon | Examiner le processus local et son lien avec les flux. |
| A5 | Windows Security | Compléter le contexte de sécurité du poste. |
| A6 | Symantec | Rechercher des alertes ou des blocages liés aux indicateurs. |
| A7 | Arrêt | Terminer l’investigation lorsque les conditions l’autorisent. |

La numérotation des actions ne fixe pas leur ordre d’exécution. L’ordre est choisi par la politique MaskablePPO parmi les actions autorisées dans l’état courant.

## Structure du dossier

```text
.
├── data/
├── outputs/
├── rag/
├── schemas/
├── tests/
├── .gitignore
├── AUDIT_V5_2_VALIDATION.md
├── agent_action_planner_v2.py
├── evidence_interpreter_h1.py
├── gym_hunting_env_v1.py
├── hunting_policy_contract_v5.py
├── normalize_action_catalog_v2.py
├── requirements.txt
├── run_hunt_H1_splunk.py
├── spl_templates_controlled.py
├── splunk_executor_v1.py
└── train_ppo_hunting_h1_v5.py
```

## Description des principaux fichiers

| Fichier ou dossier | Rôle |
|---|---|
| `data/` | Contient les données de configuration ou les fichiers nécessaires à H1. Les gros fichiers bruts de BOTS v3 ne sont pas inclus dans le dépôt. |
| `outputs/` | Contient les résultats générés pendant l’exécution. Certains fichiers temporaires sont ignorés par Git selon `.gitignore`. |
| `rag/` | Contient les éléments de contexte ou de connaissances utilisés par le planificateur d’actions. |
| `schemas/` | Contient les schémas utilisés pour structurer ou valider les sorties. |
| `tests/` | Contient les tests de logique et d’intégration du prototype. |
| `AUDIT_V5_2_VALIDATION.md` | Résume les contrôles réalisés pour valider la version V5.2. |
| `agent_action_planner_v2.py` | Appelle le LLM afin de recommander les actions possibles pour investiguer H1. |
| `normalize_action_catalog_v2.py` | Normalise le catalogue d’actions recommandé afin de le rendre exploitable par le prototype. |
| `spl_templates_controlled.py` | Définit les modèles de requêtes SPL contrôlés associés aux actions de chasse. |
| `splunk_executor_v1.py` | Exécute les requêtes SPL dans Splunk au moyen de l’API REST locale. |
| `evidence_interpreter_h1.py` | Interprète les résultats retournés par Splunk et met à jour les preuves disponibles. |
| `gym_hunting_env_v1.py` | Définit l’environnement Gymnasium utilisé pour entraîner et exécuter l’agent de chasse. |
| `hunting_policy_contract_v5.py` | Définit le contrat de décision, les actions admissibles, les variables d’état et les règles associées. |
| `train_ppo_hunting_h1_v5.py` | Entraîne la politique MaskablePPO utilisée pour la chasse adaptative de H1. |
| `run_hunt_H1_splunk.py` | Lance l’exécution de la chasse H1 dans Splunk avec la politique entraînée. |
| `requirements.txt` | Liste les dépendances Python nécessaires. |

## Installation

Créer un environnement virtuel Python :

```powershell
python -m venv .venv
```

Activer l’environnement :

```powershell
.venv\Scripts\Activate.ps1
```

Installer les dépendances :

```powershell
python -m pip install -r requirements.txt
```

## Exécution générale

L’exécution complète suppose que Splunk Enterprise est installé localement, que le jeu de données BOTS v3 est accessible dans l’index attendu et que les paramètres de connexion sont correctement configurés.

Étapes générales :

```powershell
python normalize_action_catalog_v2.py
python train_ppo_hunting_h1_v5.py
python run_hunt_H1_splunk.py
```

Selon l’environnement local, certains chemins, paramètres Splunk ou fichiers de configuration peuvent devoir être ajustés.

## Résultat attendu

Dans l’exécution étudiée, la politique choisit le parcours suivant :

```text
A3 → A4 → A1 → A7
```

Le prototype exécute donc trois recherches avant de sélectionner l’action d’arrêt. Le verdict automatique produit pour H1 est « hypothèse soutenue ».

Ce verdict doit être interprété comme une conclusion du prototype à examiner par l’analyste. Les résultats soutiennent l’existence de communications vers l’infrastructure étudiée et leur association à `chrome.exe`, mais ils ne démontrent pas directement l’exécution effective d’un minage de cryptomonnaie ni une compromission certaine du poste.

## Tests et audit

Le fichier `AUDIT_V5_2_VALIDATION.md` conserve une trace des tests et contrôles réalisés sur la version V5.2. Ces contrôles portent notamment sur :

- les correspondances entre indicateurs ;
- la corrélation entre les résultats A3 et A4 ;
- les contraintes du masque d’actions ;
- la compatibilité du modèle entraîné ;
- le bon fonctionnement de la logique de décision.

Les tests peuvent être lancés avec :

```powershell
python -m pytest tests
```

## Limites

Ce prototype est spécialisé pour l’investigation de H1 dans BOTS v3. Les requêtes, les indicateurs, les règles d’interprétation et les conditions d’arrêt sont adaptés à cette hypothèse.

La version actuelle évalue la sélection adaptative d’actions préparées. Elle ne démontre pas une découverte entièrement autonome des indicateurs ni une généralisation à d’autres hypothèses ou à d’autres jeux de données sans adaptation.

La validation finale des preuves et du verdict reste sous la responsabilité de l’analyste.

## Sécurité et fichiers non inclus

Le dépôt ne doit pas contenir :

- clé API ;
- mot de passe Splunk ;
- fichier `.env` ;
- environnement virtuel `.venv/` ;
- dossier `__pycache__/` ;
- gros fichiers bruts de BOTS v3 ;
- exports volumineux non nécessaires à la reproduction des résultats principaux.

Les fichiers ignorés sont définis dans `.gitignore`.
