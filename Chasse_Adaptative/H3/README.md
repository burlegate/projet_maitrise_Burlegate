# Chasse adaptative – Hypothèse H3

Ce dossier contient les scripts, modèles et résultats utilisés pour l’investigation de l’hypothèse H3 dans le cadre du projet de maîtrise.

H3 provient de la phase de pré-chasse guidée et concerne les requêtes DNS NIMLOC présentant des noms fortement structurés. L’objectif de la chasse est d’examiner ce phénomène à l’aide de plusieurs sources de journaux afin de déterminer si les observations disponibles permettent d’établir un lien avec une activité malveillante ou une explication légitime.

La chasse H3 est distincte de celle de H1 : elle possède ses propres paramètres, règles d’interprétation, contrat de décision et environnement MaskablePPO.

## Structure du dossier

```text
chasse_H3/
│
├── data/
│   └── fichiers d'entrée nécessaires à l'investigation
│
├── models/
│   └── modèles MaskablePPO entraînés pour H3
│
├── outputs/
│   └── résultats bruts des recherches exécutées
│
├── rag/
│   └── ressources utilisées pour la recommandation des actions
│
├── resultats/
│   └── rapports, états de preuve et résultats de l'investigation
│
├── schemas/
│   └── schémas JSON utilisés pour structurer les sorties
│
├── agent_action_planner.py
├── executer_spl_H3.py
├── gym_hunting_env_h3.py
├── hunting_policy_contract_h3.py
├── ppo_h3_common.py
├── train_ppo_h3.py
├── run_ppo_h3_replay.py
├── test_contract_h3.py
├── test_gym_h3.py
├── requirements.txt
├── requirements_h3_ppo.txt
└── README.md
