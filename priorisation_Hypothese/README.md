
# Priorisation des hypothèses

Ce dossier contient le module de priorisation utilisé après la pré-chasse guidée.

Le module prend en entrée le rapport JSON produit par l’agent de pré-chasse V9, conserve les hypothèses telles qu’elles ont été générées et les classe selon plusieurs critères qualitatifs.

La priorisation ne constitue pas un verdict de sécurité. Le rang indique uniquement l’ordre proposé pour poursuivre l’investigation.

## Fichiers

- `priorisation_hypotheses.py` : script de priorisation.
- `prechasse_v9_dns_mini_rag_20260804T042327Z.json` : rapport de pré-chasse guidée utilisé comme entrée.
- `priorisation_hypotheses_20260929T012444745511Z.json` : résultat de priorisation retenu dans le rapport.

## Principe de fonctionnement

Le script extrait les hypothèses candidates du rapport de pré-chasse et les compare selon cinq critères :

- intérêt pour la sécurité ;
- appui dans les observations ;
- spécificité du signal ;
- risque de faux positif ;
- valeur pour la chasse.

Les hypothèses ne sont ni créées, ni supprimées, ni fusionnées ou reformulées pendant cette étape.

Le fichier CSV brut et la vérité terrain BOTS v3 ne sont pas transmis au module de priorisation.

## Exécution

Exemple :

```powershell
python .\priorisation_hypotheses.py `
  --rapport ".\prechasse_v9_dns_mini_rag_20260804T042327Z.json" `
  --raisonnement medium `
  --max-output-tokens 12000
