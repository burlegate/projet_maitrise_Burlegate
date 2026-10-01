# Clôture de l'audit V5.2 — H1 Coinhive

Date : 29 août 2026

## Conclusion

La V5.2 est un nouveau modèle réentraîné, et non un simple renommage de la
V5.1. Elle conserve la corrélation forte A3-A4 et ajoute une politique
adaptative capable d'utiliser A2 HTTP et A5 Windows Security lorsque les
résultats les rendent utiles.

## Corrections principales

| Point audité | Correction V5.2 | Vérification |
|---|---|---|
| A2/A5 absentes des parcours V5.1 | Scénarios directs HTTP/Windows, variables dédiées et rewards contextuels | Parcours d'acceptation contenant A2 et A5 |
| Parcours unique de la V5.1 | Douze scénarios et quatre parcours déterministes observés | Métadonnées du modèle |
| A6 indirecte exécutée trop tôt | A6 attend les suivis directs pertinents A2/A5 | Test du masque |
| A7 automatique ou prématurée | A7 n'est admissible qu'avec un verdict défendable, puis reste choisie par PPO | 12/12 arrêts choisis par PPO |
| Répétition d'une recherche | A1 à A6 masquées après exécution | Test de non-répétition |
| Faux résultat A4 vide | Filtre `Image="*\\chrome.exe"` conservé | Test SPL et données BOTS réelles |
| Corrélation approximative | Même paire A3-A4, même SHA-256 et délai de 0 à 300 s | Test croisé négatif et paire réelle à 6,406 s |

## Contrat PPO

- Algorithme : MaskablePPO.
- Entraînement : 200 000 étapes demandées, seed 42, CPU.
- Espace d'action : `Discrete(7)` pour A1 à A7.
- Observation : `Box(21,)`.
- Scénarios d'évaluation : 12.
- Arrêt opérationnel `--stop-when-supported` : absent.
- Confirmation humaine : toujours en attente après le verdict automatique.

Le masque impose des contraintes métier; il ne choisit aucune action. A7 est
temporairement indisponible seulement lorsqu'aucun verdict défendable ne peut
encore être produit. Dès qu'elle devient admissible, PPO décide entre A7 et les
recherches encore possibles.

## Résultat de l'évaluation du modèle

| Groupe de scénarios | Parcours déterministe | Verdict représentatif | A7 par PPO |
|---|---|---|---|
| BOTS fort | A3 → A4 → A1 → A7 | hypothese_soutenue | oui |
| HTTP direct nécessaire | A3 → A4 → A1 → A2 → A7 | hypothese_partiellement_soutenue | oui |
| Windows direct nécessaire | A3 → A4 → A1 → A5 → A7 | hypothese_partiellement_soutenue | oui |
| EDR seul ou aucune preuve | A3 → A4 → A1 → A6 → A7 | non_concluante | oui |

Critères d'acceptation :

- 0 arrêt prématuré;
- 12/12 épisodes terminés par A7 choisi par PPO;
- 2/2 scénarios forts correctement soutenus;
- scénario HTTP direct utilisant A2;
- scénario Windows direct utilisant A5;
- quatre parcours distincts;
- scénario BOTS fort arrêté sans A6 inutile.

Les détails des 12 épisodes, versions logicielles, paramètres et rewards sont
enregistrés dans `outputs/ppo_hunting_h1_v5_2_metadata.json`.

## Validation code et données BOTS

- 17 tests unitaires et d'intégration : succès.
- Contrat du modèle : 7 actions et 21 observations validées au chargement.
- Modèle V5/V5.1 à 19 observations : incompatible et refusé par
  l'orchestrateur V5.2.
- Rejeu sur les exports BOTS réels : `A3 → A4 → A1 → A7`.
- Résultats réels retrouvés : 6 flux A3, 5 événements A4 et 28 événements A1.
- Corrélation réelle : SHA-256
  `268A0463D7CB907D45E1C2AB91703E71734116F08B2C090E34C2D506183F9BCA`,
  délai `6,406 s`, verdict `hypothese_soutenue`, confiance forte.

## Portée et limites

- L'environnement PPO simule des résultats; Splunk réel reste la source de
  preuve pendant l'orchestration.
- Les templates contrôlés ciblent le schéma BOTS v3. Une autre base utilisant
  des champs différents exige une adaptation des templates.
- A2/A5 ne sont pas obligatoires. Elles sont sélectionnées lorsqu'elles sont
  pertinentes et que les preuves principales ne suffisent pas encore.
- Les indicateurs Coinhive sont propres à H1 et doivent être versionnés si le
  jeu d'indicateurs change.
- Le verdict automatique assiste l'analyste; l'humain confirme ou rejette la
  conclusion finale à partir des preuves et de la trace JSON.
