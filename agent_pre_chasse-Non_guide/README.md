# Pré-chasse DNS V3 — agents séparés avec debug

Cette version garde les deux agents séparés et ajoute une gestion robuste des erreurs JSON.

## Améliorations V3

- sauvegarde toujours la réponse brute dans `resultats/debug_output_text_...txt`;
- sauvegarde l'objet complet OpenAI dans `resultats/debug_response_object_...json`;
- ajoute `reasoning_effort` dans les métadonnées du rapport final;
- ajoute une boucle légère explicite de pré-chasse dans les prompts;
- permet de régler `--max-output-tokens`.

## Lancer en medium

```powershell
python .\agent_non_guide.py --csv "C:\Users\burle\Downloads\botsv3_dns_complet.csv" --raisonnement medium
python .\agent_guide_dns.py --csv "C:\Users\burle\Downloads\botsv3_dns_complet.csv" --raisonnement medium
```

## En cas d'erreur JSON

Regarder ou envoyer les fichiers créés dans `resultats` :

```text
debug_output_text_...
debug_response_object_...
```
