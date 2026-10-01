# RAG général pour la chasse aux menaces

Ce document contient seulement des connaissances générales. Il ne contient pas de vérité terrain BOTS v3 et ne donne aucune réponse CTF.

## Principe
Une hypothèse issue du DNS doit être validée par corrélation multi-sources. Le DNS peut montrer qu'un domaine a été résolu, mais il ne prouve pas à lui seul :
- le processus local ;
- l'utilisateur ;
- l'exécution d'une charge utile ;
- une compromission ;
- une charge CPU anormale.

## Sources utiles
- DNS : domaines, sous-domaines, src_ip, dest_ip, query_type, reply_code, fenêtre temporelle.
- HTTP : site, URI, URL, user-agent, statut, contexte de navigation.
- Flux réseau enrichis : src_ip, dest_ip, port, processus, parent_process, user_account, destination host.
- Sysmon : processus local, parent process, command line, user, connexions réseau si présentes.
- Windows Security : connexions autorisées/bloquées, compte, processus, adresse source/destination.
- EDR/antivirus : signature, sévérité, action, blocage, quarantaine.
- Chronologie : aligner DNS, flux, endpoint et alertes pour réduire l'incertitude.

## Règles de prudence
- Ne jamais confirmer une compromission à partir du DNS seul.
- Ne pas inventer d'hôte, d'adresse IP, de processus ou de signature.
- L'absence d'alerte EDR ne réfute pas automatiquement l'hypothèse.
- Une trace HTTP absente ne réfute pas une communication si le trafic est chiffré ou non journalisé.
- Une conclusion forte nécessite plusieurs familles de logs cohérentes.
