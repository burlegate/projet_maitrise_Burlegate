"""
spl_templates_controlled.py
---------------------------
Templates SPL contrôlés pour la chasse H1.

Version V5.2 adaptative (correctif SPL V5.1 conservé):
- Corrige le bug UnboundLocalError: process_search dans dns_lookup.
- A1 / dns_lookup cherche seulement les domaines Coinhive observés en pré-chasse.
- A3 / cisco_nvm_flow_lookup utilise sourcetype="syslog" source="cisconvmflowdata".
- A3 est resserré: sa=IP source ET (da=IP Coinhive OU dh=domaine Coinhive).
- A4 / sysmon_process_lookup utilise Sysmon XML, extrait les champs avec rex, et cible host=BSTOLL-L + BudStoll + chrome.exe + EventID=1.
- A6 / symantec_alert_lookup exige, dans le même événement, un indicateur Coinhive ET le contexte de la cible H1.
- A3 et A4 exposent les SHA-256 et horodatages nécessaires à leur corrélation automatique.
- A7 / stop_decision reste une action PPO, sans requête Splunk.

Objectif:
- PPO choisit une action: A1, A2, A3, A4, A5, A6, A7.
- Python transforme l'action en requête SPL contrôlée via template_id.
- Aucun SPL libre généré par un LLM n'est exécuté directement.
"""

from __future__ import annotations

import re
from copy import deepcopy
from typing import Any, Dict, Iterable, List, Optional


DEFAULT_H1_INDICATORS: Dict[str, List[str]] = {
    "domains": [
        "coinhive.com",
        "ws001.coinhive.com",
        "ws005.coinhive.com",
        "ws011.coinhive.com",
        "ws014.coinhive.com",
        "ws019.coinhive.com",
    ],
    "src_ips": ["192.168.247.131"],
    "dest_ips": [
        "37.187.167.21",
        "217.182.164.14",
        "37.187.166.108",
        "37.187.165.41",
        "104.20.208.59",
        "37.187.167.47",
    ],
    # Optionnel. On peut laisser vide pour ne pas injecter un host fixe.
    # Si besoin: --param hosts=BSTOLL-L
    "hosts": [],
    "users": ["BudStoll", "AzureAD\\BudStoll"],
    "process_names": ["chrome.exe"],
}


ACTION_TO_TEMPLATE: Dict[str, str] = {
    "A1": "dns_lookup",
    "A2": "http_context_lookup",
    "A3": "cisco_nvm_flow_lookup",
    "A4": "sysmon_process_lookup",
    "A5": "windows_security_lookup",
    "A6": "symantec_alert_lookup",
    "A7": "stop_decision",
}

TEMPLATE_TO_ACTION: Dict[str, str] = {v: k for k, v in ACTION_TO_TEMPLATE.items()}

TEMPLATE_DESCRIPTIONS: Dict[str, str] = {
    "dns_lookup": "A1 - Vérifier les résolutions DNS vers les domaines suspects seulement.",
    "dns_host_context_lookup": "Contexte optionnel - Activité DNS générale de l'hôte source, hors PPO par défaut.",
    "http_context_lookup": "A2 - Chercher un contexte HTTP/web autour de l'activité.",
    "cisco_nvm_flow_lookup": "A3 - Vérifier les flux Cisco NVM vers les destinations suspectes.",
    "sysmon_process_lookup": "A4 - Vérifier processus/utilisateur/parent process avec Sysmon.",
    "windows_security_lookup": "A5 - Chercher contexte Windows Security.",
    "symantec_alert_lookup": "A6 - Chercher un événement Symantec reliant Coinhive à l'hôte ou l'utilisateur cible.",
    "stop_decision": "A7 - Stop: pas de requête Splunk; décision PPO/agent.",
}


class TemplateError(ValueError):
    """Erreur liée à un template SPL contrôlé."""


def available_templates() -> List[str]:
    return list(TEMPLATE_DESCRIPTIONS.keys())


def normalize_template_id(template_or_action: str) -> str:
    """Accepte A1..A7 ou un template_id et retourne le template_id."""
    value = str(template_or_action).strip()
    if value in ACTION_TO_TEMPLATE:
        return ACTION_TO_TEMPLATE[value]
    if value in TEMPLATE_DESCRIPTIONS:
        return value
    raise TemplateError(f"Template/action inconnu: {template_or_action}")


def default_h1_params() -> Dict[str, Any]:
    return {
        "index": "botsv3",
        "earliest": "0",
        "latest": "now",
        "limit": 200,
        **deepcopy(DEFAULT_H1_INDICATORS),
    }


def merge_params(overrides: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    params = default_h1_params()
    if overrides:
        for key, value in overrides.items():
            if value is None:
                continue
            params[key] = value
    return params


def _ensure_list(value: Any) -> List[str]:
    if value is None:
        return []
    if isinstance(value, (list, tuple, set)):
        return [str(v).strip() for v in value if str(v).strip()]
    text = str(value).strip()
    if not text:
        return []
    if "," in text:
        return [part.strip() for part in text.split(",") if part.strip()]
    return [text]


def _clean_token(value: Any) -> str:
    text = str(value).strip()
    text = text.replace("\r", " ").replace("\n", " ")
    text = re.sub(r"\s+", " ", text)
    if len(text) > 300:
        raise TemplateError(f"Valeur trop longue pour un paramètre SPL: {text[:50]}...")
    return text


def _spl_quote(value: Any) -> str:
    text = _clean_token(value)
    text = text.replace("\\", "\\\\").replace('"', '\\"')
    return f'"{text}"'


def _safe_index(index: Any) -> str:
    text = _clean_token(index or "botsv3")
    if not re.fullmatch(r"[A-Za-z0-9_\-*.]+", text):
        raise TemplateError(f"Index non autorisé: {text}")
    return text


def _safe_time(value: Any, default: str) -> str:
    text = _clean_token(value or default)
    if not re.fullmatch(r"[A-Za-z0-9_@:+./\-]+", text):
        raise TemplateError(f"Valeur temporelle non autorisée: {text}")
    return text


def normalize_limit(value: Any, default: int = 200) -> int:
    """Normalise la limite une seule fois pour SPL, métriques et rapport."""
    try:
        number = int(value)
    except Exception:
        number = default
    return max(1, min(number, 5000))


def _raw_terms(values: Iterable[Any]) -> str:
    items = [_spl_quote(v) for v in values if str(v).strip()]
    if not items:
        return ""
    return "(" + " OR ".join(items) + ")"


def _field_or_terms(field: str, values: Iterable[Any]) -> str:
    """Construit (field="v1" OR field="v2") avec valeurs sécurisées."""
    if not re.fullmatch(r"[A-Za-z0-9_]+", field):
        raise TemplateError(f"Nom de champ non autorisé: {field}")
    items = [f"{field}={_spl_quote(v)}" for v in values if str(v).strip()]
    if not items:
        return ""
    if len(items) == 1:
        return items[0]
    return "(" + " OR ".join(items) + ")"


def _base_search(params: Dict[str, Any], sourcetype_expr: str) -> str:
    index = _safe_index(params.get("index"))
    earliest = _safe_time(params.get("earliest"), "0")
    latest = _safe_time(params.get("latest"), "now")
    return f"search index={index} earliest={earliest} latest={latest} {sourcetype_expr}"


def _domains_only_terms(params: Dict[str, Any]) -> str:
    """Termes pour A1 DNS: domaines seulement, pas src_ip/dest_ip."""
    domains = _ensure_list(params.get("domains"))
    return _raw_terms(domains)


def _host_context_terms(params: Dict[str, Any]) -> str:
    """Termes pour contexte hôte DNS: IP source / host, sans domaines obligatoires."""
    src_ips = _ensure_list(params.get("src_ips"))
    hosts = _ensure_list(params.get("hosts"))
    return _raw_terms(src_ips + hosts)


def _h1_terms(params: Dict[str, Any], include_process: bool = False) -> str:
    """Termes larges pour actions de contexte."""
    domains = _ensure_list(params.get("domains"))
    src_ips = _ensure_list(params.get("src_ips"))
    dest_ips = _ensure_list(params.get("dest_ips"))
    hosts = _ensure_list(params.get("hosts"))
    users = _ensure_list(params.get("users"))
    process_names = _ensure_list(params.get("process_names")) if include_process else []
    return _raw_terms(domains + src_ips + dest_ips + hosts + users + process_names)


def _cisco_nvm_flow_terms(params: Dict[str, Any]) -> str:
    """
    Termes stricts pour A3 Cisco NVM.
    On évite une recherche trop large comme OR "chrome.exe".
    La preuve réseau H1 doit montrer: source suspecte -> destination/domaines Coinhive.
    """
    src_ips = _ensure_list(params.get("src_ips"))
    dest_ips = _ensure_list(params.get("dest_ips"))
    domains = _ensure_list(params.get("domains"))

    sa_part = _field_or_terms("sa", src_ips)
    da_part = _field_or_terms("da", dest_ips)
    dh_part = _field_or_terms("dh", domains)

    dest_parts = [part for part in [da_part, dh_part] if part]
    if not dest_parts:
        return sa_part

    dest_expr = "(" + " OR ".join(dest_parts) + ")" if len(dest_parts) > 1 else dest_parts[0]
    if sa_part:
        return f"{sa_part} {dest_expr}"
    return dest_expr


def _symantec_h1_terms(params: Dict[str, Any]) -> str:
    """
    Termes stricts pour A6 Symantec.

    L'ancienne requête plaçait indicateurs, IP cible, utilisateurs et
    ``chrome.exe`` dans un seul grand OR. Elle pouvait donc retourner des
    événements sans rapport entre eux, par exemple Chrome sur un autre hôte et
    l'IP cible seulement comme adresse distante.

    La recherche corrigée impose deux groupes dans le même événement :
    1. au moins un domaine ou une IP Coinhive ;
    2. au moins une identité forte de la cible H1 (hôte ou utilisateur).

    ``chrome.exe`` n'est volontairement pas un critère suffisant : ce processus
    est trop fréquent pour identifier à lui seul la machine concernée.
    """
    domains = _ensure_list(params.get("domains"))
    dest_ips = _ensure_list(params.get("dest_ips"))
    hosts = _ensure_list(params.get("hosts")) or ["BSTOLL-L"]
    users = _ensure_list(params.get("users")) or ["BudStoll"]

    indicator_part = _raw_terms(domains + dest_ips)

    # Dans les données observées, 192.168.247.131 apparaît aussi comme adresse
    # locale d'un autre poste (MKRAEUS-L). L'IP seule n'est donc pas une identité
    # suffisamment fiable pour attribuer un événement à BSTOLL-L.
    target_part = _raw_terms(hosts + users)

    if indicator_part and target_part:
        # Deux groupes séparés dans une recherche Splunk sont combinés par AND.
        return f"{indicator_part} {target_part}"
    return indicator_part or target_part


def build_spl(template_or_action: str, overrides: Optional[Dict[str, Any]] = None) -> str:
    """Construit une requête SPL contrôlée."""
    template_id = normalize_template_id(template_or_action)
    params = merge_params(overrides)
    limit = normalize_limit(params.get("limit"))

    if template_id == "stop_decision":
        raise TemplateError("A7/stop_decision ne correspond à aucune requête Splunk.")

    if template_id == "dns_lookup":
        # A1 cherche les domaines suspects seulement.
        # On ne met pas 192.168.247.131 ici, sinon Splunk retourne tout le DNS de la machine.
        terms = _domains_only_terms(params)
        base = _base_search(params, 'sourcetype="stream:dns"')
        if terms:
            base = f"{base} {terms}"
        return (
            f"{base}\n"
            "| table _time host sourcetype source src src_ip dest dest_ip query answer reply_code message_type _raw\n"
            "| sort _time\n"
            f"| head {limit}"
        )

    if template_id == "dns_host_context_lookup":
        # Optionnel: contexte DNS de l'hôte, à utiliser seulement après A1 si besoin.
        terms = _host_context_terms(params)
        base = _base_search(params, 'sourcetype="stream:dns"')
        if terms:
            base = f"{base} {terms}"
        return (
            f"{base}\n"
            "| table _time host sourcetype source src src_ip dest dest_ip query answer reply_code message_type _raw\n"
            "| sort _time\n"
            f"| head {limit}"
        )

    if template_id == "http_context_lookup":
        terms = _h1_terms(params, include_process=True)
        base = _base_search(params, 'sourcetype="stream:http"')
        if terms:
            base = f"{base} {terms}"
        return (
            f"{base}\n"
            "| table _time host sourcetype source src src_ip dest dest_ip http_method method uri url site status user_agent _raw\n"
            "| sort _time\n"
            f"| head {limit}"
        )

    if template_id == "cisco_nvm_flow_lookup":
        # Dans BOTS v3, Cisco NVM est visible comme:
        # sourcetype="syslog" source="cisconvmflowdata".
        # La requête stricte vérifie: sa=192.168.247.131 ET destination/domaines Coinhive.
        terms = _cisco_nvm_flow_terms(params)
        base = _base_search(params, 'sourcetype="syslog" source="cisconvmflowdata"')
        if terms:
            base = f"{base} {terms}"
        return (
            f"{base}\n"
            "| table _time host sourcetype source sa da sp dp dh pn ph ppn pa osn fst fet msg _raw\n"
            "| sort _time\n"
            f"| head {limit}"
        )

    if template_id == "sysmon_process_lookup":
        # A4: Sysmon XML ciblé sur H1.
        # But: confirmer côté endpoint que chrome.exe a été lancé sur BSTOLL-L
        # par AzureAD\BudStoll, avec un événement Sysmon EventID 1 (Process Create).
        # Les champs utiles ne sont pas toujours extraits automatiquement par Splunk,
        # donc on les extrait depuis _raw avec rex.
        process_names = _ensure_list(params.get("process_names")) or ["chrome.exe"]
        hosts = _ensure_list(params.get("hosts")) or ["BSTOLL-L"]
        users = _ensure_list(params.get("users")) or ["BudStoll"]

        base = _base_search(
            params,
            'sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" source="WinEventLog:Microsoft-Windows-Sysmon/Operational"',
        )

        # Filtre host : évite de récupérer les Chrome d'autres machines comme FYODOR-L.
        host_part = _field_or_terms("host", hosts)
        if host_part:
            base = f"{base} {host_part}"

        # Dans le raw, on force à la fois le processus et l'utilisateur liés à H1.
        raw_process_terms = _raw_terms(process_names)
        raw_user_terms = _raw_terms(users)
        if raw_process_terms:
            base = f"{base} {raw_process_terms}"
        if raw_user_terms:
            base = f"{base} {raw_user_terms}"

        process_search_parts = []
        for process_name in process_names:
            # Seul le processus créé (Image) qualifie A4. Un chrome.exe présent
            # uniquement dans ParentImage ou CommandLine ne doit pas produire
            # un faux positif endpoint.
            simple_name = str(process_name).replace("/", "\\").split("\\")[-1]
            image_suffix = "\\" + simple_name
            process_search_parts.extend([
                f"Image={_spl_quote(simple_name)}",
                f"Image={_spl_quote('*' + image_suffix)}",
            ])
        process_search = " OR ".join(process_search_parts)

        user_search_parts = []
        # BudStoll suffit à matcher AzureAD\BudStoll et évite les problèmes d'échappement.
        for user in users:
            simple_user = str(user).split("\\")[-1]
            quoted = _spl_quote(f"*{simple_user}*")
            user_search_parts.append(f"User={quoted}")
        user_search = " OR ".join(user_search_parts)

        extra_search = '| search sysmon_event_id="1"\n'
        if process_search:
            extra_search += f"| search ({process_search})\n"
        if user_search:
            extra_search += f"| search ({user_search})\n"

        return (
            f"{base}\n"
            "| rex field=_raw \"<EventID[^>]*>(?<sysmon_event_id>\\d+)</EventID>\"\n"
            "| rex field=_raw \"<Data Name='UtcTime'>(?<UtcTime>[^<]+)</Data>\"\n"
            "| rex field=_raw \"<Data Name='Image'>(?<Image>[^<]+)</Data>\"\n"
            "| rex field=_raw \"<Data Name='ParentImage'>(?<ParentImage>[^<]+)</Data>\"\n"
            "| rex field=_raw \"<Data Name='CommandLine'>(?<CommandLine>[^<]+)</Data>\"\n"
            "| rex field=_raw \"<Data Name='User'>(?<User>[^<]+)</Data>\"\n"
            "| rex field=_raw \"<Data Name='Hashes'>(?<Hashes>[^<]+)</Data>\"\n"
            "| rex field=_raw \"<Data Name='ProcessId'>(?<ProcessId>[^<]+)</Data>\"\n"
            "| rex field=_raw \"<Data Name='ParentProcessId'>(?<ParentProcessId>[^<]+)</Data>\"\n"
            f"{extra_search}"
            "| table _time host sourcetype source sysmon_event_id UtcTime Image ParentImage CommandLine User Hashes ProcessId ParentProcessId _raw\n"
            "| sort _time\n"
            f"| head {limit}"
        )

    if template_id == "windows_security_lookup":
        terms = _h1_terms(params)
        base = _base_search(params, 'sourcetype="WinEventLog:Security"')
        if terms:
            base = f"{base} {terms}"
        return (
            f"{base}\n"
            "| table _time host sourcetype source EventCode Account_Name user src_ip dest_ip Logon_Type Process_Name _raw\n"
            "| sort _time\n"
            f"| head {limit}"
        )

    if template_id == "symantec_alert_lookup":
        # A6 doit retourner des événements individuellement corrélés à H1.
        # On ne mélange plus tous les critères dans un grand OR.
        terms = _symantec_h1_terms(params)
        base = _base_search(params, 'sourcetype=symantec*')
        if terms:
            base = f"{base} {terms}"
        return (
            f"{base}\n"
            "| table _time host sourcetype source action signature signature_id severity local_host local_ip remote_host remote_ip remote_port user process file_path _raw\n"
            "| sort _time\n"
            f"| head {limit}"
        )

    raise TemplateError(f"Template non implémenté: {template_id}")


if __name__ == "__main__":
    print("Templates disponibles:")
    for tid, desc in TEMPLATE_DESCRIPTIONS.items():
        print(f"- {tid}: {desc}")
    print("\nExemple A1 DNS corrigé:\n")
    print(build_spl("A1"))
