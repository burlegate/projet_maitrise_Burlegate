"""Interprétation déterministe V5.2 des preuves Splunk pour l'hypothèse H1.

V5 applique trois principes auditables :
1. les indicateurs et processus sont comparés comme valeurs exactes ;
2. la corrélation A3-A4 conserve les faits par événement ;
3. reward, niveau de preuve et verdict ne sont jamais produits par un LLM.
"""

from __future__ import annotations

import re
from datetime import datetime
from pathlib import PureWindowsPath
from typing import Any, Dict, List, Optional, Sequence, Tuple

from hunting_policy_contract_v5 import classify_stop, supporting_source_count


COINHIVE_DOMAINS = {
    "coinhive.com",
    "ws001.coinhive.com",
    "ws005.coinhive.com",
    "ws011.coinhive.com",
    "ws014.coinhive.com",
    "ws019.coinhive.com",
}

COINHIVE_IPS = {
    "37.187.167.21",
    "217.182.164.14",
    "37.187.166.108",
    "37.187.165.41",
    "104.20.208.59",
    "37.187.167.47",
}

TARGET_HOST = "bstoll-l"
TARGET_IP = "192.168.247.131"
TARGET_USER = "budstoll"
TARGET_PROCESS = "chrome.exe"

ACTION_RESULT_UNITS = {
    "A1": "événement(s) DNS",
    "A2": "événement(s) HTTP",
    "A3": "ligne(s) de flux réseau Cisco NVM",
    "A4": "événement(s) Sysmon de création de processus",
    "A5": "événement(s) Windows Security",
    "A6": "événement(s) Symantec correspondant aux critères A6",
}

DOMAIN_PATTERN = re.compile(r"(?i)(?<![a-z0-9-])(?:[a-z0-9-]+\.)+[a-z]{2,}(?![a-z0-9-])")
IP_PATTERN = re.compile(r"(?<!\d)(?:\d{1,3}\.){3}\d{1,3}(?!\d)")
SHA256_PATTERN = re.compile(r"(?i)(?<![a-f0-9])([a-f0-9]{64})(?![a-f0-9])")
BLOCK_PATTERN = re.compile(r"\bblock(?:ed|ing)?\b", re.IGNORECASE)
XML_DATA_PATTERN = re.compile(
    r"<Data\s+Name=['\"](?P<name>[^'\"]+)['\"]>(?P<value>[^<]*)</Data>",
    re.IGNORECASE,
)
NVM_FIELD_PATTERN = re.compile(
    r"(?:^|\s)(?P<name>[a-z][a-z0-9_]*)=(?:\"(?P<quoted>[^\"]*)\"|(?P<plain>\S+))",
    re.IGNORECASE,
)


def empty_correlation() -> Dict[str, Any]:
    return {
        "hash_match": False,
        "matching_sha256": [],
        "closest_time_delta_seconds": None,
        "temporal_proximity_confirmed": False,
        "correlated": False,
        "matched_pair": None,
    }


def initial_state() -> Dict[str, Any]:
    return {
        "dns_positive": False,
        "http_positive": False,
        "http_context_found": False,
        "network_flow_positive": False,
        "sysmon_positive": False,
        # Alias conservé pour les anciens rapports, mais le contrat V5.2 utilise
        # explicitement sysmon_positive.
        "endpoint_positive": False,
        "windows_direct_found": False,
        "windows_context_found": False,
        "edr_indirect": False,
        "coinhive_indicator_found": False,
        "process_chrome_found": False,
        "user_budstoll_found": False,
        "host_bstoll_found": False,
        "target_ip_found": False,
        "network_flow_evidence": [],
        "endpoint_process_evidence": [],
        "network_process_hashes": [],
        "endpoint_process_hashes": [],
        "network_flow_start_times_utc": [],
        "endpoint_process_start_times_utc": [],
        "a3_a4_correlation": empty_correlation(),
        "evidence_score": 0.0,
        "multi_source_count": 0,
        "context_source_count": 0,
        "stop_decision": None,
        "executed_actions": [],
        "timeline": [],
    }


def result_rows(results: Any) -> List[Dict[str, Any]]:
    if isinstance(results, list):
        return [row for row in results if isinstance(row, dict)]
    if isinstance(results, dict):
        for key in ("results", "events"):
            if isinstance(results.get(key), list):
                return [row for row in results[key] if isinstance(row, dict)]
    return []


def count_results(results: Any) -> int:
    return len(result_rows(results))


def _row_text(row: Dict[str, Any]) -> str:
    return " ".join(str(value) for value in row.values()).lower()


def results_to_text(results: Any) -> str:
    return "\n".join(_row_text(row) for row in result_rows(results))


def result_row_texts(results: Any) -> List[str]:
    return [_row_text(row) for row in result_rows(results)]


def _field_values(row: Dict[str, Any], *names: str) -> List[str]:
    wanted = {name.lower() for name in names}
    values: List[str] = []
    for key, value in row.items():
        if str(key).lower() not in wanted or value in (None, ""):
            continue
        if isinstance(value, (list, tuple, set)):
            values.extend(str(item).strip() for item in value if str(item).strip())
        else:
            values.append(str(value).strip())
    return values


def _raw_text(row: Dict[str, Any]) -> str:
    values = _field_values(row, "_raw")
    return values[0] if values else ""


def _xml_fields(row: Dict[str, Any]) -> Dict[str, str]:
    return {
        match.group("name").lower(): match.group("value").strip()
        for match in XML_DATA_PATTERN.finditer(_raw_text(row))
    }


def _nvm_fields(row: Dict[str, Any]) -> Dict[str, str]:
    fields: Dict[str, str] = {}
    for match in NVM_FIELD_PATTERN.finditer(_raw_text(row)):
        fields[match.group("name").lower()] = (match.group("quoted") or match.group("plain") or "").strip()
    return fields


def _first_field(row: Dict[str, Any], names: Sequence[str], fallback: Optional[Dict[str, str]] = None) -> str:
    values = _field_values(row, *names)
    if values:
        return values[0]
    fallback = fallback or {}
    for name in names:
        value = fallback.get(name.lower())
        if value:
            return value
    return ""


def _basename(value: str) -> str:
    normalized = str(value).strip().replace("/", "\\")
    return PureWindowsPath(normalized).name.lower()


def _identity_token_present(text: str, value: str) -> bool:
    pattern = rf"(?<![a-z0-9_-]){re.escape(value.lower())}(?![a-z0-9_-])"
    return bool(re.search(pattern, text.lower()))


def _domains_and_ips(text: str) -> Tuple[set[str], set[str]]:
    domains = {match.lower().rstrip(".") for match in DOMAIN_PATTERN.findall(text)}
    ips = set(IP_PATTERN.findall(text))
    return domains, ips


def indicators_in_row(row: Dict[str, Any]) -> Tuple[List[str], List[str]]:
    domains, ips = _domains_and_ips(_row_text(row))
    return sorted(domains & COINHIVE_DOMAINS), sorted(ips & COINHIVE_IPS)


def has_coinhive_indicator(value: Any) -> bool:
    """Détection exacte : ``notcoinhive.com`` ne correspond pas à Coinhive."""
    if isinstance(value, dict):
        domains, ips = indicators_in_row(value)
        return bool(domains or ips)
    domains, ips = _domains_and_ips(str(value))
    return bool((domains & COINHIVE_DOMAINS) or (ips & COINHIVE_IPS))


def has_block_event(value: Any) -> bool:
    text = _row_text(value) if isinstance(value, dict) else str(value)
    return bool(BLOCK_PATTERN.search(text))


def has_symantec_target_identity(value: Any) -> bool:
    text = _row_text(value) if isinstance(value, dict) else str(value).lower()
    return _identity_token_present(text, TARGET_HOST) or _identity_token_present(text, TARGET_USER)


def _parse_datetime(value: str, formats: Sequence[str]) -> Optional[datetime]:
    cleaned = str(value).strip().removesuffix("Z")
    try:
        return datetime.fromisoformat(cleaned)
    except ValueError:
        pass
    for date_format in formats:
        try:
            return datetime.strptime(cleaned, date_format)
        except (TypeError, ValueError):
            continue
    return None


def _datetime_to_utc_text(value: Optional[datetime]) -> Optional[str]:
    return value.isoformat(timespec="milliseconds") + "Z" if value else None


def _sha256_from_value(value: str) -> Optional[str]:
    matches = SHA256_PATTERN.findall(str(value))
    return matches[0].upper() if matches else None


def extract_network_flow_evidence(results: Any) -> List[Dict[str, Any]]:
    evidence: List[Dict[str, Any]] = []
    for row_index, row in enumerate(result_rows(results)):
        fallback = _nvm_fields(row)
        domains, ips = indicators_in_row(row)
        process = _first_field(row, ("pn",), fallback)
        source_ip = _first_field(row, ("sa", "src", "src_ip"), fallback)
        destination_ip = _first_field(row, ("da", "dest", "dest_ip"), fallback)
        destination_domain = _first_field(row, ("dh",), fallback).lower().rstrip(".")
        user = _first_field(row, ("un", "user"), fallback)
        hash_value = _sha256_from_value(_first_field(row, ("ph",), fallback))
        time_value = _first_field(row, ("fst",), fallback)
        parsed_time = _parse_datetime(time_value, ("%a %b %d %H:%M:%S %Y",)) if time_value else None
        evidence.append({
            "row_index": row_index,
            "source_ip": source_ip,
            "destination_ip": destination_ip,
            "destination_domain": destination_domain,
            "process_name": process,
            "user": user,
            "sha256": hash_value,
            "start_time_utc": _datetime_to_utc_text(parsed_time),
            "indicator_found": bool(domains or ips),
            "source_is_target": source_ip.strip() == TARGET_IP,
            "process_is_target": _basename(process) == TARGET_PROCESS,
        })
    return evidence


def extract_endpoint_process_evidence(results: Any) -> List[Dict[str, Any]]:
    evidence: List[Dict[str, Any]] = []
    for row_index, row in enumerate(result_rows(results)):
        fallback = _xml_fields(row)
        image = _first_field(row, ("Image",), fallback)
        host = _first_field(row, ("host", "Computer"), fallback)
        user = _first_field(row, ("User",), fallback)
        hashes = _first_field(row, ("Hashes",), fallback)
        hash_value = _sha256_from_value(hashes)
        time_value = _first_field(row, ("UtcTime",), fallback)
        parsed_time = _parse_datetime(time_value, ("%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%d %H:%M:%S")) if time_value else None
        evidence.append({
            "row_index": row_index,
            "host": host,
            "user": user,
            "image": image,
            "sha256": hash_value,
            "start_time_utc": _datetime_to_utc_text(parsed_time),
            "host_is_target": host.strip().lower() == TARGET_HOST,
            "user_is_target": user.strip().lower().split("\\")[-1] == TARGET_USER,
            "process_is_target": _basename(image) == TARGET_PROCESS,
        })
    return evidence


def correlate_a3_a4(
    network_evidence: Sequence[Dict[str, Any]],
    endpoint_evidence: Sequence[Dict[str, Any]],
    max_delta_seconds: float = 300.0,
) -> Dict[str, Any]:
    """Corrèle une même paire d'événements par hash et temps."""
    candidates: List[Tuple[float, Dict[str, Any], Dict[str, Any]]] = []
    for network in network_evidence:
        if not (network.get("indicator_found") and network.get("source_is_target") and network.get("process_is_target")):
            continue
        for endpoint in endpoint_evidence:
            if not (endpoint.get("host_is_target") and endpoint.get("process_is_target")):
                continue
            network_hash = network.get("sha256")
            endpoint_hash = endpoint.get("sha256")
            if not network_hash or network_hash != endpoint_hash:
                continue
            network_time = _parse_datetime(str(network.get("start_time_utc") or ""), ())
            endpoint_time = _parse_datetime(str(endpoint.get("start_time_utc") or ""), ())
            if not network_time or not endpoint_time:
                continue
            delta = (network_time - endpoint_time).total_seconds()
            if 0 <= delta <= max_delta_seconds:
                candidates.append((delta, network, endpoint))

    if not candidates:
        return empty_correlation()

    delta, network, endpoint = min(candidates, key=lambda item: item[0])
    matching_hashes = sorted({item[1]["sha256"] for item in candidates})
    return {
        "hash_match": True,
        "matching_sha256": matching_hashes,
        "closest_time_delta_seconds": round(delta, 3),
        "temporal_proximity_confirmed": True,
        "correlated": True,
        "matched_pair": {
            "network_row_index": network["row_index"],
            "endpoint_row_index": endpoint["row_index"],
            "sha256": network["sha256"],
            "network_start_time_utc": network["start_time_utc"],
            "endpoint_start_time_utc": endpoint["start_time_utc"],
            "delta_seconds": round(delta, 3),
        },
    }


def extract_sha256_values(results: Any) -> List[str]:
    values = set()
    for row in result_rows(results):
        for value in row.values():
            match = _sha256_from_value(str(value))
            if match:
                values.add(match)
    return sorted(values)


def extract_nvm_flow_start_times(results: Any) -> List[str]:
    return sorted({item["start_time_utc"] for item in extract_network_flow_evidence(results) if item["start_time_utc"]})


def extract_sysmon_process_start_times(results: Any) -> List[str]:
    return sorted({item["start_time_utc"] for item in extract_endpoint_process_evidence(results) if item["start_time_utc"]})


def build_result_metrics(action_id: str, results: Any, query_limit: Optional[int] = None) -> Dict[str, Any]:
    rows = result_rows(results)
    domains: set[str] = set()
    ips: set[str] = set()
    for row in rows:
        row_domains, row_ips = indicators_in_row(row)
        domains.update(row_domains)
        ips.update(row_ips)

    network = extract_network_flow_evidence(results) if action_id == "A3" else []
    endpoint = extract_endpoint_process_evidence(results) if action_id == "A4" else []
    texts = [_row_text(row) for row in rows]
    limit = int(query_limit) if query_limit is not None else None

    if action_id == "A3":
        target_process_found = any(item["process_is_target"] for item in network)
        target_ip_found = any(item["source_is_target"] for item in network)
        target_user_found = any(item["user"].strip().lower().split("\\")[-1] == TARGET_USER for item in network)
        target_host_found = False
    elif action_id == "A4":
        target_process_found = any(item["process_is_target"] for item in endpoint)
        target_host_found = any(item["host_is_target"] for item in endpoint)
        target_user_found = any(item["user_is_target"] for item in endpoint)
        target_ip_found = any(_identity_token_present(text, TARGET_IP) for text in texts)
    else:
        target_process_found = any(_identity_token_present(text, TARGET_PROCESS) for text in texts)
        target_host_found = any(_identity_token_present(text, TARGET_HOST) for text in texts)
        target_user_found = any(_identity_token_present(text, TARGET_USER) for text in texts)
        target_ip_found = any(_identity_token_present(text, TARGET_IP) for text in texts)

    return {
        "splunk_row_count": len(rows),
        "result_unit": ACTION_RESULT_UNITS.get(action_id, "ligne(s) de résultat Splunk"),
        "query_limit": limit,
        "query_limit_reached": bool(limit is not None and len(rows) >= limit),
        "coinhive_indicator_count": len(domains) + len(ips),
        "coinhive_domains_found": sorted(domains),
        "coinhive_ips_found": sorted(ips),
        "target_host_found": target_host_found,
        "target_ip_found": target_ip_found,
        "target_user_found": target_user_found,
        "target_process_found": target_process_found,
        "blocked_event_count": sum(has_block_event(row) for row in rows),
        "coinhive_event_count": sum(has_coinhive_indicator(row) for row in rows),
        "coinhive_blocked_event_count": sum(has_block_event(row) and has_coinhive_indicator(row) for row in rows),
        "target_identity_event_count": sum(has_symantec_target_identity(row) for row in rows),
        "h1_correlated_event_count": sum(
            has_block_event(row) and has_coinhive_indicator(row) and has_symantec_target_identity(row)
            for row in rows
        ),
    }


def evidence_display_category(action_id: str, level: str) -> str:
    labels = {
        ("A1", "positive"): "preuve principale DNS",
        ("A2", "positive"): "preuve HTTP directe",
        ("A2", "contexte"): "preuve de contexte HTTP",
        ("A3", "forte"): "preuve principale réseau forte",
        ("A3", "positive"): "preuve principale réseau",
        ("A4", "forte"): "preuve endpoint corrélée forte avec A3",
        ("A4", "positive"): "preuve endpoint corroborante",
        ("A5", "forte"): "preuve complémentaire forte",
        ("A5", "contexte"): "preuve de contexte Windows",
        ("A6", "indirecte"): "preuve indirecte EDR corrélée événement par événement",
    }
    if level == "non_concluant":
        return "aucune preuve concluante"
    return labels.get((action_id, level), level)


def analyze_result(action_id: str, results: Any, query_limit: Optional[int] = None, state: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    state = state or initial_state()
    rows = result_rows(results)
    metrics = build_result_metrics(action_id, results, query_limit)
    count = metrics["splunk_row_count"]

    network_evidence = list(state.get("network_flow_evidence", []))
    endpoint_evidence = list(state.get("endpoint_process_evidence", []))
    if action_id == "A3":
        network_evidence = extract_network_flow_evidence(results)
    if action_id == "A4":
        endpoint_evidence = extract_endpoint_process_evidence(results)
    correlation = correlate_a3_a4(network_evidence, endpoint_evidence)

    analysis: Dict[str, Any] = {
        "action_id": action_id,
        "result_count": count,
        "result_unit": metrics["result_unit"],
        "result_metrics": metrics,
        "evidence_level": "non_concluant",
        "finding_status": "non_concluant",
        "evidence_category": "aucune preuve concluante",
        "reward": 0.0,
        "state_update": {},
        "evidence_details": {
            "network_flow_evidence": network_evidence,
            "endpoint_process_evidence": endpoint_evidence,
            "network_process_hashes": sorted({item["sha256"] for item in network_evidence if item.get("sha256")}),
            "endpoint_process_hashes": sorted({item["sha256"] for item in endpoint_evidence if item.get("sha256")}),
            "network_flow_start_times_utc": sorted({item["start_time_utc"] for item in network_evidence if item.get("start_time_utc")}),
            "endpoint_process_start_times_utc": sorted({item["start_time_utc"] for item in endpoint_evidence if item.get("start_time_utc")}),
            "a3_a4_correlation": correlation,
        },
        "comment": "",
    }

    if action_id == "A1":
        matching_rows = [row for row in rows if has_coinhive_indicator(row)]
        if matching_rows:
            analysis.update(evidence_level="positive", reward=1.3)
            analysis["state_update"] = {
                "dns_positive": True,
                "coinhive_indicator_found": True,
                "target_ip_found": metrics["target_ip_found"],
            }
            analysis["comment"] = f"{len(matching_rows)} événement(s) DNS contiennent un indicateur Coinhive exact."
        else:
            analysis["reward"] = -0.2
            analysis["comment"] = "Aucun indicateur DNS Coinhive exact n'a été trouvé."

    elif action_id == "A2":
        direct = [row for row in rows if has_coinhive_indicator(row)]
        context = [row for row in rows if _identity_token_present(_row_text(row), TARGET_IP)]
        if direct:
            analysis.update(evidence_level="positive", reward=1.0)
            analysis["state_update"] = {"http_positive": True, "coinhive_indicator_found": True}
            analysis["comment"] = f"{len(direct)} événement(s) HTTP contiennent un indicateur Coinhive exact."
        elif context:
            analysis.update(evidence_level="contexte", reward=0.1)
            analysis["state_update"] = {"http_context_found": True, "target_ip_found": True}
            analysis["comment"] = "Activité HTTP de la cible observée, sans indicateur Coinhive direct."
        else:
            analysis["comment"] = "Aucune preuve HTTP directe liée à Coinhive."

    elif action_id == "A3":
        strong = [item for item in network_evidence if item["indicator_found"] and item["source_is_target"] and item["process_is_target"]]
        positive = [item for item in network_evidence if item["indicator_found"] and item["source_is_target"]]
        if strong:
            analysis.update(evidence_level="forte", reward=1.7)
            analysis["state_update"] = {
                "network_flow_positive": True,
                "coinhive_indicator_found": True,
                "process_chrome_found": True,
                "target_ip_found": True,
                "user_budstoll_found": metrics["target_user_found"],
            }
            analysis["comment"] = (
                f"{len(strong)} flux Cisco NVM relient exactement la source {TARGET_IP}, "
                f"une destination Coinhive et le champ pn={TARGET_PROCESS}."
            )
            if correlation["correlated"]:
                analysis["comment"] += " La corrélation avec l'événement Sysmon A4 est confirmée."
        elif positive:
            analysis.update(evidence_level="positive", reward=1.2)
            analysis["state_update"] = {"network_flow_positive": True, "coinhive_indicator_found": True, "target_ip_found": True}
            analysis["comment"] = "Flux de la cible vers Coinhive trouvé, mais pn n'est pas exactement chrome.exe."
        else:
            analysis["reward"] = -0.2
            analysis["comment"] = "Aucun flux exact cible → Coinhive n'a été trouvé."

    elif action_id == "A4":
        exact_endpoint = [item for item in endpoint_evidence if item["host_is_target"] and item["process_is_target"]]
        process_only = [item for item in endpoint_evidence if item["process_is_target"]]
        if exact_endpoint and correlation["correlated"]:
            analysis.update(evidence_level="forte", reward=1.9)
            analysis["state_update"] = {
                "sysmon_positive": True,
                "endpoint_positive": True,
                "process_chrome_found": True,
                "host_bstoll_found": True,
                "user_budstoll_found": metrics["target_user_found"],
            }
            pair = correlation["matched_pair"]
            analysis["comment"] = (
                f"{len(exact_endpoint)} événement(s) Sysmon montrent Image=chrome.exe sur BSTOLL-L. "
                f"Une même paire A3-A4 partage le SHA-256 {pair['sha256']} et un délai de "
                f"{pair['delta_seconds']:.1f} seconde(s)."
            )
        elif exact_endpoint:
            analysis.update(evidence_level="positive", reward=1.0)
            analysis["state_update"] = {
                "sysmon_positive": True,
                "endpoint_positive": True,
                "process_chrome_found": True,
                "host_bstoll_found": True,
                "user_budstoll_found": metrics["target_user_found"],
            }
            analysis["comment"] = (
                f"{len(exact_endpoint)} événement(s) Sysmon montrent Image=chrome.exe sur BSTOLL-L, "
                "mais aucune même paire d'événements ne confirme encore hash et proximité temporelle avec A3."
            )
        elif process_only:
            analysis.update(evidence_level="positive", reward=0.7)
            analysis["state_update"] = {"sysmon_positive": True, "endpoint_positive": True, "process_chrome_found": True}
            analysis["comment"] = "Image=chrome.exe est observé dans Sysmon, mais pas sur l'hôte BSTOLL-L."
        else:
            analysis["reward"] = -0.2
            analysis["comment"] = "Aucun événement Sysmon avec Image exactement égal à chrome.exe."

    elif action_id == "A5":
        context_rows = [
            row for row in rows
            if any(_identity_token_present(_row_text(row), value) for value in (TARGET_HOST, TARGET_IP, TARGET_USER))
        ]
        direct_rows = [row for row in context_rows if has_coinhive_indicator(row)]
        if direct_rows:
            analysis.update(evidence_level="forte", reward=1.2)
            analysis["state_update"] = {
                "windows_direct_found": True,
                "windows_context_found": True,
                "coinhive_indicator_found": True,
            }
            analysis["comment"] = "Un même événement Windows Security relie la cible à un indicateur Coinhive."
        elif context_rows:
            analysis.update(evidence_level="contexte", reward=0.4)
            analysis["state_update"] = {
                "windows_context_found": True,
                "host_bstoll_found": metrics["target_host_found"],
                "target_ip_found": metrics["target_ip_found"],
                "user_budstoll_found": metrics["target_user_found"],
            }
            analysis["comment"] = "Windows Security confirme le contexte de la cible, sans preuve Coinhive directe."
        else:
            analysis["comment"] = "Windows Security ne fournit aucun contexte utile pour H1."

    elif action_id == "A6":
        correlated = [row for row in rows if has_block_event(row) and has_coinhive_indicator(row) and has_symantec_target_identity(row)]
        blocked_coinhive = [row for row in rows if has_block_event(row) and has_coinhive_indicator(row)]
        if correlated:
            analysis.update(evidence_level="indirecte", reward=0.5)
            analysis["state_update"] = {"edr_indirect": True, "coinhive_indicator_found": True}
            analysis["comment"] = f"{len(correlated)} événement(s) Symantec relient dans la même ligne blocage, Coinhive et cible H1."
        elif blocked_coinhive:
            analysis.update(evidence_level="indirecte", reward=0.3)
            analysis["state_update"] = {"edr_indirect": True, "coinhive_indicator_found": True}
            analysis["comment"] = "Blocage Coinhive observé dans un même événement Symantec, mais sans identité H1 confirmée."
        elif rows:
            analysis["comment"] = "Événements Symantec présents, sans événement unique reliant blocage, Coinhive et cible H1."
        else:
            analysis["comment"] = "Aucun événement Symantec correspondant à H1; cette absence ne réfute pas l'hypothèse."

    else:
        analysis["comment"] = "Action inconnue."

    if action_id == "A4" and analysis["evidence_level"] == "forte":
        analysis["finding_status"] = "preuve_endpoint_correlee_forte"
    elif action_id == "A4" and analysis["evidence_level"] == "positive":
        analysis["finding_status"] = "preuve_endpoint_corroborante"
    elif analysis["evidence_level"] in {"positive", "forte"}:
        analysis["finding_status"] = "preuve_directe_ou_principale_trouvee"
    elif analysis["evidence_level"] == "contexte":
        analysis["finding_status"] = "contexte_trouve_sans_preuve_directe"
    elif analysis["evidence_level"] == "indirecte":
        analysis["finding_status"] = "preuve_indirecte_trouvee"
    elif analysis["reward"] < 0:
        analysis["finding_status"] = "signal_non_trouve"

    analysis["evidence_category"] = evidence_display_category(action_id, analysis["evidence_level"])

    if action_id in {"A3", "A4"}:
        details = analysis["evidence_details"]
        analysis["state_update"].update({
            "network_flow_evidence": network_evidence,
            "endpoint_process_evidence": endpoint_evidence,
            "network_process_hashes": details["network_process_hashes"],
            "endpoint_process_hashes": details["endpoint_process_hashes"],
            "network_flow_start_times_utc": details["network_flow_start_times_utc"],
            "endpoint_process_start_times_utc": details["endpoint_process_start_times_utc"],
            "a3_a4_correlation": correlation,
        })

    return analysis


def update_state(state: Dict[str, Any], analysis: Dict[str, Any]) -> Dict[str, Any]:
    action_id = analysis["action_id"]
    if action_id not in state["executed_actions"]:
        state["executed_actions"].append(action_id)
    state.update(analysis["state_update"])
    state["evidence_score"] = round(float(state["evidence_score"]) + float(analysis["reward"]), 6)
    analysis["cumulative_reward_after_action"] = state["evidence_score"]
    state["multi_source_count"] = supporting_source_count(state)
    state["context_source_count"] = sum(
        bool(state.get(key))
        for key in ("http_context_found", "windows_context_found", "edr_indirect")
    )
    state["timeline"].append({
        "action_id": action_id,
        "result_count": analysis["result_count"],
        "result_unit": analysis["result_unit"],
        "result_metrics": analysis["result_metrics"],
        "evidence_level": analysis["evidence_level"],
        "finding_status": analysis["finding_status"],
        "evidence_category": analysis["evidence_category"],
        "reward": analysis["reward"],
        "cumulative_reward_after_action": analysis["cumulative_reward_after_action"],
        "comment": analysis["comment"],
        "evidence_details": analysis.get("evidence_details", {}),
    })
    return state


def final_verdict(state: Dict[str, Any]) -> Dict[str, str]:
    return classify_stop(state)
