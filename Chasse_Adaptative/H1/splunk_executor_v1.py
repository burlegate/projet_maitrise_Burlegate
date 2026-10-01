"""
splunk_executor_v1.py
---------------------
Exécute un template SPL contrôlé dans Splunk via le REST endpoint search/jobs/export.

Ce script ne génère pas de SPL libre.
Il appelle spl_templates_controlled.py pour obtenir une requête contrôlée.

Exemples PowerShell:

1) Voir la requête sans se connecter à Splunk:
   py splunk_executor_v1.py --template dns_lookup --dry-run

2) Exécuter A1 DNS sur Splunk local:
   $env:SPLUNK_USERNAME="burlegate"
   $env:SPLUNK_PASSWORD="TON_MOT_DE_PASSE"
   py splunk_executor_v1.py --template dns_lookup --host localhost --port 8089 --verify-ssl false

3) Tester une autre action:
   py splunk_executor_v1.py --template cisco_nvm_flow_lookup --host localhost --port 8089 --verify-ssl false
"""

from __future__ import annotations

import argparse
import base64
import getpass
import json
import os
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

from spl_templates_controlled import (
    TEMPLATE_DESCRIPTIONS,
    TemplateError,
    build_spl,
    normalize_limit,
    normalize_template_id,
)

TEMPLATE_RESULT_UNITS = {
    "dns_lookup": "ligne(s) de résultat DNS",
    "http_context_lookup": "ligne(s) de résultat HTTP",
    "cisco_nvm_flow_lookup": "ligne(s) de flux réseau Cisco NVM",
    "sysmon_process_lookup": "ligne(s) de résultat Sysmon",
    "windows_security_lookup": "ligne(s) de résultat Windows Security",
    "symantec_alert_lookup": "ligne(s) de résultat Symantec",
}


def str_to_bool(value: Any) -> bool:
    text = str(value).strip().lower()
    if text in {"1", "true", "yes", "y", "oui"}:
        return True
    if text in {"0", "false", "no", "n", "non"}:
        return False
    raise argparse.ArgumentTypeError("Valeur booléenne attendue: true/false")


def parse_csv_or_list(values: Optional[Iterable[str]]) -> Optional[List[str]]:
    if not values:
        return None
    output: List[str] = []
    for value in values:
        for part in str(value).split(","):
            part = part.strip()
            if part:
                output.append(part)
    return output or None


def is_preview_payload(payload: Dict[str, Any]) -> bool:
    """Indique si une ligne JSON de l'export Splunk est un résultat provisoire."""
    preview = payload.get("preview", False)
    if isinstance(preview, str):
        return preview.strip().lower() in {"1", "true", "yes"}
    return preview is True or preview == 1


def run_splunk_export(
    spl: str,
    host: str,
    port: int,
    username: str,
    password: str,
    scheme: str = "https",
    verify_ssl: bool = False,
    timeout: int = 180,
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    """Exécute une recherche Splunk et retourne (results, messages)."""
    url = f"{scheme}://{host}:{port}/services/search/jobs/export"

    form = urllib.parse.urlencode(
        {
            "search": spl,
            "output_mode": "json",
        }
    ).encode("utf-8")

    request = urllib.request.Request(url, data=form, method="POST")
    token = base64.b64encode(f"{username}:{password}".encode("utf-8")).decode("ascii")
    request.add_header("Authorization", f"Basic {token}")
    request.add_header("Content-Type", "application/x-www-form-urlencoded")

    context = None
    if scheme.lower() == "https":
        if verify_ssl:
            context = ssl.create_default_context()
        else:
            # Pratique pour un labo Splunk local avec certificat auto-signé.
            context = ssl._create_unverified_context()  # noqa: SLF001

    results: List[Dict[str, Any]] = []
    messages: List[Dict[str, Any]] = []

    try:
        with urllib.request.urlopen(request, timeout=timeout, context=context) as response:
            for raw_line in response:
                line = raw_line.decode("utf-8", errors="replace").strip()
                if not line:
                    continue
                try:
                    payload = json.loads(line)
                except json.JSONDecodeError:
                    messages.append({"type": "non_json_line", "text": line})
                    continue

                # search/jobs/export peut transmettre un jeu d'aperçu, puis le
                # jeu final. Ne conserver que les résultats finaux évite de
                # compter deux fois les mêmes événements.
                if is_preview_payload(payload):
                    continue

                if "result" in payload and isinstance(payload["result"], dict):
                    results.append(payload["result"])
                else:
                    messages.append(payload)
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"Erreur HTTP Splunk {exc.code}: {body}") from exc
    except urllib.error.URLError as exc:
        raise RuntimeError(f"Impossible de joindre Splunk: {exc}") from exc

    return results, messages


def save_json(path: Path, data: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)


def build_overrides(args: argparse.Namespace) -> Dict[str, Any]:
    overrides: Dict[str, Any] = {
        "index": args.index,
        "earliest": args.earliest,
        "latest": args.latest,
        "limit": args.limit,
        "domains": parse_csv_or_list(args.domains),
        "src_ips": parse_csv_or_list(args.src_ips),
        "dest_ips": parse_csv_or_list(args.dest_ips),
        "hosts": parse_csv_or_list(args.hosts_filter),
        "users": parse_csv_or_list(args.users),
        "process_names": parse_csv_or_list(args.process_names),
    }
    return {k: v for k, v in overrides.items() if v is not None}


def make_default_output_path(template_id: str) -> Path:
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    return Path("outputs") / f"splunk_{template_id}_{ts}.json"


def main() -> int:
    parser = argparse.ArgumentParser(description="Exécuter un template SPL contrôlé pour H1 dans Splunk.")
    parser.add_argument(
        "--template",
        default="dns_lookup",
        help="Template ou action: A1, A2, A3, A4, A5, A6, dns_lookup, cisco_nvm_flow_lookup, etc.",
    )
    parser.add_argument("--index", default="botsv3")
    parser.add_argument("--earliest", default="0")
    parser.add_argument("--latest", default="now")
    parser.add_argument("--limit", type=int, default=200)

    parser.add_argument("--domains", nargs="*", help="Domaines, séparés par espace ou virgule.")
    parser.add_argument("--src-ips", nargs="*", help="IP sources, séparées par espace ou virgule.")
    parser.add_argument("--dest-ips", nargs="*", help="IP destinations, séparées par espace ou virgule.")
    parser.add_argument("--hosts-filter", nargs="*", help="Noms de machines à ajouter comme filtre.")
    parser.add_argument("--users", nargs="*", help="Utilisateurs à ajouter comme filtre.")
    parser.add_argument("--process-names", nargs="*", help="Processus à ajouter comme filtre, ex. chrome.exe.")

    parser.add_argument("--host", default=os.getenv("SPLUNK_HOST", "localhost"))
    parser.add_argument("--port", type=int, default=int(os.getenv("SPLUNK_PORT", "8089")))
    parser.add_argument("--scheme", choices=["https", "http"], default=os.getenv("SPLUNK_SCHEME", "https"))
    parser.add_argument("--username", default=os.getenv("SPLUNK_USERNAME", "burlegate"))
    parser.add_argument("--password", default=os.getenv("SPLUNK_PASSWORD"))
    parser.add_argument("--verify-ssl", type=str_to_bool, default=False)
    parser.add_argument("--timeout", type=int, default=180)
    parser.add_argument("--dry-run", action="store_true", help="Afficher la requête SPL sans exécuter Splunk.")
    parser.add_argument("--out", default=None, help="Chemin du fichier JSON de sortie.")
    parser.add_argument("--list-templates", action="store_true", help="Afficher les templates disponibles.")

    args = parser.parse_args()
    args.limit = normalize_limit(args.limit)

    if args.port < 1 or args.port > 65535:
        parser.error("--port doit être compris entre 1 et 65535.")
    if args.timeout < 1:
        parser.error("--timeout doit être supérieur ou égal à 1.")

    if args.list_templates:
        print("Templates disponibles:")
        for template_id, description in TEMPLATE_DESCRIPTIONS.items():
            print(f"- {template_id}: {description}")
        return 0

    try:
        template_id = normalize_template_id(args.template)
        overrides = build_overrides(args)
        spl = build_spl(template_id, overrides)
    except TemplateError as exc:
        print(f"ERREUR template: {exc}", file=sys.stderr)
        return 2

    print("=" * 80)
    print(f"Template: {template_id}")
    print("SPL contrôlé:")
    print("-" * 80)
    print(spl)
    print("=" * 80)

    if args.dry_run:
        print("Mode dry-run: aucune connexion Splunk effectuée.")
        return 0

    password = args.password
    if not password:
        password = getpass.getpass(f"Mot de passe Splunk pour {args.username}: ")

    print(f"Connexion Splunk: {args.scheme}://{args.host}:{args.port}")
    results, messages = run_splunk_export(
        spl=spl,
        host=args.host,
        port=args.port,
        username=args.username,
        password=password,
        scheme=args.scheme,
        verify_ssl=args.verify_ssl,
        timeout=args.timeout,
    )

    result_unit = TEMPLATE_RESULT_UNITS.get(template_id, "ligne(s) de résultat Splunk")
    query_limit_reached = len(results) >= args.limit

    output_data: Dict[str, Any] = {
        "created_at_utc": datetime.now(timezone.utc).isoformat(),
        "template_id": template_id,
        "splunk": {
            "scheme": args.scheme,
            "host": args.host,
            "port": args.port,
            "username": args.username,
            "verify_ssl": args.verify_ssl,
        },
        "params": {k: v for k, v in overrides.items() if k != "password"},
        "spl": spl,
        "result_count": len(results),
        "result_unit": result_unit,
        "query_limit": args.limit,
        "query_limit_reached": query_limit_reached,
        "message_count": len(messages),
        "messages": messages,
        "results": results,
    }

    out_path = Path(args.out) if args.out else make_default_output_path(template_id)
    save_json(out_path, output_data)

    print(f"Lignes Splunk retournées: {len(results)} {result_unit}")
    print(f"Limite de la requête: {args.limit} lignes")
    if query_limit_reached:
        print("Limite potentiellement atteinte: oui — le total réel peut être supérieur")
    else:
        print("Limite potentiellement atteinte: non")
    print(f"Messages Splunk: {len(messages)}")
    print(f"Fichier sauvegardé: {out_path}")

    # Affiche quelques résultats pour vérification rapide.
    for i, result in enumerate(results[:3], start=1):
        print(f"\n--- Résultat {i} ---")
        for key in ["_time", "host", "sourcetype", "source", "query", "src_ip", "src", "dest_ip", "dest", "sa", "da", "dh", "pn", "ppn", "pa", "sysmon_event_id", "UtcTime", "Image", "ParentImage", "CommandLine", "User", "ProcessId", "ParentProcessId", "signature"]:
            if key in result and result[key] not in (None, ""):
                print(f"{key}: {result[key]}")
        if "_raw" in result:
            raw = str(result["_raw"])
            print("_raw:", raw[:500].replace("\n", " "))

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
