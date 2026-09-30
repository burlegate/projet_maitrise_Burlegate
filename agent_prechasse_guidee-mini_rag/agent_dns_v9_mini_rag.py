from __future__ import annotations

import argparse
import json
import os
import random
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from openai import APIConnectionError, APITimeoutError, InternalServerError, OpenAI, RateLimitError

BASE_DIR = Path(__file__).resolve().parent
RESULTS_DIR = BASE_DIR / "resultats"
PROMPT_PATH = BASE_DIR / "prompts" / "agent_dns_v9_mini_rag.txt"
DEFAULT_KNOWLEDGE_PATH = BASE_DIR / "knowledge" / "guide_dns_threat_hunting_general.txt"
SCHEMA_PATH = BASE_DIR / "schema_sortie_v9.json"
DEFAULT_CSV = BASE_DIR / "data" / "dns_sample_20.csv"

MODEL = os.getenv("OPENAI_MODEL", "gpt-5.4-mini")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Agent DNS V9 — pré-chasse avec mini-RAG DNS général")
    parser.add_argument("--csv", type=Path, default=DEFAULT_CSV, help="Chemin du CSV DNS complet à analyser.")
    parser.add_argument("--knowledge", type=Path, default=DEFAULT_KNOWLEDGE_PATH, help="Chemin du guide DNS général mini-RAG.")
    parser.add_argument("--raisonnement", choices=["low", "medium", "high"], default="medium", help="Effort de raisonnement du modèle.")
    parser.add_argument("--max-output-tokens", type=int, default=16000, help="Taille maximale de la sortie.")
    parser.add_argument("--retries", type=int, default=3, help="Nombre de tentatives en cas de 429/500/timeout.")
    parser.add_argument("--retry-base-wait", type=int, default=60, help="Attente initiale en secondes entre les tentatives.")
    return parser.parse_args()


def validate(csv_path: Path, knowledge_path: Path) -> None:
    if not os.getenv("OPENAI_API_KEY"):
        raise RuntimeError("OPENAI_API_KEY n'est pas définie dans ce terminal.")
    if not csv_path.exists():
        raise RuntimeError(f"CSV introuvable : {csv_path}")
    if csv_path.suffix.lower() != ".csv":
        raise RuntimeError("Le fichier de données doit être un .csv")
    if not knowledge_path.exists():
        raise RuntimeError(f"Guide mini-RAG introuvable : {knowledge_path}")


def with_retries(func: Callable[[], Any], retries: int, base_wait: int) -> Any:
    last_error: Exception | None = None
    for attempt in range(1, retries + 1):
        try:
            return func()
        except (RateLimitError, InternalServerError, APITimeoutError, APIConnectionError) as e:
            last_error = e
            if attempt == retries:
                break
            wait = base_wait * (2 ** (attempt - 1)) + random.uniform(0, 5)
            print(f"Tentative {attempt}/{retries} échouée ({type(e).__name__}). Nouvelle tentative dans {wait:.1f} secondes...")
            time.sleep(wait)
    raise last_error if last_error else RuntimeError("Échec inconnu pendant l'appel API.")


def save_debug_files(timestamp: str, response: Any, output_text: str) -> tuple[Path, Path]:
    RESULTS_DIR.mkdir(exist_ok=True)
    raw_txt = RESULTS_DIR / f"debug_output_text_v9_{timestamp}.txt"
    raw_json = RESULTS_DIR / f"debug_response_object_v9_{timestamp}.json"

    raw_txt.write_text(output_text or "", encoding="utf-8")

    try:
        response_json = response.model_dump_json(indent=2)
    except Exception:
        response_json = json.dumps(response, default=str, ensure_ascii=False, indent=2)

    raw_json.write_text(response_json, encoding="utf-8")
    return raw_txt, raw_json


def run_agent_dns_v9(
    csv_path: Path,
    knowledge_path: Path,
    reasoning_effort: str = "medium",
    max_output_tokens: int = 16000,
    retries: int = 3,
    retry_base_wait: int = 60,
) -> Path:
    RESULTS_DIR.mkdir(exist_ok=True)
    validate(csv_path, knowledge_path)

    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    prompt = PROMPT_PATH.read_text(encoding="utf-8")
    knowledge = knowledge_path.read_text(encoding="utf-8")

    instructions = (
        prompt
        + "\n\n===== MINI-RAG DNS GÉNÉRAL À UTILISER COMME CONNAISSANCE DE DOMAINE =====\n"
        + knowledge
        + "\n===== FIN DU MINI-RAG DNS GÉNÉRAL =====\n"
    )

    client = OpenAI()

    print("Mode : dns_autonome_mini_rag")
    print("Version : v9_dns_mini_rag")
    print(f"Modèle : {MODEL}")
    print(f"Raisonnement : {reasoning_effort}")
    print(f"Max output tokens : {max_output_tokens}")
    print(f"CSV : {csv_path.resolve()}")
    print(f"Mini-RAG : {knowledge_path.resolve()}")
    print("Téléversement du CSV vers OpenAI...")

    with csv_path.open("rb") as f:
        uploaded = client.files.create(file=f, purpose="user_data")

    try:
        def api_call() -> Any:
            return client.responses.create(
                model=MODEL,
                reasoning={"effort": reasoning_effort},
                instructions=instructions,
                tools=[
                    {
                        "type": "code_interpreter",
                        "container": {
                            "type": "auto",
                            "memory_limit": "4g",
                            "file_ids": [uploaded.id],
                        },
                    }
                ],
                input=(
                    f"Analyse le fichier CSV DNS complet nommé {csv_path.name}. "
                    "Utilise le mini-RAG DNS général seulement comme connaissance de domaine générale. "
                    "Reste en pré-chasse DNS. Produis uniquement des hypothèses candidates DNS, "
                    "sans plan, sans requête SPL, sans pivot, sans confirmation, sans réfutation."
                ),
                text={
                    "format": {
                        "type": "json_schema",
                        "name": "rapport_pre_chasse_dns_v9_mini_rag",
                        "schema": schema,
                        "strict": True,
                    }
                },
                max_output_tokens=max_output_tokens,
                store=False,
            )

        response = with_retries(api_call, retries=retries, base_wait=retry_base_wait)

        timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        output_text = getattr(response, "output_text", "") or ""

        if not output_text.strip():
            debug_txt, debug_json = save_debug_files(timestamp, response, output_text)
            raise RuntimeError(
                "La réponse finale JSON est vide. "
                f"Fichiers de debug créés : {debug_txt} et {debug_json}"
            )

        try:
            report = json.loads(output_text)
        except json.JSONDecodeError as e:
            debug_txt, debug_json = save_debug_files(timestamp, response, output_text)
            raise RuntimeError(
                "La réponse finale n'est pas un JSON valide. "
                f"Erreur JSON : {e}. "
                f"Fichiers de debug créés : {debug_txt} et {debug_json}"
            ) from e

        out = RESULTS_DIR / f"prechasse_v9_dns_mini_rag_{timestamp}.json"
        envelope = {
            "metadata": {
                "date_utc": datetime.now(timezone.utc).isoformat(),
                "mode": "dns_autonome_mini_rag",
                "version_agent": "v9_dns_mini_rag",
                "model": MODEL,
                "reasoning_effort": reasoning_effort,
                "max_output_tokens": max_output_tokens,
                "csv": str(csv_path.resolve()),
                "csv_name": csv_path.name,
                "knowledge_file": str(knowledge_path.resolve()),
                "response_id": response.id,
                "note": (
                    "Pré-chasse DNS uniquement: CSV complet + mini-RAG DNS général. "
                    "Pas de CSV partiel, pas de SPL, pas de plan, pas de pivot, pas de confirmation/refutation."
                ),
            },
            "rapport": report,
        }
        out.write_text(json.dumps(envelope, ensure_ascii=False, indent=2), encoding="utf-8")
        print(f"Rapport sauvegardé : {out}")
        return out

    finally:
        try:
            client.files.delete(uploaded.id)
            print("Fichier téléversé supprimé d'OpenAI.")
        except Exception as e:
            print(f"Avertissement : suppression automatique impossible : {e}", file=sys.stderr)


if __name__ == "__main__":
    args = parse_args()
    run_agent_dns_v9(
        args.csv.expanduser().resolve(),
        args.knowledge.expanduser().resolve(),
        args.raisonnement,
        args.max_output_tokens,
        args.retries,
        args.retry_base_wait,
    )
