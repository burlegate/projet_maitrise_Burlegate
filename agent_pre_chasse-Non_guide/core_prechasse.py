from __future__ import annotations
import argparse,json,os,sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from openai import OpenAI
BASE_DIR=Path(__file__).resolve().parent
RESULTS_DIR=BASE_DIR/'resultats'; PROMPTS_DIR=BASE_DIR/'prompts'; SCHEMA_PATH=BASE_DIR/'schema_sortie.json'; DEFAULT_CSV=BASE_DIR/'data'/'dns_sample_20.csv'
MODEL=os.getenv('OPENAI_MODEL','gpt-5.4-mini')

def parse_args(description:str)->argparse.Namespace:
    p=argparse.ArgumentParser(description=description)
    p.add_argument('--csv',type=Path,default=DEFAULT_CSV,help='Chemin du CSV DNS à analyser.')
    p.add_argument('--raisonnement',choices=['low','medium','high'],default='medium',help='Effort de raisonnement du modèle.')
    p.add_argument('--max-output-tokens',type=int,default=16000,help='Taille maximale de la sortie.')
    return p.parse_args()

def load_json(path:Path)->dict[str,Any]: return json.loads(path.read_text(encoding='utf-8'))

def validate(csv_path:Path)->None:
    if not os.getenv('OPENAI_API_KEY'): raise RuntimeError("OPENAI_API_KEY n'est pas définie dans ce terminal.")
    if not csv_path.exists(): raise RuntimeError(f'CSV introuvable : {csv_path}')
    if csv_path.suffix.lower()!='.csv': raise RuntimeError('Le fichier doit être un .csv')

def save_debug_files(mode:str,timestamp:str,response:Any,output_text:str)->tuple[Path,Path]:
    RESULTS_DIR.mkdir(exist_ok=True)
    raw_txt=RESULTS_DIR/f'debug_output_text_{mode}_{timestamp}.txt'
    raw_json=RESULTS_DIR/f'debug_response_object_{mode}_{timestamp}.json'
    raw_txt.write_text(output_text or '',encoding='utf-8')
    try: response_json=response.model_dump_json(indent=2)
    except Exception:
        try: response_json=json.dumps(response,default=str,ensure_ascii=False,indent=2)
        except Exception as e: response_json=f'Impossible de sérialiser la réponse brute: {e}'
    raw_json.write_text(response_json,encoding='utf-8')
    return raw_txt,raw_json

def run_prechasse(mode:str,csv_path:Path,reasoning_effort:str='medium',max_output_tokens:int=16000)->Path:
    RESULTS_DIR.mkdir(exist_ok=True); validate(csv_path)
    schema=load_json(SCHEMA_PATH); prompt=(PROMPTS_DIR/f'{mode}.txt').read_text(encoding='utf-8')
    client=OpenAI()
    print(f'Mode : {mode}'); print(f'Modèle : {MODEL}'); print(f'Raisonnement : {reasoning_effort}'); print(f'Max output tokens : {max_output_tokens}'); print(f'CSV : {csv_path.resolve()}'); print('Téléversement du CSV vers OpenAI...')
    with csv_path.open('rb') as f: uploaded=client.files.create(file=f,purpose='user_data')
    try:
        response=client.responses.create(
            model=MODEL, reasoning={'effort':reasoning_effort}, instructions=prompt,
            tools=[{'type':'code_interpreter','container':{'type':'auto','memory_limit':'4g','file_ids':[uploaded.id]}}],
            input=(f'Analyse le fichier CSV DNS nommé {csv_path.name}. Utilise ton outil Python interne pour l’ouvrir et l’examiner. Suis la boucle légère de pré-chasse décrite dans les instructions. Retourne uniquement le rapport JSON structuré.'),
            text={'format':{'type':'json_schema','name':'rapport_pre_chasse_dns','schema':schema,'strict':True}},
            max_output_tokens=max_output_tokens, store=False)
        timestamp=datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')
        output_text=getattr(response,'output_text','') or ''
        debug_txt,debug_json=save_debug_files(mode,timestamp,response,output_text)
        if not output_text.strip():
            raise RuntimeError(f'La réponse finale JSON est vide. Fichiers de debug créés : {debug_txt} et {debug_json}')
        try: report=json.loads(output_text)
        except json.JSONDecodeError as e:
            raise RuntimeError(f"La réponse finale n'est pas un JSON valide. Erreur JSON : {e}. Fichiers de debug créés : {debug_txt} et {debug_json}") from e
        out=RESULTS_DIR/f'prechasse_{mode}_{timestamp}.json'
        envelope={'metadata':{'date_utc':datetime.now(timezone.utc).isoformat(),'mode':mode,'model':MODEL,'reasoning_effort':reasoning_effort,'max_output_tokens':max_output_tokens,'csv':str(csv_path.resolve()),'csv_name':csv_path.name,'response_id':response.id,'debug_output_text':str(debug_txt),'debug_response_object':str(debug_json),'note':'Le script local téléverse le CSV, appelle OpenAI et sauvegarde le résultat. L’analyse est réalisée par le LLM avec son outil Python interne.'},'rapport':report}
        out.write_text(json.dumps(envelope,ensure_ascii=False,indent=2),encoding='utf-8')
        print(f'Rapport sauvegardé : {out}'); print(f'Debug sauvegardé : {debug_txt}'); print(f'Debug sauvegardé : {debug_json}')
        return out
    finally:
        try: client.files.delete(uploaded.id); print('Fichier téléversé supprimé d’OpenAI.')
        except Exception as e: print(f'Avertissement : suppression automatique impossible : {e}',file=sys.stderr)
