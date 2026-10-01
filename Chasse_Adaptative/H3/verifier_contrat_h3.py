"""Rejeu technique d'un ordre explicite. Ne lance ni Splunk ni PPO."""
import argparse
import json
from datetime import datetime,timezone
from pathlib import Path
from evidence_interpreter_h3 import select_reports,sha
from hunting_policy_contract_h3 import *


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--dossier',type=Path,default=Path(__file__).resolve().parent/'outputs')
    p.add_argument('--ordre',nargs='+',default=['R1','R4','R2','R3','R5'])
    p.add_argument('--budget',type=int,default=5)
    args=p.parse_args()
    try:
        selected=select_reports(args.dossier)
        episode=new_episode(args.budget); trace=[]
        print('REJEU TECHNIQUE : ordre fourni, aucune decision PPO.')
        for action in args.ordre:
            if valid_action_mask(episode)[-1]:break
            if action not in RESEARCH:raise ValueError('L ordre contient seulement R1 a R5.')
            if action not in selected:raise ValueError('Export compatible manquant : '+action)
            path,report=selected[action]
            before=observation_values(episode)
            mask=valid_action_mask(episode)
            apply_action(episode,action,report)
            trace.append(dict(action=action,selected_by='ordre_fourni',observation_before=before,
                              mask_before=mask,observation_after=observation_values(episode),
                              source_file=str(path.resolve()),sha256=sha(path)))
            allowed=[x for x,b in zip(ACTION_IDS,valid_action_mask(episode)) if b]
            print(action,'-> actions autorisees :',', '.join(allowed))
        if valid_action_mask(episode)[-1]:
            apply_action(episode,'R7')
            print('R7 ->',episode['stop']['reason'],'|',episode['stop']['verdict'])
        else:print('Sequence terminee ; investigation encore ouverte.')
        stamp=datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S_%fZ')
        out=args.dossier/f'H3_contract_replay_{stamp}.json'
        evidence=episode['evidence']; evidence.pop('_reports',None)
        payload=dict(mode='rejeu_technique_sans_ppo',feature_names=OBSERVATION_FEATURES,
                     episode=episode,trace=trace,contract_sha256=sha(Path(__file__).with_name('hunting_policy_contract_h3.py')))
        out.write_text(json.dumps(payload,ensure_ascii=False,indent=2),encoding='utf-8')
        print('Fichier :',out.resolve())
        return 0
    except (ValueError,OSError,KeyError) as e:
        print('Erreur :',e);return 1

if __name__=='__main__':raise SystemExit(main())
