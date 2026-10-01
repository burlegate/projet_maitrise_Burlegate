"""Inference MaskablePPO sur exports ; ni ordre fixe ni nouvelle requete Splunk."""
import argparse,json,time
from datetime import datetime,timezone
from pathlib import Path
import torch
from sb3_contrib import MaskablePPO
from gym_hunting_env_h3 import H3ReplayEnv
from hunting_policy_contract_h3 import ACTION_IDS
from ppo_h3_common import verify_metadata,runtime_metadata
from evidence_interpreter_h3 import sha


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--dossier',type=Path,default=Path(__file__).resolve().parent/'outputs')
    p.add_argument('--modele',type=Path,default=Path(__file__).resolve().parent/'models'/'ppo_h3.zip')
    args=p.parse_args()
    try:
        torch.set_num_threads(1)
        meta=json.loads(args.modele.with_suffix('.metadata.json').read_text(encoding='utf-8'))
        verify_metadata(meta)
        if sha(args.modele)!=meta['model_sha256']:raise ValueError('Empreinte du modele incoherente.')
        env=H3ReplayEnv(args.dossier)
        model=MaskablePPO.load(str(args.modele),env=env,device='cpu')
        obs,_=env.reset(seed=meta['seed']);total=0.;start=time.perf_counter()
        print('MASKABLEPPO EN REJEU : aucun appel Splunk, aucune evaluation independante.')
        for _ in range(7):
            mask=env.action_masks()
            action,_=model.predict(obs,action_masks=mask,deterministic=True)
            obs,reward,terminated,truncated,info=env.step(int(action));total+=reward
            row=env.trace[-1];row['selected_by']='maskableppo_predict'
            print(ACTION_IDS[int(action)],'| choix unique impose par masque' if row['forced_by_mask'] else '| choix PPO parmi plusieurs actions', '| reward :',reward)
            if terminated or truncated:break
        if not env.episode['terminated'] or env.episode['stop'] is None:raise ValueError('Episode sans cloture valide.')
        stop=env.episode['stop']
        stamp=datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S_%fZ')
        payload=dict(mode='maskableppo_replay',runtime=runtime_metadata(),model_sha256=sha(args.modele),
                     source_exports=env.provenance,
                     same_exports_as_training={a:v['sha256'] for a,v in env.provenance.items()}=={a:v['sha256'] for a,v in meta['training_exports'].items()},
                     trace=env.trace,stop=stop,total_reward=total,search_count=len(env.episode['attempted']),
                     local_replay_seconds=time.perf_counter()-start,
                     limitations=['Duree locale du rejeu, pas duree Splunk.','Aucune economie de recherches revendiquee.','R7 imposee lorsque seule autorisee.'])
        out=args.dossier/f'H3_ppo_replay_{stamp}.json'
        out.write_text(json.dumps(payload,ensure_ascii=False,indent=2),encoding='utf-8')
        print('Verdict :',stop['verdict'],'| motif :',stop['reason'])
        print('Recherches :',payload['search_count'],'| recompense totale :',total)
        print('Fichier :',out.resolve());env.close();return 0
    except (OSError,ValueError) as e:
        print('Erreur :',e);return 1

if __name__=='__main__':raise SystemExit(main())
