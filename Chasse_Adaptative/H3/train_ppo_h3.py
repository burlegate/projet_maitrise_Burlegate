"""Entrainement technique sur un cas H3 fixe ; aucune validation independante."""
import argparse,json
from datetime import datetime,timezone
from pathlib import Path
import torch
from sb3_contrib import MaskablePPO
from gym_hunting_env_h3 import H3ReplayEnv
from ppo_h3_common import runtime_metadata
from evidence_interpreter_h3 import sha


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--dossier',type=Path,default=Path(__file__).resolve().parent/'outputs')
    p.add_argument('--timesteps',type=int,default=4096)
    p.add_argument('--seed',type=int,default=42)
    p.add_argument('--sortie',type=Path,default=Path(__file__).resolve().parent/'models'/'ppo_h3')
    args=p.parse_args()
    if args.timesteps<128:p.error('--timesteps doit etre >= 128')
    try:
        torch.set_num_threads(1)
        env=H3ReplayEnv(args.dossier)
        print('ENTRAINEMENT TECHNIQUE SUR EXPORTS FIXES ; aucun appel Splunk.')
        print('Avec ce contrat, cinq recherches sont requises : aucun gain de recherches attendu.')
        model=MaskablePPO('MlpPolicy',env,n_steps=128,batch_size=64,n_epochs=5,
                          gamma=1.0,learning_rate=0.0003,ent_coef=0.01,
                          policy_kwargs=dict(net_arch=[32,32]),device='cpu',seed=args.seed,verbose=1)
        model.learn(total_timesteps=args.timesteps)
        base=args.sortie.with_suffix('');base.parent.mkdir(parents=True,exist_ok=True)
        model.save(str(base))
        meta=runtime_metadata()
        meta.update(created_at_utc=datetime.now(timezone.utc).isoformat(),seed=args.seed,
                    requested_timesteps=args.timesteps,actual_timesteps=model.num_timesteps,
                    training_mode='single_case_replay_integration',training_exports=env.provenance,
                    hyperparameters=dict(n_steps=128,batch_size=64,n_epochs=5,gamma=1.0,learning_rate=0.0003,ent_coef=0.01,net_arch=[32,32]),
                    reward='-1 par recherche, 0 pour R7 ; retour total -5 pour tout parcours complet valide.',
                    model_sha256=sha(base.with_suffix('.zip')),
                    limitations=['Aucune evaluation independante.','Aucune generalisation demontree.','Tous les ordres complets ont le meme retour ; cet apprentissage ne demontre pas un ordre optimal.'])
        base.with_suffix('.metadata.json').write_text(json.dumps(meta,ensure_ascii=False,indent=2),encoding='utf-8')
        print('Modele :',base.with_suffix('.zip').resolve())
        print('Ensuite : python .\\run_ppo_h3_replay.py --dossier .\\outputs')
        env.close();return 0
    except (OSError,ValueError) as e:
        print('Erreur :',e);return 1

if __name__=='__main__':raise SystemExit(main())
