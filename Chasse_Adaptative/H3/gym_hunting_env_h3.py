"""Environnement H3 en rejeu des exports, sans appels Splunk/OpenAI."""
from copy import deepcopy
import gymnasium as gym
from gymnasium import spaces
import numpy as np
from evidence_interpreter_h3 import select_reports, sha, execution_status
from hunting_policy_contract_h3 import (
    ACTION_IDS, RESEARCH, OBSERVATION_FEATURES, new_episode,
    valid_action_mask, observation_values, apply_action,
)

REWARD_VERSION='H3-integration-cost-v1'


class H3ReplayEnv(gym.Env):
    metadata={'render_modes':[]}

    def __init__(self, dossier=None, *, reports=None):
        super().__init__()
        self.provenance={}
        if reports is None:
            selected=select_reports(dossier)
            reports={a:r for a,(_,r) in selected.items() if a in RESEARCH}
            self.provenance={a:dict(path=str(p.resolve()),sha256=sha(p)) for a,(p,r) in selected.items() if a in RESEARCH}
        self._reports=deepcopy(reports)
        for a in RESEARCH:
            if a not in self._reports or self._reports[a].get('action')!=a:
                raise ValueError('Export compatible manquant ou incoherent : '+a)
            if execution_status(self._reports[a])[0] not in ('ok','empty'):
                raise ValueError('Corriger l export non exploitable avant entrainement : '+a)
        self.action_space=spaces.Discrete(len(ACTION_IDS))
        self.observation_space=spaces.Box(0.,1.,shape=(len(OBSERVATION_FEATURES),),dtype=np.float32)
        self._cache={}
        self.episode=new_episode()
        self.trace=[]

    def _observation(self):
        return np.asarray(observation_values(self.episode),dtype=np.float32)

    def action_masks(self):
        return np.asarray(valid_action_mask(self.episode),dtype=bool)

    def reset(self,*,seed=None,options=None):
        super().reset(seed=seed)
        self.episode=new_episode()
        self.trace=[]
        return self._observation(),{'mode':'rejeu_exports'}

    def step(self,action):
        if self.episode['terminated']:
            raise RuntimeError('Episode termine : appeler reset().')
        if not self.action_space.contains(action):
            raise ValueError('Indice action invalide.')
        index=int(action);action_id=ACTION_IDS[index]
        before=self._observation();mask=self.action_masks()
        if not mask[index]:
            # Gym check_env peut ignorer le masque. Echec explicite et borne.
            self.episode['terminated']=True
            info={'invalid_action':action_id,'mode':'rejeu_exports'}
            self.trace.append(dict(action=action_id,valid=False,reward=-10.))
            return before,-10.,True,False,info
        if action_id=='R7':
            apply_action(self.episode,action_id)
            reward=0.
        else:
            key=frozenset(self.episode['attempted']+[action_id])
            if key in self._cache:
                self.episode['attempted'].append(action_id)
                self.episode['evidence']=deepcopy(self._cache[key])
                self.episode['evidence']['_reports']={a:self._reports[a] for a in self.episode['attempted']}
            else:
                apply_action(self.episode,action_id,self._reports[action_id])
                evidence={k:v for k,v in self.episode['evidence'].items() if k!='_reports'}
                self._cache[key]=deepcopy(evidence)
            reward=-1.  # Cout unitaire, aucun bonus de benignite ou d'alerte.
        terminal=self.episode['terminated']
        after=self._observation()
        info={'mode':'rejeu_exports','action_id':action_id}
        if terminal:info['stop']=deepcopy(self.episode['stop'])
        self.trace.append(dict(action=action_id,valid=True,observation_before=before.tolist(),
                               action_mask_before=mask.tolist(),observation_after=after.tolist(),
                               reward=reward,forced_by_mask=int(mask.sum())==1))
        return after,reward,terminal,False,info
