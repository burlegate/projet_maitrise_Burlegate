import importlib.metadata
from pathlib import Path
from evidence_interpreter_h3 import sha
from hunting_policy_contract_h3 import VERSION,ACTION_IDS,OBSERVATION_FEATURES
from gym_hunting_env_h3 import REWARD_VERSION


def runtime_metadata():
    return dict(contract_version=VERSION,action_ids=list(ACTION_IDS),features=list(OBSERVATION_FEATURES),
                reward_version=REWARD_VERSION,
                packages={x:importlib.metadata.version(x) for x in ('numpy','torch','gymnasium','stable-baselines3','sb3-contrib')},
                code_sha256={x:sha(Path(__file__).with_name(x)) for x in (
                    'evidence_interpreter_h3.py','hunting_policy_contract_h3.py','gym_hunting_env_h3.py')})


def verify_metadata(metadata):
    current=runtime_metadata()
    for key in ('contract_version','action_ids','features','reward_version','code_sha256'):
        if metadata.get(key)!=current[key]:
            raise ValueError('Modele incompatible avec les scripts : '+key+'. Reentrainer le modele H3.')
