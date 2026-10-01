"""Contrat H3 v1 : observations partielles et autorisations, sans politique PPO."""
import math
from evidence_interpreter_h3 import initial_state, update_state, final_verdict

VERSION = 'H3-contract-1.0'
ACTION_IDS = ('R1','R2','R3','R4','R5','R6','R7')
RESEARCH = ACTION_IDS[:5]
OBSERVATION_FEATURES = tuple(f'{a}_{f}' for a in RESEARCH for f in ('attempted','usable','empty','rows_log')) + (
    'netbios_compatible','r2_process_context','r3_process_context',
    'r4_tuple_match','r5_context_alert','budget_fraction')


def new_episode(max_searches=5):
    if not isinstance(max_searches,int) or not 1 <= max_searches <= 5:
        raise ValueError('Le budget doit etre un entier de 1 a 5 recherches.')
    return dict(contract_version=VERSION,evidence=initial_state(),attempted=[],
                max_searches=max_searches,terminated=False,stop=None)


def stop_assessment(episode):
    a=episode['evidence']['analyses']
    base=final_verdict(episode['evidence'])
    attempted=episode['attempted']
    failed=[x for x in attempted if not a.get(x,{}).get('usable')]
    complete=all(a.get(x,{}).get('usable') for x in RESEARCH)
    r1=a.get('R1',{})
    if complete:
        reason='catalogue_termine'; verdict='non_concluant'
    elif 'R1' in attempted and not r1.get('usable'):
        reason='echec_technique_R1'; verdict='investigation_incomplete'
    elif r1.get('usable') and not r1.get('row_count'):
        reason='aucune_cible_R1'; verdict='signal_non_retrouve'
    elif r1.get('usable') and not r1.get('source_ips'):
        reason='cibles_R1_absentes'; verdict='investigation_incomplete'
    elif len(attempted)>=episode['max_searches']:
        reason='budget_epuise'; verdict='investigation_incomplete'
    else:
        reason='poursuivre'; verdict='investigation_incomplete'
    return dict(authorized=reason!='poursuivre',reason=reason,verdict=verdict,
                phenomenon=base['phenomenon'],failed_actions=failed,
                unexecuted_actions=[x for x in RESEARCH if x not in attempted],
                campaign_stop=False,
                explanation='Aucune preuve de legitimite ou de malveillance deduite du seul arret.')


def valid_action_mask(episode):
    if episode['terminated']:
        return [False]*len(ACTION_IDS)
    stop=stop_assessment(episode)
    if stop['authorized']:
        return [False]*6+[True]
    a=episode['evidence']['analyses']
    root=a.get('R1',{})
    targets=bool(root.get('usable') and root.get('row_count') and root.get('source_ips'))
    return [x not in episode['attempted'] and (x=='R1' or targets) for x in RESEARCH]+[False,False]


def observation_values(episode):
    a=episode['evidence']['analyses']; out=[]
    for action in RESEARCH:
        entry=a.get(action,{})
        usable=bool(entry.get('usable'))
        out.extend([float(action in episode['attempted']),float(usable),
                    float(usable and entry.get('row_count')==0),
                    min(1.,math.log1p(max(0,entry.get('row_count',0)))/math.log1p(100000))])
    out.extend([float(bool(a.get('R1',{}).get('netbios_encoding_consistent'))),
                float(bool(a.get('R2',{}).get('process_context_rows'))),
                float(bool(a.get('R3',{}).get('process_context_rows'))),
                float(bool(a.get('R4',{}).get('dns_tuple_match_count'))),
                float(bool(a.get('R5',{}).get('alerts'))),
                len(episode['attempted'])/episode['max_searches']])
    assert len(out)==len(OBSERVATION_FEATURES)
    return out


def apply_action(episode,action,report=None):
    if action not in ACTION_IDS or not valid_action_mask(episode)[ACTION_IDS.index(action)]:
        raise ValueError(f'Action interdite : {action}')
    if action=='R7':
        result=stop_assessment(episode)
        episode.update(terminated=True,stop=result)
    else:
        if not isinstance(report,dict) or report.get('action')!=action:
            raise ValueError('Export absent ou identifiant action incoherent.')
        update_state(episode['evidence'],action,report)
        episode['attempted'].append(action)
    return episode
