import unittest
from hunting_policy_contract_h3 import *


def report(a,rows=None):
    if rows is None:rows=[{'h3_src_ip':'192.0.2.1','h3_query':'A'*32,'h3_src_port':'137','h3_dest_port':'137','h3_transport':'udp'}] if a=='R1' else []
    return dict(action=a,status='ok' if rows else 'empty',results=rows,result_count=len(rows))

class ContractTests(unittest.TestCase):
    def test_initial_no_future_evidence(self):
        e=new_episode();self.assertEqual(observation_values(e),[0.]*26)
        self.assertEqual(valid_action_mask(e),[True,False,False,False,False,False,False])
    def test_repetition_and_r6(self):
        e=new_episode();apply_action(e,'R1',report('R1'))
        self.assertEqual(valid_action_mask(e),[False,True,True,True,True,False,False])
        with self.assertRaises(ValueError):apply_action(e,'R1',report('R1'))
    def test_budget_is_not_evidence(self):
        e=new_episode(2)
        for a in ('R1','R4'):apply_action(e,a,report(a))
        apply_action(e,'R7')
        self.assertEqual(e['stop']['verdict'],'investigation_incomplete')
        self.assertEqual(e['stop']['reason'],'budget_epuise')
    def test_full(self):
        e=new_episode()
        for a in ('R1','R5','R3','R2','R4'):apply_action(e,a,report(a))
        apply_action(e,'R7')
        self.assertEqual(e['stop']['reason'],'catalogue_termine')
        self.assertFalse(any(valid_action_mask(e)))
    def test_empty_root(self):
        e=new_episode();apply_action(e,'R1',report('R1',[]));apply_action(e,'R7')
        self.assertEqual(e['stop']['verdict'],'signal_non_retrouve')
    def test_failed_root(self):
        e=new_episode();r=report('R1');r['error']='timeout'
        apply_action(e,'R1',r);apply_action(e,'R7')
        self.assertEqual(e['stop']['reason'],'echec_technique_R1')
    def test_wrong_export(self):
        e=new_episode()
        with self.assertRaises(ValueError):apply_action(e,'R1',report('R2'))
        self.assertEqual(e['attempted'],[])

if __name__=='__main__':unittest.main()
