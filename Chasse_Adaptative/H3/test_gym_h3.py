import unittest
import numpy as np
from gym_hunting_env_h3 import H3ReplayEnv
from hunting_policy_contract_h3 import ACTION_IDS


def reports():
    root=[dict(h3_src_ip='192.0.2.1',h3_query='A'*32,h3_src_port='137',h3_dest_port='137',h3_transport='udp')]
    return {a:dict(action=a,status='ok' if a=='R1' else 'empty',results=root if a=='R1' else [],result_count=1 if a=='R1' else 0) for a in ACTION_IDS[:5]}

class EnvTests(unittest.TestCase):
    def test_reset_and_future_hidden(self):
        e=H3ReplayEnv(reports=reports());o,_=e.reset()
        self.assertTrue(np.all(o==0));self.assertEqual(e.action_masks().tolist(),[True]+[False]*6)
        e.step(0);self.assertTrue(np.all(e._observation()[4:20]==0))
    def test_all_orders_and_cache(self):
        from itertools import permutations
        e=H3ReplayEnv(reports=reports())
        for order in permutations(range(1,5)):
            e.reset();total=0
            for a in [0,*order,6]:
                self.assertTrue(e.action_masks()[a])
                o,r,t,tr,i=e.step(a);total+=r
                self.assertTrue(e.observation_space.contains(o))
            self.assertEqual(total,-5.);self.assertTrue(t);self.assertFalse(tr)
            self.assertEqual(i['stop']['verdict'],'non_concluant')
    def test_invalid_action_terminates(self):
        e=H3ReplayEnv(reports=reports());e.reset()
        _,r,t,_,i=e.step(5)
        self.assertEqual(r,-10.);self.assertTrue(t);self.assertIn('invalid_action',i)
    def test_missing_export_rejected(self):
        r=reports();del r['R4']
        with self.assertRaises(ValueError):H3ReplayEnv(reports=r)

if __name__=='__main__':unittest.main()
