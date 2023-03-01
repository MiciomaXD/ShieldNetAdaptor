import subprocess
from threading import Event, Thread
from time import sleep
import scapy.all as sc
import pandas as pd
import numpy as np
from black_board import *
from common import *
from very_simple_logger import *
from config import *
from log_level import *
from model_structure import *

from datetime import timedelta, datetime
import torch
import re

import os

def main():
    logger = set_up_logger('./log.txt')
    go=NeuralThreadContent(blackbox=BlackBoardStorageTest(logger=logger, jail_t='.\\test\\test_generated.csv'))
    go.start()
    go.join()

class NeuralThreadContent(Thread):
    """Runnable to be sure the MetricsRegister thread can work flawlessly and self-contained, just
    pass a logger instance and the shared blackboard memorizer instance"""
    def __init__(self, blackbox: BlackBoardStorage, args: list):
        super().__init__(group=None, target=self.check_flows_register, name='NeuralProcessor', args=args[0], kwargs=None, daemon=True) #daemon true because stop when main stops (supporting thread), but we manage graceful stop so technically not needed
        self.blackbox=blackbox
        self.shieldnet_wrapper = ShieldNet(SHIELDNET_MODEL_PATH, SCALER_PATH, self.blackbox.logger)
        self.t_delta_old = timedelta(seconds=OLD_AFTER_SEC)
        self.t_delta_react = timedelta(seconds=REACTION_TIME_SEC)
    
    def from_df_to_nparray(self, df: pd.DataFrame) -> np.ndarray:
        slice = df.iloc[:,:20]
        slice['__flow_duration'] = float(slice['__flow_duration']) * 1e6
        return np.ndarray()
    
    def get_predictions(self, out):
        pass

    def check_flows_register(self, stop_event: Event):
        while (not stop_event.is_set()): #stop event is telling me to shutdown
            
            now = datetime.now()
            
            #free table from old flows and free ips
            too_old = self.blackbox.jail_table[now - self.blackbox.jail_table['LAST_PKT_TMS'] > self.t_delta_old]
            #some flows could have been blocked since some time
            #need to clear iptables from them (pardon)
            #from too old flows get the source ips of the ones that were blocked
            #and free them
            to_pardon_ips = too_old[too_old['BLOCKED_WHEN'] == True, 'Src_IP']
            for ipv4 in to_pardon_ips:
                self.free_from_jail(ipv4)
            #update register (keep only recent flows)
            self.blackbox.jail_table = self.blackbox.jail_table[now - self.blackbox.jail_table['LAST_PKT_TMS'] <= self.t_delta_old]

            #extract flows to check with NN
            to_check = self.blackbox.jail_table[self.blackbox.jail_table['BLOCKED_WHEN'] == np.nan & \
            (now - self.blackbox.jail_table['CHECKED'] > self.t_delta_react)]

            #classify in bulk
            inputs = torch.tensor(self.from_df_to_nparray(to_check), dtype=torch.float64)
            clss, probs = self.shieldnet_wrapper.eval_input(inputs)
            #{0 : 'ddos', 1 : 'Benign'}

            #update CHECKED
            self.blackbox.jail_table[self.blackbox.jail_table['FLOW'].isin(to_check['FLOW'])]['CHECKED'] = datetime.now()
            
            #isolate dos class index 1
            dos_idx = [i for i,s in enumerate(clss) if s == 1]
            dos_prob = [p for p,s in zip(clss, probs) if s == 1]

            dos_rows = to_check[to_check.index.isin(dos_idx)]

            #block ips
            for i,ipv4 in enumerate(dos_rows['SRC_IP']):
                print('Blocking', ipv4) #! TEST correctness
                continue #! TEST correctness
                self.block_flow(ipv4)
                self.blackbox.logger.log('Blocked ipv4 {0} (probably DoS {1})'.format(ipv4, dos_prob[i]), Level.ERROR, APP_NAME_CORE + '_neural')
            
            #update BLOCKED_WHEN
            self.blackbox.jail_table[self.blackbox.jail_table['FLOW'].isin(dos_rows['FLOW'])]['BLOCKED_WHEN'] = datetime.now()
            
            self.blackbox.jail_table.to_csv('.\\test\\after_block_state.csv', header=True, index=False) #! TEST correctness
    def free_from_jail(self, ip: str):
        if self.check_if_rule_already_exists(ip):
            cmm_out = subprocess.check_output(['iptables', '-t', 'raw', '-L', 'ShieldNetJail', '--line-numbers'])

            ip4_tokens = ip.split('.')
            regex = re.compile(r'^(\d+)(?:[\-\s\w]+)({0}\.{1}\.{2}\.{3})'.format(ip4_tokens[0], ip4_tokens[1], ip4_tokens[2], ip4_tokens[3]))
            match_obj = regex.match(cmm_out)
            rule_num = match_obj.group(1)

            os.system('iptables -t raw -D ShieldNetJail {0}'.format(rule_num))

            self.blackbox.logger.log('Pardon granted to ipv4 {0}'.format(ip), Level.INFO, APP_NAME_CORE + '_neural')
        else:
            self.blackbox.logger.log('No rule in jail table to revoke for ipv4 {0}. This could be an error!'.format(ip), Level.WARNING, APP_NAME_CORE + '_neural')

    def check_if_rule_already_exists(self, ip: str):
        #0 if exists, 1 if not found
        return not os.system('iptables -t raw -A ShieldNetJail -s {0} -j DROP'.format(ip))

    def block_flow(self, ip: str):
        os.system('iptables -t raw -A ShieldNetJail -s {0} -j DROP'.format(ip))

main()
