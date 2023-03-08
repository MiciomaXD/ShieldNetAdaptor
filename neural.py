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

"""def main():
    logger = set_up_logger('./log.txt')
    stop_event = Event()
    go=NeuralThreadContent(blackboard=BlackBoardStorageTest(logger=logger, jail_t='.\\test\\test_generated.pkl'), stop_e = stop_event)
    go.start()
    go.join()"""

class NeuralThreadContent(Thread):
    """Runnable to be sure the MetricsRegister thread can work flawlessly and self-contained, just
    pass a logger instance and the shared blackboard memorizer instance"""
    def __init__(self, blackboard: BlackBoardStorage, stop_e: Event):
        super().__init__(group=None, target=self.check_flows_register, name='NeuralProcessor', args=(stop_e,), kwargs=None, daemon=True) #daemon true because stop when main stops (supporting thread), but we manage graceful stop so technically not needed
        self.blackboard = blackboard
        self.shieldnet_wrapper = ShieldNet(SHIELDNET_MODEL_PATH, SCALER_PATH, self.blackboard.logger)
        self.t_delta_old = timedelta(seconds=OLD_AFTER_SEC)
        self.t_delta_react = timedelta(seconds=REACTION_TIME_SEC)
        self.t_delta_jail = timedelta(seconds=JAIL_TIME_SEC)
        self.at_least_fwd = AT_LEAST_FWD_PKT_TO_CLASSIF
    
    def __from_df_to_numpy(self, df: pd.DataFrame) -> torch.Tensor:
        slice = df.iloc[:,:20]
        return slice.to_numpy(dtype=np.float64)

    def check_flows_register(self, stop_event: Event):
        """This function checks the register for old flows to clear,
        flows to classify and does the job"""
        while (not stop_event.is_set()): #stop event is telling me to shutdown
            
            now = datetime.now()
            
            #free table from old flows and free ips associated
            #old flows are flows checked at least once and if blocked more than JAIL_TIME_SEC ago or
            #not blocked but older than OLD_AFTER_SEC

            #yes, concatenation requires this many ().......
            too_old = self.blackboard.jail_table[(self.blackboard.jail_table['CHECKED'] != 'never') & (
                ((now - self.blackboard.jail_table['LAST_PKT_TMS'] > self.t_delta_old) &
                (self.blackboard.jail_table['BLOCKED_WHEN'] == 'never')) |
                ((now - self.blackboard.jail_table['LAST_PKT_TMS'] > self.t_delta_jail) &
                (self.blackboard.jail_table['BLOCKED_WHEN'] != 'never')))]
            #some flows could have been blocked since some time
            #need to clear iptables from them (pardon)
            #from too old flows get the source ips of the ones that were blocked
            #and free them
            to_pardon_ips = too_old[too_old['BLOCKED_WHEN'] != 'never']['SRC_IP']
            for ipv4 in to_pardon_ips:
                self.__free_from_jail(ipv4)
            #update register (keep only flows not in too_old)
            self.blackboard.jail_table = self.blackboard.jail_table[~self.blackboard.jail_table['FLOW'].isin(too_old['FLOW'])]
            
            #extract flows to check with NN (flows not blocked and at least 20 fwd packets, checked more than t_delta_react time ago or never checked)
            to_check = self.blackboard.jail_table[(self.blackboard.jail_table['BLOCKED_WHEN'] == 'never') & 
                                                  (self.blackboard.jail_table['PKTS_NUMBER_FWD'] > self.at_least_fwd)] #flows not blocked
            to_check_A = to_check[to_check['CHECKED'] == 'never'] #never checked
            to_check_B = to_check[to_check['CHECKED'] != 'never']
            to_check_B = to_check_B[now - to_check_B['CHECKED'] > self.t_delta_react] #older than delta react
            to_check = pd.concat([to_check_A, to_check_B], ignore_index=True) #ignore index true to rebuild index

            #no flow to check?
            if len(to_check) == 0:
                for _ in range(int(self.t_delta_react.total_seconds())): #to ensure reactivity
                    if stop_event.is_set():
                        return
                    sleep(1)
                continue
            
            #found at least one flow to check
            #classify in bulk
            inputs = self.__from_df_to_numpy(to_check)
            clss, probs = self.shieldnet_wrapper.eval_input(inputs)
            #{0 : 'ddos', 1 : 'Benign'}

            #update CHECKED
            #not this (vorking on copy)
            #self.blackboard.jail_table[self.blackboard.jail_table['FLOW'].isin(to_check['FLOW'])]['CHECKED'] = datetime.now()
            #but this
            self.blackboard.jail_table.loc[self.blackboard.jail_table['FLOW'].isin(to_check['FLOW']), 'CHECKED'] = datetime.now()
            
            #isolate dos class index 0
            dos_idx = [i for i,s in enumerate(clss) if s == 0]
            dos_prob = [probs[i] for i in dos_idx]

            dos_rows = to_check[to_check.index.isin(dos_idx)]

            #block ips
            for i,ipv4 in enumerate(dos_rows['SRC_IP']):
                print('Blocking', ipv4) #! TEST correctness
                continue #! TEST correctness
                self.__block_flow(ipv4)
                self.blackboard.logger.log('Blocked ipv4 {0} (probably DoS {1})'.format(ipv4, dos_prob[i]), Level.ERROR, APP_NAME_CORE + '_neural')
            
            #update BLOCKED_WHEN
            #self.blackboard.jail_table[self.blackboard.jail_table['FLOW'].isin(dos_rows['FLOW'])]['BLOCKED_WHEN'] = datetime.now()
            self.blackboard.jail_table.loc[self.blackboard.jail_table['FLOW'].isin(dos_rows['FLOW']), 'BLOCKED_WHEN'] = datetime.now()
            
            self.blackboard.jail_table.to_csv('.\\test\\after_block_state.csv', header=True, index=False, mode='w') #! TEST correctness
    
    def __free_from_jail(self, ip: str):
        """Unjails an ip from iptables"""
        if self.__check_if_rule_already_exists(ip):
            cmm_out = subprocess.check_output(['iptables', '-t', 'raw', '-L', 'ShieldNetJail', '--line-numbers'])

            ip4_tokens = ip.split('.')
            regex = re.compile(r'^(\d+)(?:[\-\s\w]+)(?:{0}\.{1}\.{2}\.{3})'.format(ip4_tokens[0], ip4_tokens[1], ip4_tokens[2], ip4_tokens[3]))
            match_obj = regex.match(cmm_out)
            rule_num = match_obj.group(1)

            os.system('iptables -t raw -D ShieldNetJail {0}'.format(rule_num))

            self.blackboard.logger.log('Pardon granted to ipv4 {0}'.format(ip), Level.INFO, APP_NAME_CORE + '_neural')
        else:
            self.blackboard.logger.log('No rule in jail table to revoke for ipv4 {0}. This could be an error!'.format(ip), Level.WARNING, APP_NAME_CORE + '_neural')

    def __check_if_rule_already_exists(self, ip: str) -> bool:
        """Is there any rule that blocks the ip?"""
        #command returns 0 if exists, 1 if not found
        return not os.system('iptables -t raw -C ShieldNetJail -s {0} -j DROP'.format(ip))

    def __block_flow(self, ip: str) -> None:
        """Blocks an ip"""
        os.system('iptables -t raw -A ShieldNetJail -s {0} -j DROP'.format(ip))

#main()
