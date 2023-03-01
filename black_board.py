from queue import SimpleQueue
from threading import Thread
import pandas as pd
from very_simple_logger import VerySimpleLogger

class BlackBoardStorage():
    def __init__(self, logger):
        self.jail_table: pd.DataFrame = pd.DataFrame(columns=['__src_port','__dst_port','__protocol','__flow_duration',
                                                              '__fwd_pkt_len_max','__fwd_pkt_len_min','__fwd_pkt_len_mean',
                                                              '__fwd_pkt_len_std','__bwd_pkt_len_min','__bwd_pkt_len_mean',
                                                              '__fwd_IAT_tot','__pkt_len_min','__RST_flag_cnt','__PSH_flag_cnt',
                                                              '__ACK_flag_cnt','__CWE_flag_cnt','__fwd_seg_size_avg',
                                                              '__bwd_seg_size_avg','__init_fwd_win_byts','__fwd_seg_size_min',
                                                              'CHECKED','BLOCKED_WHEN','FLOW','SRC_IP','SRC_PORT',
                                                              'DST_IP','DST_PORT', 'PROTOCOL', 'FIRST_PKT_TMS', 'LAST_PKT_TMS_FWD', 
                                                              'PKTS_NUMBER_FWD', 'PKTS_NUMBER_BWD', 'LAST_PKT_TMS'])
        #['flow','src_ip','source_port', 'dest_ip', 'dest_port', 'checked', 'blocked_when']
        self.logger: VerySimpleLogger = logger
        self.subprocesses: list(Thread) = []

class BlackBoardStorageTest(BlackBoardStorage):
    """BlackBoard memory for threads but forcing a particular, precomputed jail table from csv"""
    def __init__(self, logger: VerySimpleLogger, jail_t: str):
        super().__init__(logger)
        self.jail_table : pd.DataFrame = pd.read_csv(jail_t)