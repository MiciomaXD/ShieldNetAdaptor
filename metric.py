from threading import Event, Thread
import scapy.all as sc
import pandas as pd
from black_board import *
from common import *
from very_simple_logger import *
from pkt_direction import *
from numpy import nan
from datetime import datetime, timedelta
import metrics_computation as mc
from config import APP_NAME_CORE
import pickle

"""def main():
    logger = set_up_logger('./log.txt')
    #logger.reset()
    stop_event = Event()
    go=MetricsThreadContent(blackboard=BlackBoardStorage(logger = logger), stop_e = stop_event)
    go.start()
    go.join()"""

class MetricsThreadContent(Thread):
    """Runnable to be sure the MetricsRegister thread can work flawlessly and self-contained, just
    pass a logger instance and the shared blackboard memorizer instance"""
    def __init__(self, blackboard: BlackBoardStorage, stop_e: Event):
        self.blackboard=blackboard
        super().__init__(group=None, target=self.listen, name='MetricsRegister', 
                         args=(stop_e,), kwargs=None, daemon=True) #daemon true because stop 
        #when main stops (supporting thread), but we manage graceful stop so technically not needed
        #(stop_e,) is creating manually a tuple with one element (yes, with the comma...)
    
    def listen(self, stop_event: Event):
        """Called by starting the thread, updates jails-table/register every packet that arrives"""
        
        #count=0 #! TEST correctness
        #for packet in sc.sniff(offline='.\\test\\test.pcap'): #! TEST correctness

        for packet in sc.sniff():
            try:
                #count+=1 #! TEST correctness
                #if count % 10000 == 0: print(count) #! TEST correctness

                #todo if exceptions log everything but continue
                if stop_event.is_set(): #stop event is telling me to shutdown
                    return

                if not self.__is_valid(packet): #packet is not TCP or UDP
                    continue
                
                #packet.show()
                flow_dict, layers = self.__parse_flow(packet)

                flow_key = self.__get_packet_flow_key(flow_dict, PacketDirection.FWD)
                exists, idx = self.__flow_exists(flow_key)
                if exists:
                    self.__update_metrics(flow_key, idx, packet, layers, PacketDirection.FWD)
                    continue #processed packet, go to next packet
                
                #fwd key not found if I am here
                #if there is no forward flow with that key, there might be one of it in reverse
                flow_key = self.__get_packet_flow_key(flow_dict, PacketDirection.BWD)
                exists, idx = self.__flow_exists(flow_key)
                if exists:
                    self.__update_metrics(flow_key, idx, packet, layers, PacketDirection.BWD)
                    continue

                #also bwd key not found if I am here
                #this is a packet of a brand new flow
                #by default direction of first packet is FWD
                self.__insert_new_flow(flow_key, flow_dict, packet, layers)
            except Exception as e:
                self.blackboard.logger.log('Unable to process packet:\n' + packet.show(dump=True) + 'Exception was:' + str(e), Level.ERROR, APP_NAME_CORE + '_metrics')
        
        #self.blackboard.jail_table.to_csv(".\\test\\test_generated.csv", header=True, index=False, mode='w') #! TEST correctness
        #with open('.\\test\\test_generated.pkl', 'wb') as handle: #! TEST correctness
            #pickle.dump(self.blackboard.jail_table, handle) #! TEST correctness

    def __is_valid(self, p: sc.Packet):
        """Excludes non TCP or UDP packets (non TCP/UDP can be handled vanilla with iptables)"""
        return 'IP' in p and (p.proto == 17 or p.proto == 6)

    def __get_packet_flow_key(self, flow_dict: dict, direction: PacketDirection) -> str:
        """Returs the key that identifies the flow taking care of the direction"""
        if direction == PacketDirection.FWD:
            return flow_dict['Source_IP'] + '-' + \
            flow_dict['Destination_IP'] + '-' + \
            str(flow_dict['Source_Port']) + '-' + \
            str(flow_dict['Destination_Port']) + '-' + \
            str(flow_dict['Protocol'])

        #direction is backwards
        return str(flow_dict['Destination_IP']) + '-' + \
        flow_dict['Source_IP']+ '-' + \
        str(flow_dict['Destination_Port']) + '-' + \
        str(flow_dict['Source_Port']) + '-' + \
        str(flow_dict['Protocol'])

    def __get_packet_layers(self, p: sc.Packet):
        """Saves the layers of the flow (e.g. Ether/IP/TCP) as a generator,
        remember to call list(this function) to get something manageable"""
        yield p.name
        while p.payload:                     
            p = p.payload
            yield p.name

    def __parse_flow(self, p: sc.Packet) -> dict:
        """Returns a dictionary containing five unique labels that determine flow id; 
        also returns already extracted layers of the packet
        (useless to repeat work later to calculate metrics)"""
        layers = list(self.__get_packet_layers(p))

        #ignore Ether as first layer...(indexes significant from 1)

        if layers[1] == 'ARP':                                      
            src_ip = p[layers[1]].psrc                
            prot = layers[1]                                
            src_port, dst_port, dst_ip = None                              
        else: 
            src_ip = p[layers[1]].src                            
            dst_ip = p[layers[1]].dst
            prot = p[layers[1]].proto
            src_port = p[layers[2]].sport 
            dst_port = p[layers[2]].dport

        flow_parameters = {'Source_IP' : src_ip,
                        'Source_Port' : src_port,
                        'Destination_IP' : dst_ip,
                        'Destination_Port': dst_port,
                        'Protocol' : prot}
        return flow_parameters, layers

    def __flow_exists(self, flow_str: str) -> tuple[bool, int]:
        """Given a flow string identifier, searches it in the register aka jail-table;
        returns a couple <present[T|F],row:int> in which the row index is meaningful only
        if present is True obv"""
        idx = self.blackboard.jail_table.index[self.blackboard.jail_table['FLOW'] == flow_str].tolist()
        if not len(idx):
            return False, -1
        
        return True, idx[0]

    def __insert_new_flow(self, flow_str: str, flow_dict: dict, p: sc.Packet, layers: None | list):
        """If we call this, we know that a packet not belonging to previously seen flows has arrived; so
        insert a new row in the register with right metrics parameters"""
        if layers == None:
            layers = list(self.__get_packet_layers(p))

        tcp_flags = mc.get_tcp_layer_flags_of_packet(p, layers)
        pkt_len = mc.get_pkt_len(p)
        init_win_size = mc.get_init_win_size(p)
        segment_size = mc.get_segment_size(p, self.blackboard.logger)

        row = [
             #-----v needed for NN v---------
             flow_dict['Source_Port'], #__src_port
             flow_dict['Destination_Port'], #__dst_port
             flow_dict['Protocol'], #__protocol
             0., #__flow_duration: empty timedelta constructor is 0
             pkt_len, #__fwd_pkt_len_max: only one value at first, first packet is fwd by default
             pkt_len, #__fwd_pkt_len_min: only one value at first, first packet is fwd by default
             pkt_len, #__fwd_pkt_len_mean: only one value at first, first packet is fwd by default
             0., #__fwd_pkt_len_std: it is the only packet, so 0
             0, #__bwd_pkt_len_min: only one packet by default fwd
             0., #__bwd_pkt_len_mean: only one packet by default fwd
             0., #__fwd_IAT_tot: need at least 2 packets to compute interarrival time
             pkt_len, #__pkt_len_min: only one value at first
             1 if 'RST' in tcp_flags else 0, #__RST_flag_cnt
             1 if 'PSH' in tcp_flags else 0, #__PSH_flag_cnt
             1 if 'ACK' in tcp_flags else 0, #__ACK_flag_cnt
             1 if 'CWE' in tcp_flags else 0, #__CWE_flag_count
             segment_size, #__fwd_seg_size_avg: only one value at first
             0., #__bwd_seg_size_avg
             init_win_size, #__init_fwd_win_byts
             segment_size, #__fwd_seg_size_min
             #-----^----------------------------------^---------
             #-----v needed for jail table management v---------
             # ----v and metrics computation          v---------
             'never', #CHECKED
             'never', #BLOCKED_WHEN
             flow_str, #FLOW
             flow_dict['Source_IP'], #SRC_IP
             flow_dict['Source_Port'], #SRC_PORT
             flow_dict['Destination_IP'], #DST_IP
             flow_dict['Destination_Port'], #DST_PORT
             flow_dict['Protocol'], #PROTOCOL
             datetime.now(), #FIRST_PKT_TMS
             datetime.now(), #LAST_PKT_TMS_FWD
             1, #PKTS_NUMBER_FWD
             0, #PKTS_NUMBER_BWD
             datetime.now() #LAST_PKT_TMS
             #-----^----------------------------------^--------
             ]
        self.blackboard.jail_table.loc[len(self.blackboard.jail_table)] = row

    def __update_metrics(self, flow_existing_key: str, idx: int, packet: sc.Packet, layers: list[str], direction: PacketDirection):
        """A packet is captured, update the corresponding flow information"""
        old_row = self.blackboard.jail_table.iloc[idx,:]

        pkt_len = mc.get_pkt_len(packet)
        tcp_flags = mc.get_tcp_layer_flags_of_packet(packet, layers)
        updated_fwd_pkt_len_mean = mc.update_fwd_pkt_len_mean(old_row['__fwd_pkt_len_mean'], pkt_len, old_row['PKTS_NUMBER_FWD'], direction)
        last_pkt_seen_fwd = datetime.now() if direction == PacketDirection.FWD else old_row['LAST_PKT_TMS_FWD']
        segment_size = mc.get_segment_size(packet, self.blackboard.logger)

        new_row = [
            #-----v needed for NN v---------
            old_row['__src_port'], #__src_port
            old_row['__dst_port'], #__dst_port
            old_row['__protocol'], #__protocol

            mc.update_flow_duration(old_row['FIRST_PKT_TMS']), #__flow_duration

            mc.update_fwd_pkt_len_max(old_row['__fwd_pkt_len_max'], pkt_len, direction), #__fwd_pkt_len_max
            mc.update_fwd_pkt_len_min(old_row['__fwd_pkt_len_min'], pkt_len, direction), #__fwd_pkt_len_min
            updated_fwd_pkt_len_mean, #__fwd_pkt_len_mean
            mc.update_fwd_pkt_len_std(old_row['__fwd_pkt_len_std'], pkt_len, updated_fwd_pkt_len_mean, old_row['PKTS_NUMBER_FWD'], direction), #__fwd_pkt_len_std
             
            mc.update_bwd_pkt_len_min(old_row['__bwd_pkt_len_min'], pkt_len, direction), #__bwd_pkt_len_min
            mc.update_bwd_pkt_len_mean(old_row['__bwd_pkt_len_mean'], pkt_len, old_row['PKTS_NUMBER_BWD'], direction), #__bwd_pkt_len_mean
             
            mc.update_fwd_IAT_tot(old_row['__fwd_IAT_tot'], datetime.now(), old_row['LAST_PKT_TMS_FWD'], direction), #__fwd_IAT_tot: need at least 2 packets to compute interarrival time
             
            mc.update_pkt_len_min(old_row['__pkt_len_min'], pkt_len), #__pkt_len_min

            old_row['__RST_flag_cnt'] + 1 if 'RST' in tcp_flags else old_row['__RST_flag_cnt'], #__RST_flag_cnt
            old_row['__PSH_flag_cnt'] + 1 if 'PSH' in tcp_flags else old_row['__RST_flag_cnt'], #__PSH_flag_cnt
            old_row['__ACK_flag_cnt'] + 1 if 'ACK' in tcp_flags else old_row['__RST_flag_cnt'], #__ACK_flag_cnt
            old_row['__CWE_flag_cnt'] + 1 if 'CWE' in tcp_flags else old_row['__RST_flag_cnt'], #__CWE_flag_cnt

            mc.update_fwd_seg_size_avg(old_row['__fwd_seg_size_avg'], segment_size, old_row['PKTS_NUMBER_FWD'], direction), #__fwd_seg_size_avg
            mc.update_bwd_seg_size_avg(old_row['__bwd_seg_size_avg'], segment_size, old_row['PKTS_NUMBER_BWD'], direction), #__bwd_seg_size_avg

            old_row['__init_fwd_win_byts'],#__init_fwd_win_byts
             
            mc.update_fwd_seg_size_min(old_row['__fwd_seg_size_min'], segment_size, direction),#__fwd_seg_size_min
            #-----^----------------------------------^---------
            #-----v needed for jail table management v---------
            # ----v and metrics computation          v---------
            old_row['CHECKED'], #CHECKED
            old_row['BLOCKED_WHEN'], #BLOCKED_WHEN
            old_row['FLOW'], #FLOW
            old_row['SRC_IP'], #SRC_IP
            old_row['SRC_PORT'], #SRC_PORT
            old_row['DST_IP'], #DST_IP
            old_row['DST_PORT'], #DST_PORT
            old_row['PROTOCOL'], #PROTOCOL

            old_row['FIRST_PKT_TMS'], #FIRST_PKT_TMS
            last_pkt_seen_fwd, #LAST_PKT_TMS_FWD
            old_row['PKTS_NUMBER_FWD'] + 1 if direction == PacketDirection.FWD else old_row['PKTS_NUMBER_FWD'], #PKTS_NUMBER_FWD
            old_row['PKTS_NUMBER_BWD'] + 1 if direction == PacketDirection.FWD else old_row['PKTS_NUMBER_BWD'], #PKTS_NUMBER_BWD
            datetime.now() #LAST_PKT_TMS
            #-----^----------------------------------^---------
            ]
        
        self.blackboard.jail_table.iloc[idx] = new_row

#main()