from config import TCP_FLAGS_TRANSLATOR, APP_NAME_CORE
import scapy.all as sc
from numpy import float64, sqrt, nan
from datetime import datetime, timedelta
from pkt_direction import *
from very_simple_logger import *

def get_tcp_layer_flags_of_packet(p: sc.Packet, layers: list) -> list:
    """Extracts a list containing the full names of the flags set to true
    for the TCP layer of the packet. If no TCP layer, empty list."""
    if 'TCP' in layers:
        return [TCP_FLAGS_TRANSLATOR[x] for x in p['TCP'].flags]
    
    return []

def get_pkt_len(p: sc.Packet) -> int:
    """What is the length of the packet (in bytes)?"""
    return len(p)

def get_init_win_size(p: sc.Packet) -> int:
    """Window length of the packet. 0 for UDP"""
    return p['TCP'].window if 'TCP' in p else 0

def update_mu(new_value: float64, old_mean: float64, n: int) -> float64:
    return 1 / (n + 1) * (n * old_mean + new_value)

def update_sigma(new_value: float64, old_sigma: float64, mean: float64, n: int) -> float64:
    """Returns updated stddev using population variance"""
    return sqrt(n / (n+1) * old_sigma**2 + 1 / n * (new_value - mean)**2)

def update_flow_duration(tms_first_pkt: datetime) -> float64:
    """Returns updated flow duration in musec"""
    return (dt.now() - tms_first_pkt).total_seconds()*1e6

def update_fwd_pkt_len_max(old_value: int, new_value: int, direction: PacketDirection) -> int:
    if direction != PacketDirection.FWD:
        return old_value
    
    #direction is fwd
    if old_value == nan:
        return new_value
    
    #old is not nan
    return max(new_value, old_value)
    
def update_fwd_pkt_len_min(old_value: int, new_value: int, direction: PacketDirection) -> int:
    
    if direction != PacketDirection.FWD:
        return old_value
    
    #direction is fwd
    if old_value == nan:
        return new_value
    
    #old is not nan
    return min(new_value, old_value)

def update_fwd_pkt_len_mean(old_value: float64, new_value: int, n: int, direction: PacketDirection) -> float64:

    if direction != PacketDirection.FWD:
        return old_value
    
    #direction is fwd
    return update_mu(new_value, old_value, n)

def update_fwd_pkt_len_std(old_value: float64, new_value: int, mean: float64, n: int, direction: PacketDirection) -> float64:

    if direction != PacketDirection.FWD:
        return old_value
    
    #direction is fwd
    return update_sigma(new_value, old_value, mean, n)

def update_bwd_pkt_len_min(old_value: int, new_value: int, direction: PacketDirection) ->  int:
    if direction != PacketDirection.BWD:
        return old_value
    
    #direction is bwd
    if old_value == nan:
        return new_value
    
    #old is not nan
    return min(new_value, old_value)

def update_bwd_pkt_len_mean(old_value: float64, new_value: int, n: int, direction: PacketDirection) -> float64:

    if direction != PacketDirection.BWD:
        return old_value
    
    #direction is bwd
    return update_mu(new_value, old_value, n)

def update_fwd_IAT_tot(old_value: float64, seen_now: datetime, last_seen: datetime, direction: PacketDirection) -> float64:

    if direction != PacketDirection.FWD:
        return old_value
    
    #direction is fwd
    #if old_value == nan:
    #    return seen_now - last_seen
    
    #old is not nan
    #return old_value + (seen_now - last_seen)

    return old_value + (seen_now - last_seen).total_seconds()*1e6

def update_pkt_len_min(old_value: int, new_value: int) -> int:

    return min(new_value, old_value)

def update_fwd_seg_size_avg(old_value: float64, new_value: float64, n: int, direction : PacketDirection) -> float64:
    if direction != PacketDirection.FWD:
        return old_value
        
    #direction is fwd
    return update_mu(new_value, old_value, n)

def update_bwd_seg_size_avg(old_value: float64, new_value: float64, n: int, direction : PacketDirection) -> float64:
    if direction != PacketDirection.BWD:
        return old_value
        
    #direction is bwd
    return update_mu(new_value, old_value, n)

def update_fwd_seg_size_min(old_value: float64, new_value: float64, direction : PacketDirection) -> float64:
    if direction != PacketDirection.FWD:
        return old_value
        
    #direction is fwd
    return min(new_value, old_value)

def get_segment_size(p: sc.Packet, logger: VerySimpleLogger) -> int:
    try:
        return len(p['Raw']) if 'Raw' in p else 0
    except Exception as e: #see strange packet
        logger.log('Unable to process packet:\n' + p.show(dump=True) + 'Exception was:' + str(e), Level.ERROR, APP_NAME_CORE + '_metrics')
        return 0