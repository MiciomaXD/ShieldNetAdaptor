from threading import Event
from config import *
from black_board import *
from very_simple_logger import *
from log_level import *
from available_commands import *
from metric import *
from common import set_up_logger, write_to_pipe
from neural import *

import os
import errno

logger = None
blackboard = None

def __main_second_layer():
    """Implements a second layer defence in a classic way, using iptables calls; this function
    offers a basic protection"""
    logger.log('Implementing second layer MAIN defence...', Level.INFO, APP_NAME_CORE)

    if os.path.isfile(CLASSIC_SHIELD_RULES):
        with open(CLASSIC_SHIELD_RULES, 'r') as og_iptables:
                for rule in og_iptables:
                    r = rule.strip(' \n')
                    if not r.startswith('#') & (r != ''):
                        os.system(r)
        
        logger.log('Second layer MAIN defence in place', Level.INFO, APP_NAME_CORE)
    else:
        logger.log('Classic iptables rules file not found, cannot implement second layer MAIN defence', Level.WARNING, APP_NAME_CORE)

def __extended_second_layer():
    """Implements a second layer defence in a classic way, using iptables calls; this function
    offers optional defence capabilities"""
    logger.log('Implementing second layer EXTENDED defence...', Level.INFO, APP_NAME_CORE)

    if os.path.isfile(CLASSIC_SHIELD_RULES_OPT):
        with open(CLASSIC_SHIELD_RULES_OPT, 'r') as og_iptables:
            for rule in og_iptables:
                r = rule.strip(' \n')
                if not r.startswith('#') & (r != ''):
                    os.system(r)
        
        logger.log('Second layer EXTENDED defence in place', Level.INFO, APP_NAME_CORE)
    else:
        logger.log('Classic iptables rules file not found, cannot implement second layer EXTENDED defence', Level.WARNING, APP_NAME_CORE)    

def __synproxy_second_layer():
    """Implements a second layer defence in a classic way, using iptables calls; this function
    offers optional defence capabilities using iptables' SYNPROXY: READ COMMENTS IN og_iptables_rules_synproxy BEFORE USE"""
    logger.log('Implementing second layer SYNPROXY defence...', Level.INFO, APP_NAME_CORE)

    if os.path.isfile(CLASSIC_SHIELD_RULES_SYNPROXY):
        with open(CLASSIC_SHIELD_RULES_SYNPROXY, 'r') as og_iptables:
                for rule in og_iptables:
                    r = rule.strip(' \n')
                    if not r.startswith('#') & (r != ''):
                        os.system(r)
        
        logger.log('Second layer SYNPROXY defence in place', Level.INFO, APP_NAME_CORE)
    else:
        logger.log('Classic iptables rules file not found, cannot implement second layer SYNPROXY defence', Level.WARNING, APP_NAME_CORE)

def implement_classic_shield(skip: bool, skip_extended: bool, skip_syproxy: bool):
    """Implements a second layer defence in a classic way, using iptables calls; this function
    is the customizer: what do we want to skip? All second layer def, optional, synproxy..."""
    if skip:
        logger.log('Skipping classic second layer defence (MAIN, EXTENDED & SYNPROXY)...', Level.INFO, APP_NAME_CORE)
        return

    logger.log('Implementing classical fallback defense...', Level.INFO, APP_NAME_CORE)
    __main_second_layer()

    if not skip_extended:
        __extended_second_layer()
    else:
        logger.log('Skipping EXTENDED second layer defence...', Level.INFO, APP_NAME_CORE)
    
    if not skip_syproxy:
        __synproxy_second_layer()
    else:
        logger.log('Skipping SYNPROXY second layer defence...', Level.INFO, APP_NAME_CORE)
    
    logger.log('Fallback defence in place', Level.INFO, APP_NAME_CORE)

def create_jail_chains():
    """Creates a chain in table raw (as closer to the lower layer as possible) that will retain all rules
    blocking ips with the default policy (DROP all from source XXX.XXX.XXX.XXX)"""
    os.system('iptables -t raw -N ShieldNetJail')
    os.system('iptables -t raw -A PREROUTING -j ShieldNetJail')

def delete_first_layer_chains():
    """Restores original setup of iptables when ShieldNet has to stop for what first layer defence is concerned"""
    os.system('iptables -t raw -D PREROUTING -j ShieldNetJail')
    os.system('iptables -t raw -F ShieldNetJail')
    os.system('iptables -t raw -X ShieldNetJail')

def delete_second_layer_chains():
    """Restores original setup of iptables when ShieldNet has to stop for what second layer defence is concerned"""
    if not CLASSIC_SHIELD_SKIP:
        os.system('iptables -t mangle -D PREROUTING -j ShieldNet')
        os.system('iptables -t mangle -F ShieldNet')
        os.system('iptables -t mangle -X ShieldNet')

        if not EXTENDED_CLASSIC_SHIELD_SKIP:
            os.system('iptables -t filter -D INPUT -j ShieldNet')
            os.system('iptables -t filter -F ShieldNet')
            os.system('iptables -t filter -X ShieldNet')

        if not SYNPROXY_SHIELD_SKIP:
            os.system('iptables -t raw -D PREROUTING -j ShieldNet')
            os.system('iptables -t raw -F ShieldNet')
            os.system('iptables -t raw -X ShieldNet')

def main():
    """Entry point of all of this stuff, starts ShieldNet completely: main thread,
    metrics thread, neural thread, iptables classic def, jail management, cooldowns, logging..."""
    global logger, blackboard #so that we can modify global variables

    logger = set_up_logger('./log.txt')

    logger.log('Starting ShieldNet v1.0...', Level.INFO, APP_NAME_CORE)

    logger.log('NOTICE: for optimized fallback defense (main, extended) and synproxy (mandatory, unless skip), use custom kernel settings provided!', Level.WARNING, APP_NAME_CORE)
    implement_classic_shield(CLASSIC_SHIELD_SKIP, EXTENDED_CLASSIC_SHIELD_SKIP, SYNPROXY_SHIELD_SKIP)
    #delete_chains()

    blackboard = BlackBoardStorage(logger)
    logger.log('Storage ready', Level.INFO, APP_NAME_CORE)

    stop_event = Event()
    logger.log('Spawning metrics thread...', Level.INFO, APP_NAME_CORE)
    metrics_th=MetricsThreadContent(blackboard=blackboard, stop_e=stop_event)
    blackboard.subprocesses.append(metrics_th) #get reference
    metrics_th.start()
    logger.log('Metrics thread up and running', Level.INFO, APP_NAME_CORE)

    logger.log('Spawning neural thread...', Level.INFO, APP_NAME_CORE)
    create_jail_chains()
    neural_th=NeuralThreadContent(blackboard=blackboard, args=stop_event)
    blackboard.subprocesses.append(neural_th) #get reference
    neural_th.start()
    logger.log('Neural thread ready and on stand-by', Level.INFO, APP_NAME_CORE)
    logger.log('Defense online', Level.INFO, APP_NAME_CORE)

    logger.log('Initializing interactive ECOM...', Level.INFO, APP_NAME_CORE)
    try:
        logger.log('Creating ECOM named pipes...', Level.INFO, APP_NAME_CORE)
        os.mkfifo(NAMED_PIPE_TO_CORE)
        os.mkfifo(NAMED_PIPE_TO_EXT)
        logger.log('ECOM named pipes created', Level.INFO, APP_NAME_CORE)
    except OSError as oe:
        if oe.errno != errno.EEXIST: #if already existing
            #pipes ok, no good if other error
            logger.log(oe.with_traceback(), Level.ERROR, APP_NAME_CORE)
            raise
        
    while True:
        with open(NAMED_PIPE_TO_CORE, 'r') as fifo:
            for line in fifo:

                refined_line=line.strip(' \n')
                
                if refined_line == Command.HELP.value:
                    message = 'Available commands are:\n'\
                    '[!] help        display this prompt\n'\
                    '[!] start       start ShieldNet packet analysis\n'\
                    '[!] stop        disable ShieldNet packet analysis\n'\
                    '[!] situation   display a human-readable '\
                    'internal state of ShieldNet jails (detailed '\
                    'blocked IPs information)'
                    
                    write_to_pipe(NAMED_PIPE_TO_EXT, message)

                elif refined_line == Command.SITUATION.value:
                    message = blackboard.jail_table.to_string()
                    write_to_pipe(NAMED_PIPE_TO_EXT, message)
                elif refined_line == Command.START.value:
                    message = 'SN Ada, SN Classic, SN Neural are already running!'
                    write_to_pipe(NAMED_PIPE_TO_EXT, message)
                elif refined_line == Command.STOP.value:
                    logger.log('Stopping procedure of ShieldNet invoked', Level.INFO, APP_NAME_CORE)

                    logger.log('Stopping background operations...', Level.INFO, APP_NAME_CORE)
                    stop_event.set()
                    for proc in blackboard.subprocesses:
                        logger.log('Stopped background operations: {0}'.format(proc.name), Level.INFO, APP_NAME_CORE)
                        proc.join()
                    logger.log('Stopped background operations: clear to exit parallel', Level.INFO, APP_NAME_CORE)

                    logger.log('Freeing all in iptables...', Level.INFO, APP_NAME_CORE)
                    delete_second_layer_chains()
                    delete_first_layer_chains()
                    logger.log('Freed all jails and all layers', Level.INFO, APP_NAME_CORE)


                    logger.log('Shutting down gracefully...', Level.INFO, APP_NAME_CORE)
                    
                    message='Shutdown complete'
                    write_to_pipe(NAMED_PIPE_TO_EXT, message)

                    #exit here
                    return
                else:
                    write_to_pipe(NAMED_PIPE_TO_EXT, 'Command not recognized!')

if __name__ == "__main__":
    main()
