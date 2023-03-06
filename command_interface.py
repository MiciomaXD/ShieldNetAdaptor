from config import *
from very_simple_logger import VerySimpleLogger
from log_level import Level
from common import set_up_logger, write_to_pipe, read_from_pipe

import sys

logger=None

def main():
    global logger
    logger = set_up_logger('./log.txt')

    args = sys.argv[1:] #ignore index 0 (name script.py)

    #SN accept only one arg as an allowed command
    if len(args) > 1:
        print('Command not recognized!')
        return

    res = ''
    try:
        write_to_pipe(NAMED_PIPE_TO_CORE, args[0])
        res = read_from_pipe(NAMED_PIPE_TO_EXT)
    except Exception as e:
        logger.log(e.with_traceback(), Level.ERROR, APP_NAME_INTERACTIVE)
        raise
    
    print(res)
    
if __name__ == "__main__":
    main()
