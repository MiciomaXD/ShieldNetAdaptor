from very_simple_logger import VerySimpleLogger
from log_level import Level
import stat, os

def set_up_logger(path: str) -> VerySimpleLogger:
    """In what file are we going to log?"""
    return VerySimpleLogger(path)

def write_to_pipe(pipe_name: str, what: str):
    """Write to named pipe to communicate"""
    if stat.S_ISFIFO(os.stat(pipe_name).st_mode):

        with open(pipe_name, 'w') as fifo:
            #for pipes we must have a \n at the end to work
            if not what.endswith('\n'):
                fifo.write(what + '\n')
            else:
                fifo.write(what)
    else:
        raise Exception('Trying to write on named pipe that does not exist!')

def read_from_pipe(pipe_name: str) -> str:
    """Read from named pipe to communicate"""

    res=''
    if stat.S_ISFIFO(os.stat(pipe_name).st_mode):

        with open(pipe_name, 'r') as fifo:
            for line in fifo:
                res += line
    else:
        raise Exception('Trying to read on named pipe that does not exist!')
    
    return res