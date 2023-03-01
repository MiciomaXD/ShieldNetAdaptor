from datetime import datetime as dt
from log_level import Level

class VerySimpleLogger:
    """Nothing fancy here, only a very simple logging utility"""
    def __init__(self, log_file):
        self.path = log_file
    
    def log(self, what, level: Level = Level.NONE, app = None) -> int:
        """Log in the associated file something with an importance level coming from some app"""
        timestamp = dt.now().strftime('%d-%m-%Y %H:%M:%S')
        log_str = '[{0}]'.format(timestamp)

        if level != Level.NONE:
            log_str+='[{0}]'.format(level.value)

        log_str+=': '

        if app != None:
            log_str+='[{0}] '.format(str(app))

        log_str += str(what)
        log_str += '\n'

        try:
            f = open(self.path, 'a')
            f.write(log_str)
            f.close()
        except Exception as e:
            print(e)
            return 1
    
        return 0
    
    def reset(self) -> int:
        """Clears associated logging file"""
        try:
            f = open(self.path, 'w')
            f.close()
        except Exception as e:
            print(e)
            return 1
    
        return 0