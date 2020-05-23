from logging import getLogger, Formatter, StreamHandler, INFO, WARNING, ERROR


class Color:
    # https://stackoverflow.com/questions/287871/how-to-print-colored-text-in-terminal-in-python

    BLACK     = '\033[30m'
    RED       = '\033[31m'
    GREEN     = '\033[32m'
    YELLOW    = '\033[33m'
    BLUE      = '\033[34m'
    PURPLE    = '\033[35m'
    CYAN      = '\033[36m'
    WHITE     = '\033[37m'
    END       = '\033[0m'
    BOLD      = '\033[1m'
    UNDERLINE = '\033[4m'
    INVISIBLE = '\033[08m'
    REVERCE   = '\033[07m'

class ColoredFormatter(Formatter):
    def format(self, record):
        prefix = ''
        if record.levelno == INFO:
            prefix = '{bold}{green}[+]{end} '.format(bold=Color.BOLD, green=Color.GREEN, end=Color.END)
        if record.levelno == WARNING:
            prefix = '{bold}{red}[+]{end} '.format(bold=Color.BOLD, red=Color.RED, end=Color.END)
        elif record.levelno >= ERROR:
            prefix = '{bold}{yellow}[WARN]{end} '.format(bold=Color.BOLD, yellow=Color.YELLOW, end=Color.END)
        else:
            prefix = '{bold}[+]{end} '.format(bold=Color.BOLD, end=Color.END)

        return prefix +  super(ColoredFormatter, self).format(record)

class DeprecatedLog(object):
    def __init__(self):
        self.warn = False
    
    def dump(self, msg, level=''):
        if not self.warn:
            log.warning("`log.dump` is no longer available! Use `logger` instead")
        self.warn = True

# ptrlib root logger
handler = StreamHandler()
handler.setFormatter(ColoredFormatter("%(message)s"))
log = getLogger(__name__)
log.setLevel(INFO)
log.addHandler(handler)

# For compatibility
log = DeprecatedLog()
dump = log.dump