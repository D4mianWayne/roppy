from logging import INFO, WARNING, ERROR, DEBUG
import logging

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


class ColoredFormatter(logging.Formatter):
    def format(self, record):
        prefix = ''
        if record.levelno == 15:
            prefix = '{bold}{green}[+]{end} '.format(bold=Color.BOLD, green=Color.GREEN, end=Color.END)
        if record.levelno == INFO:
            prefix = '{bold}{green}[+]{end} '.format(bold=Color.BOLD, green=Color.BLUE, end=Color.END)
        if record.levelno == WARNING:
            prefix = '{bold}{red}[WARN]{end} '.format(bold=Color.BOLD, red=Color.WHITE, end=Color.END)
        elif record.levelno >= ERROR:
            prefix = '{bold}{yellow}[-]{end} '.format(bold=Color.BOLD, yellow=Color.YELLOW, end=Color.END)
        else:
            prefix = '{bold}[+]{end} '.format(bold=Color.BOLD, end=Color.END)

        return prefix +  super(ColoredFormatter, self).format(record)


handler = logging.StreamHandler()
handler.setFormatter(ColoredFormatter("%(message)s"))
log = logging.getLogger(__name__)
log.setLevel(0)
log.addHandler(handler)
