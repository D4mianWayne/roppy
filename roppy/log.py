from logging import *

class COLORS:
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


class ColoredFormat(Formatter):
    def format(self, message):
        if message.levelno == INFO:
            prefix = "[{0}{1}-{2}] ".format(COLORS.BOLD, COLORS.GREEN, COLORS.END)
        if message.levelno == DEBUG:
            prefix = "[{0}{1}*{2}] ".format(COLORS.BOLD, COLORS.CYAN, COLORS.END)
        elif message.levelno >= ERROR:
            prefix = "[{0}{1}*{2}] ".format(COLORS.BOLD, COLORS.RED, COLORS.END)
        else:
            prefix = "[{0}{1}+{2}] ".format(COLORS.BOLD, COLORS.GREEN, COLORS.END)
        return prefix + super(ColoredFormat, self).format(message)


handler = StreamHandler()
handler.setFormatter(ColoredFormat("%(message)s"))

logger = getLogger(__name__)
logger.addHandler(handler)
logger.setLevel(INFO)