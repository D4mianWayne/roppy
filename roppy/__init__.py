# Promote useful stuff to toplevel
from .toplevel import *

roppylib.args.initialize()
roppylib.log.install_default_handler()

log = roppylib.log.getLogger('roppylib')
