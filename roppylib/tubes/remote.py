import socket
import ssl as _ssl

from roppylib.log import getLogger
from roppylib.timeout import Timeout
from roppylib.tubes.sock import sock

log = getLogger(__name__)


class remote(sock):


    def __init__(self, host, port,
                 fam="any", typ="tcp",
                 timeout=Timeout.default, ssl=False, sock=None, level=None):
        super(remote, self).__init__(timeout, level=level)

        self.rport = int(port)
        self.rhost = host

        if sock:
            self.family = sock.family
            self.type = sock.type
            self.proto = sock.proto
            self.sock = sock
        else:
            typ = self._get_type(typ)
            fam = self._get_family(fam)
            try:
                self.sock = self._connect(fam, typ)
            except socket.gaierror as e:
                if e.errno != socket.EAI_NONAME:
                    raise
                self.error('Could not resolve hostname: %r' % host)

        if self.sock:
            self.settimeout(self.timeout)
            self.lhost, self.lport = self.sock.getsockname()[:2]

            if ssl:
                self.sock = _ssl.wrap_socket(self.sock)

    @staticmethod
    def _get_family(fam):
        if isinstance(fam, int):
            pass
        elif fam == 'any':
            fam = socket.AF_UNSPEC
        elif fam.lower() in ('ipv4', 'ip4', 'v4', '4'):
            fam = socket.AF_INET
        elif fam.lower() in ('ipv6', 'ip6', 'v6', '6'):
            fam = socket.AF_INET6
        else:
            log.error("remote(): family %r is not supported" % fam)

        return fam

    @staticmethod
    def _get_type(typ):
        if isinstance(typ, int):
            pass
        elif typ == "tcp":
            typ = socket.SOCK_STREAM
        elif typ == "udp":
            typ = socket.SOCK_DGRAM
        else:
            log.error("remote(): type %r is not supported" % typ)

        return typ

    def _connect(self, fam, typ):
        sock = None
        timeout = self.timeout

        h = self.waitfor('Opening connection to %s on port %d' % (self.rhost, self.rport))

        for res in socket.getaddrinfo(self.rhost, self.rport, fam, typ, 0, socket.AI_PASSIVE):
            self.family, self.type, self.proto, _canonname, sockaddr = res

            if self.type not in (socket.SOCK_STREAM, socket.SOCK_DGRAM):
                continue

            h.status("Trying %s" % sockaddr[0])
            sock = socket.socket(self.family, self.type, self.proto)

            if timeout is not None and timeout <= 0:
                sock.setblocking(0)
            else:
                sock.setblocking(1)
                sock.settimeout(timeout)

            try:
                sock.connect(sockaddr)
                break
            except socket.error:
                pass
        else:
            h.failure()
            self.error("Could not connect to %s on port %d" % (self.rhost, self.rport))

        h.success()
        return sock

    @classmethod
    def fromsocket(cls, socket):
        s = socket
        host, port = s.getpeername()
        return remote(host, port, fam=s.family, typ=s.type, sock=s)


class tcp(remote):
    def __init__(self, host, port,
                 fam="any", typ="tcp",
                 timeout=Timeout.default, ssl=False, sock=None, level=None):
        return super(tcp, self).__init__(host, port, fam, typ, timeout, ssl, sock, level)


class udp(remote):
    def __init__(self, host, port,
                 fam="any", typ="udp",
                 timeout=Timeout.default, ssl=False, sock=None, level=None):
        return super(udp, self).__init__(host, port, fam, typ, timeout, ssl, sock, level)
