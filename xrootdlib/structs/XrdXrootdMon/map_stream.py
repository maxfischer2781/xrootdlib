"""
Contents of the XrdXrootdMonMap struct

Each struct contains a ``userid/npayload`` info field.
The ``userid`` is always represented by :py:class:`~.UserId`,
while the ``payload`` can be any of the types of :py:class:`~.MapPayload`.

Each class is capable of parsing its respective *portion* of the info field.
That is, it expects a buffer (a :py:class:`bytes`, :py:class:`bytesarray` or :py:class:`memoryview`)
starting with the ``XrdXrootdMonMap`` info;
trailing buffer content is allowed and the buffer is never modified.
"""
from typing import Union

from ...utility import parse_cgi as _parse_cgi


# Monitor Map Message
class UserId(object):
    """``userid/*`` describing the user performing an action"""
    __slots__ = ('prot', 'user', 'pid', 'sid', 'host')

    def __init__(self, prot: bytes, user: bytes, pid: int, sid: int, host: bytes):
        self.prot, self.user, self.pid, self.sid, self.host = \
            prot, user, pid, sid, host

    def __repr__(self):
        return '{slf.__class__.__name__}({attrs})'.format(
            slf=self, attrs=', '.join(repr(getattr(self, attr)) for attr in self.__slots__)
        )

    @classmethod
    def from_buffer(cls, buffer: bytes):
        rest, host = buffer.rsplit(b'@')
        rest, sid = rest.rsplit(b':')
        rest, pid = rest.rsplit(b'.')
        prot, user = rest.rsplit(b'/')
        return cls(prot, user, int(pid), int(sid), host)


class SrvInfo(object):
    """``*/srvinfo`` describing the xrootd instance sending reports"""
    __slots__ = ('pgm', 'ver', 'inst', 'port', 'site')

    def __init__(self, pgm: bytes, ver: bytes, inst: bytes, port: int, site: bytes):
        self.pgm, self.ver, self.inst, self.port, self.site = \
            pgm, ver, inst, port, site

    @classmethod
    def from_buffer(cls, buffer: bytes):
        info_data = _parse_cgi(buffer)
        pgm, ver, inst, port, site = (info_data[slot.encode()] for slot in cls.__slots__)
        return cls(pgm, ver, inst, int(port), site)

    def __repr__(self):
        return '{slf.__class__.__name__}({attrs})'.format(
            slf=self, attrs=', '.join(repr(getattr(self, attr)) for attr in self.__slots__)
        )


class Path(object):
    """``*/path`` containing full path name of a file being opened"""
    __slots__ = ('path',)

    def __init__(self, path: bytes):
        self.path = path

    @classmethod
    def from_buffer(cls, buffer: bytes):
        return cls(buffer)

    def __repr__(self):
        return '{slf.__class__.__name__}({attrs})'.format(
            slf=self, attrs=', '.join(repr(getattr(self, attr)) for attr in self.__slots__)
        )


class AppInfo(object):
    """``*/appinfo`` containing un-interpreted application supplied information"""
    __slots__ = ('appinfo',)

    def __init__(self, appinfo: bytes):
        self.appinfo = appinfo

    @classmethod
    def from_buffer(cls, buffer: bytes):
        return cls(buffer)

    def __repr__(self):
        return '{slf.__class__.__name__}({attrs})'.format(
            slf=self, attrs=', '.join(repr(getattr(self, attr)) for attr in self.__slots__)
        )


class PrgInfo(object):
    """``*/prginfo`` describing the purging of a file"""
    __slots__ = ('xfn', 'tod', 'sz', 'at', 'ct', 'mt', 'fn')

    def __init__(self, xfn: bytes, tod: int, sz: int, at: int, ct: int, mt: int, fn: bytes):
        self.xfn, self.tod, self.sz, self.at, self.ct, self.mt, self.fn = \
            xfn, tod, sz, at, ct, mt, fn

    @classmethod
    def from_buffer(cls, buffer: bytes):
        xfn, _, rest = buffer.partition(b'\n')
        info_data = _parse_cgi(rest)
        tod, sz, at, ct, mt, fn = (info_data[slot.encode()] for slot in cls.__slots__ if slot != 'xfn')
        return cls(xfn, int(tod), int(sz), int(at), int(ct), int(mt), fn)

    def __repr__(self):
        return '{slf.__class__.__name__}({attrs})'.format(
            slf=self, attrs=', '.join(repr(getattr(self, attr)) for attr in self.__slots__)
        )


class XfrInfo(object):
    """``*/xfrinfo``` describing the transfer of a file"""
    __slots__ = ('lfn', 'tod', 'sz', 'tm', 'op', 'rc', 'pd')

    def __init__(self, lfn: bytes, tod: int, sz: int, tm: int, op: str, rc: int, pd: bytes):
        self.lfn, self.tod, self.sz, self.tm, self.op, self.rc, self.pd = \
            lfn, tod, sz, tm, op, rc, pd

    @classmethod
    def from_buffer(cls, buffer: bytes):
        lfn, _, rest = buffer.partition(b'\n')
        info_data = _parse_cgi(rest)
        tod, sz, tm, op, rc = (info_data[slot.encode()] for slot in cls.__slots__ if slot not in {'lfn', 'pd'})
        return cls(lfn, int(tod), int(sz), int(tm), op, int(rc), info_data.get(b'pd'))

    def __repr__(self):
        return '{slf.__class__.__name__}({attrs})'.format(
            slf=self, attrs=', '.join(repr(getattr(self, attr)) for attr in self.__slots__)
        )


class AuthInfo(object):
    """``*/authinfo`` describing an authenticating user"""
    __slots__ = ('p', 'n', 'h', 'o', 'r', 'g', 'm', 'x', 'y')

    @property
    def protocol(self):
        return self.p

    @property
    def name(self):
        return self.n

    @property
    def host(self):
        return self.h

    @property
    def organisation(self):
        return self.o

    @property
    def role(self):
        return self.r

    @property
    def group(self):
        return self.g

    @property
    def executable(self):
        return self.x

    @property
    def moninfo(self):
        return self.y

    def __init__(self, p: bytes, n: bytes, h: bytes, o: bytes, r: bytes, g: bytes, m: bytes, x: bytes, y: bytes):
        self.p, self.n, self.h, self.o, self.r, self.g, self.m, self.x, self.y = \
            p, n, h, o, r, g, m, x, y

    @classmethod
    def from_buffer(cls, buffer: bytes):
        info_data = _parse_cgi(buffer)
        return cls(*(info_data.get(slot.encode()) for slot in cls.__slots__))

    def __repr__(self):
        return '{slf.__class__.__name__}({attrs})'.format(
            slf=self, attrs=', '.join(repr(getattr(self, attr)) for attr in self.__slots__)
        )


MapPayload = Union[SrvInfo, Path, AppInfo, PrgInfo, AuthInfo, XfrInfo]
