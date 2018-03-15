import enum
import struct
from typing import Union

from .constants import XROOTD_MON_SIDMASK


class XROOTD_MON(int, enum.Enum):
    #: File has been opened
    OPEN = 0x80
    #: Details for a kXR_readv request
    READV = 0x90
    #: Unpacked details for kXR_readv
    READU = 0x91
    #: Application provided marker
    APPID = 0xa0
    #: File has been closed
    CLOSE = 0xc0
    #: Client has disconnected
    DISC = 0xd0
    #: Window timing mark
    WINDOW = 0xe0
    #: Entry due to forced disconnect
    FORCED = 0x01
    #: Entry for a bound path
    BOUNDP = 0x02


#: Entries in the I/O and non-I/O event streams are always of fixed size (i.e., 16 characters)
TRACE_SIZE = 16


class AppId(object):
    __slots__ = ('appid',)
    struct_parser = struct.Struct('!B 3x 12s')
    size = TRACE_SIZE

    def __init__(self, appid: bytes):
        self.appid = appid

    @classmethod
    def from_buffer(cls, buffer: bytes):
        id0, appid = cls.struct_parser.unpack_from(buffer)  # type: int, bytes
        return cls(appid)


class Close(object):
    __slots__ = ('rtot', 'wtot', 'dictid')
    struct_parser = struct.Struct('!B B B x I I L')
    size = TRACE_SIZE

    def __init__(self, rtot: int, wtot: int, dictid: int):
        self.rtot, self.wtot, self.dictid = rtot, wtot, dictid

    @classmethod
    def from_buffer(cls, buffer: bytes):
        id0, rtot_shift, wtot_shift, rtot, wtot, dictid = cls.struct_parser.unpack_from(buffer) \
            # type: int, int, int, int, int, int
        return cls(rtot << rtot_shift, wtot << wtot_shift, dictid)


class Disc(object):
    __slots__ = ('flags', 'buflen', 'dictid')
    struct_parser = struct.Struct('!B B 6x i L')
    size = TRACE_SIZE

    def __init__(self, flags: int, buflen: int, dictid: int):
        self.flags, self.buflen, self.dictid = flags, buflen, dictid

    @classmethod
    def from_buffer(cls, buffer: bytes):
        id0, flags, buflen, dictid = cls.struct_parser.unpack_from(buffer)  # type: int, int, int, int
        return cls(flags, buflen, dictid)


class Open(object):
    __slots__ = ('filesize', 'dictid')
    struct_parser = struct.Struct('!B 7s 4x L')
    size = TRACE_SIZE

    def __init__(self, filesize: int, dictid: int):
        self.filesize, self.dictid = filesize, dictid

    @classmethod
    def from_buffer(cls, buffer: bytes):
        id0, raw_filesize, dictid = cls.struct_parser.unpack_from(buffer)  # type: int, bytes, int
        filesize = int.from_bytes(raw_filesize, byteorder='big')
        return cls(filesize, dictid)


class ReadWrite(object):
    __slots__ = ('val', 'buflen', 'dictid')
    struct_parser = struct.Struct('!q i L')
    size = TRACE_SIZE

    @property
    def readlen(self):
        return max(self.buflen, 0)

    @property
    def writelen(self):
        return max(-self.buflen, 0)

    def __init__(self, val: int, buflen: int, dictid: int):
        self.val, self.buflen, self.dictid = val, buflen, dictid

    @classmethod
    def from_buffer(cls, buffer: bytes):
        val, buflen, dictid = cls.struct_parser.unpack_from(buffer)  # type: int, int, int
        return cls(val, buflen, dictid)


class Read(object):
    __slots__ = ('readid', 'count', 'buflen', 'dictid')
    struct_parser = struct.Struct('!B B H 4x i L')
    size = TRACE_SIZE

    def __init__(self, readid: int, count: int, buflen: int, dictid: int):
        self.readid, self.count, self.buflen, self.dictid = readid, count, buflen, dictid

    @classmethod
    def from_buffer(cls, buffer: bytes):
        id0, readid, count, buflen, dictid = cls.struct_parser.unpack_from(buffer)  # type: int, int, int, int, int
        return cls(readid, count, buflen, dictid)


class ReadU(Read):
    __slots__ = ()


class ReadV(Read):
    __slots__ = ()


class Window(object):
    __slots__ = ('sid', 'end', 'start')
    struct_parser = struct.Struct('!B x 6s i i')
    size = TRACE_SIZE

    def __init__(self, sid: int, end: int, start: int):
        self.sid, self.end, self.start = sid, end, start

    @classmethod
    def from_buffer(cls, buffer: bytes):
        id0, raw_sid, end, start = cls.struct_parser.unpack_from(buffer)  # type: int, bytes, int, int, int
        sid = int.from_bytes(raw_sid, byteorder='big') & XROOTD_MON_SIDMASK
        return cls(sid, end, start)


Trace = Union[AppId, Close, Disc, Open, ReadWrite, ReadU, ReadV, Window]
