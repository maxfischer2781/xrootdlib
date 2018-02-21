import struct
import enum
from typing import Optional, Union

from .constants import XROOTD_MON_SIDMASK


class recType(int, enum.Enum):
    #: XrdXrootdMonFileCLS
    isClose = 0
    #: XrdXrootdMonFileDSC
    isDisc = 0
    #: XrdXrootdMonFileOPN
    isOpen = 0
    #: XrdXrootdMonFileTOD
    isTime = 0
    #: XrdXrootdMonFileXFR
    isXFR = 0


class recFval(int, enum.Enum):
    #: The sID member is present
    hasSID = 0
    #: XrdXroodMonFileLFN present
    hasLFN = 0
    #: File opened for reads & writes
    hasRW = 0
    #: Disconnect prior to close
    forced = 0
    #: XrdXroodMonFileOPS present
    hasOPS = 0
    #: XrdXroodMonFileSSQ present
    hasSSQ = 0


class FileTOD(object):
    __slots__ = ('flags', 'records_xfr', 'records_total', 'start', 'end', 'sid')
    struct_parser = struct.Struct('!c c h h h l l q')
    size = struct_parser.size

    def __init__(self, flags: bytes, records_xfr: int, records_total: int, start: int, end: int, sid: int):
        self.flags, self.records_xfr, self.records_total, self.start, self.end, self.sid = \
            flags, records_xfr, records_total, start, end, sid

    @classmethod
    def from_buffer(cls, buffer: bytes):
        rec_type, rec_flag, rec_size, recs_xfr, recs_total, t_beg, t_end, sid = cls.struct_parser.unpack_from(buffer) \
            # type: bytes, bytes, int, int, int, int, int, int
        assert rec_size == cls.size, 'FileTOD must be fixed length'
        return cls(rec_flag, recs_xfr, recs_total, t_beg, t_end, sid & XROOTD_MON_SIDMASK)


class FileDSC(object):
    """``XrdXrootdMonFileDSC`` indicating that a client disconnected from the server"""
    __slots__ = ('flags', 'dictid')
    struct_parser = struct.Struct('!c c h L')
    size = struct_parser.size

    def __init__(self, flags: bytes, dictid: str):
        self.flags, self.dictid = flags, dictid

    @classmethod
    def from_buffer(cls, buffer: bytes):
        rec_type, rec_flag, rec_size, dictid = cls.struct_parser.unpack_from(buffer) \
            # type: bytes, bytes, int, int
        assert rec_size == cls.size, 'FileCLS must be fixed length'
        return cls(rec_flag, dictid)


class FileOPN(object):
    """``XrdXrootdMonFileOPN`` indicating that a client opened a file"""
    __slots__ = ('flags', 'fileid', 'fsz', 'user', 'lfn')
    struct_parser = struct.Struct('!c c h L q')

    @property
    def size(self):
        if self.user and self.lfn:
            return self.struct_parser.size + 4 + len(self.lfn)
        return self.struct_parser.size

    @property
    def ufn(self):
        if self.user and self.lfn:
            return FileLFNView(self)
        return None

    def __init__(self, flags: bytes, fileid: int, fsz: int, user: Optional[int] = None, lfn: Optional[bytes] = None):
        self.flags, self.fileid, self.fsz, self.user, self.lfn = flags, fileid, fsz, user, lfn

    @classmethod
    def from_buffer(cls, buffer: bytes):
        rec_type, rec_flag, rec_size, fileid, fsz = cls.struct_parser.unpack_from(buffer) \
            # type: bytes, bytes, int, int, int
        static_size = cls.struct_parser.size
        if rec_size != static_size:
            user = int.from_bytes(buffer[static_size:static_size+4], byteorder='big')
            lfn = buffer[static_size+4:static_size-static_size]
        else:
            user, lfn = None, None
        return cls(rec_flag, fileid, fsz, user, lfn)


class FileLFNView(object):
    __slots__ = ('_file_opn',)

    @property
    def user(self):
        return self._file_opn.user

    @property
    def lfn(self):
        return self._file_opn.lfn

    def __init__(self, file_opn: FileOPN):
        self._file_opn = file_opn


class FileCLS(object):
    """``XrdXrootdMonFileCLS`` indicating that a client closed a file"""
    __slots__ = ('flags', 'dictid', 'read', 'readv', 'write')
    struct_parser = struct.Struct('!c c h L q q q')

    @property
    def xfr(self):
        return StatXFRView(self)

    def __init__(self, flags: bytes, dictid: int, read: int, readv: int, write: int):
        self.flags, self.dictid, self.read, self.readv, self.write = \
            flags, dictid, read, readv, write

    @classmethod
    def from_buffer(cls, buffer: bytes):
        rec_type, rec_flag, rec_size, dictid, read, readv, write = cls.struct_parser.unpack_from(buffer) \
            # type: bytes, bytes, int, int, int, int, int
        static_size = cls.struct_parser.size
        if rec_size != static_size:
            pass


class StatXFRView(object):
    __slots__ = ('_file_cls',)

    @property
    def read(self):
        return self._file_cls.read

    @property
    def readv(self):
        return self._file_cls.readv

    @property
    def write(self):
        return self._file_cls.write

    def __init__(self, file_cls: FileCLS):
        self._file_cls = file_cls
