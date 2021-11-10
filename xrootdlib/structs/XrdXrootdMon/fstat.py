import struct
import enum
from typing import Optional, Union

from .constants import XROOTD_MON_SIDMASK
from ...utility import slot_repr


class recType(int, enum.Enum):
    """Record type identifiers for the f stream"""
    #: XrdXrootdMonFileCLS
    isClose = 0
    #: XrdXrootdMonFileDSC
    isDisc = 4
    #: XrdXrootdMonFileOPN
    isOpen = 1
    #: XrdXrootdMonFileTOD
    isTime = 2
    #: XrdXrootdMonFileXFR
    isXFR = 3


class recFval(int, enum.Enum):
    """Record flags for the f stream"""
    #: The sID member is present
    hasSID = 0x01
    #: XrdXroodMonFileLFN present
    hasLFN = 0x01
    #: FileRecord opened for reads & writes
    hasRW = 0x02
    #: Disconnect prior to close
    forced = 0x01
    #: XrdXroodMonFileOPS present
    hasOPS = 0x02
    #: XrdXroodMonFileSSQ present (implies ``hasOPS``)
    hasSSQ = 0x04


class FileTOD(object):
    """
    ``XrdXrootdMonFileTOD`` identifying the sender and time range

    :param flags: indicator for fields present
    :param records_xfr: number of :py:class:`FileXFR` records in the packet
    :param records_total: number of :py:class:`FileRecord` records in the packet
    :param start: timestamp of the first record
    :param end: timestamp the packet was sent
    :param sid: server identifier (see :py:class:`~xrootdlib.structs.XrdXrootdMon.Map`)
    """
    __slots__ = ('flags', 'records_xfr', 'records_total', 'start', 'end', 'sid')
    struct_parser = struct.Struct('!B B h h h l l q')
    size = struct_parser.size

    def __init__(self, flags: int, records_xfr: int, records_total: int, start: int, end: int, sid: int):
        self.flags, self.records_xfr, self.records_total, self.start, self.end, self.sid = \
            flags, records_xfr, records_total, start, end, sid

    @classmethod
    def from_buffer(cls, buffer: bytes):
        rec_type, rec_flag, rec_size, recs_xfr, recs_total, t_beg, t_end, sid = cls.struct_parser.unpack_from(buffer) \
            # type: int, int, int, int, int, int, int, int
        assert rec_size == cls.size, 'FileTOD must be fixed length'
        return cls(rec_flag, recs_xfr, recs_total, t_beg, t_end, sid & XROOTD_MON_SIDMASK)

    __repr__ = slot_repr


class FileDSC(object):
    """
    ``XrdXrootdMonFileDSC`` indicating that a client disconnected from the server

    :param flags: unused for this record type
    :param dictid: client identifier (see :py:class:`~xrootdlib.structs.XrdXrootdMon.Map`)
    """
    __slots__ = ('flags', 'dictid')
    struct_parser = struct.Struct('!B B h L')
    size = struct_parser.size

    def __init__(self, flags: int, dictid: int):
        self.flags, self.dictid = flags, dictid

    @classmethod
    def from_buffer(cls, buffer: bytes):
        rec_type, rec_flag, rec_size, dictid = cls.struct_parser.unpack_from(buffer) \
            # type: int, int, int, int
        assert rec_size == cls.size, 'FileDSC must be fixed length'
        return cls(rec_flag, dictid)

    __repr__ = slot_repr


class FileOPN(object):
    """
    ``XrdXrootdMonFileOPN`` indicating that a client opened a file

    :param flags: indicator for fields present and access type
    :param size: size of the struct in bytes
    :param fileid: file identifier (see :py:class:`~xrootdlib.structs.XrdXrootdMon.Map`)
    :param filesize: size of the file in bytes
    :param user: client identifier (see :py:class:`~xrootdlib.structs.XrdXrootdMon.Map`)
    :param lfn: the (logical) path of the file

    The ``fileid``, ``user`` and ``lfn`` are closely related and should be interpreted
    together. If not ``rec_flag & hasLFN`` then ``fileid`` points to user info that
    contains both ``user`` and ``lfn`` information. Otherwise, the user info should be
    constructed from ``user`` and ``lfn`` information for the given ``fileid`` as the
    corresponding :py:class:`~.FileCLS` expects this information.
    """
    __slots__ = ('flags', 'size', 'fileid', 'filesize', 'user', 'lfn')
    struct_parser = struct.Struct('!B B h L q')

    @property
    def ufn(self):
        if self.user and self.lfn:
            return FileLFNView(self)
        return None

    @property
    def fsz(self):
        return self.filesize

    def __init__(
            self, flags: int, size: int, fileid: int, filesize: int,
            user: Optional[int] = None, lfn: Optional[bytes] = None
    ):
        self.flags, self.size, self.fileid, self.filesize, self.user, self.lfn = \
            flags, size, fileid, filesize, user, lfn

    @classmethod
    def from_buffer(cls, buffer: bytes):
        rec_type, rec_flag, rec_size, fileid, filesize = cls.struct_parser.unpack_from(buffer) \
            # type: int, int, int, int, int
        static_size = cls.struct_parser.size
        if rec_flag & recFval.hasLFN:
            user = int.from_bytes(buffer[static_size:static_size+4], byteorder='big')
            lfn = bytes(buffer[static_size+4:rec_size]).partition(b'\x00')[0]
        else:
            user, lfn = None, None
        return cls(rec_flag, rec_size, fileid, filesize, user, lfn)

    __repr__ = slot_repr


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


class StatOPS(object):
    """``XrdXrootdMonStatOPS`` describing file operation statistics"""
    __slots__ = (
        'read', 'readv', 'write',
        'rsmin', 'rsmax', 'rsegs',
        'rdmin', 'rdmax', 'rvmin', 'rvmax', 'wrmin', 'wrmax'
    )
    struct_parser = struct.Struct('!3l h h q 6l')
    size = struct_parser.size

    def __init__(
        self,
        read: int, readv: int, write: int,
        rsmin: int, rsmax: int, rsegs: int,
        rdmin: int, rdmax: int, rvmin: int, rvmax: int, wrmin: int, wrmax: int,
    ):
        self.read, self.readv, self.write = read, readv, write
        self.rsmin, self.rsmax, self.rsegs = rsmin, rsmax, rsegs
        self.rdmin, self.rdmax, self.rvmin, self.rvmax, self.wrmin, self.wrmax = \
            rdmin, rdmax, rvmin, rvmax, wrmin, wrmax

    @classmethod
    def from_buffer(cls, buffer: bytes):
        read, readv, write, \
            rsmin, rsmax, rsegs, \
            rdmin, rdmax, rvmin, rvmax, wrmin, wrmax = cls.struct_parser.unpack_from(buffer) \
            # type: int, int, int, int, int, int, int, int, int, int, int, int
        return cls(
            read, readv, write,
            rsmin, rsmax, rsegs,
            rdmin, rdmax, rvmin, rvmax, wrmin, wrmax
        )

    __repr__ = slot_repr


class StatSSQ(object):
    """``XrdXrootdMonStatSSQ`` describing file operation statistic deviations"""
    __slots__ = ('read', 'readv', 'rsegs', 'write')
    struct_parser = struct.Struct('!4q')
    size = struct_parser.size

    def __init__(self, read: int, readv: int, rsegs: int, write: int):
        self.read, self.readv, self.rsegs, self.write = read, readv, rsegs, write

    @classmethod
    def from_buffer(cls, buffer: bytes):
        read, readv, rsegs, write = cls.struct_parser.unpack_from(buffer) \
            # type: int, int, int, int
        return cls(read, readv, rsegs, write)

    __repr__ = slot_repr


class FileCLS(object):
    """
    ``XrdXrootdMonFileCLS`` indicating that a client closed a file

    :param flags: indicator for fields present and close type
    :param fileid: file identifier (see :py:class:`~xrootdlib.structs.XrdXrootdMon.Map`)
    :param read: bytes read using ``read()``
    :param readv: bytes read using ``readv()``
    :param write: bytes written
    :param ops: file operation statistics
    :param ssq: file operation statistic deviations
    """
    __slots__ = ('flags', 'size', 'fileid', 'read', 'readv', 'write', 'ops', 'ssq')
    struct_parser = struct.Struct('!B B h L q q q')

    @property
    def xfr(self):
        return StatXFRView(self)

    def __init__(
            self, flags: int, size: int, fileid: int, read: int, readv: int, write: int,
            ops: Optional[StatOPS], ssq: Optional[StatSSQ]
    ):
        self.flags, self.size, self.fileid, self.read, self.readv, self.write, self.ops, self.ssq = \
            flags, size, fileid, read, readv, write, ops, ssq

    @classmethod
    def from_buffer(cls, buffer: bytes):
        rec_type, rec_flag, rec_size, dictid, read, readv, write = cls.struct_parser.unpack_from(buffer) \
            # type: int, int, int, int, int, int, int
        static_size = cls.struct_parser.size
        ops_size, ssq_size = StatOPS.size, StatSSQ.size
        if rec_flag & recFval.hasOPS:
            ops = StatOPS.from_buffer(buffer[static_size:])
            if rec_flag & recFval.hasSSQ:
                ssq = StatSSQ.from_buffer(buffer[static_size+ops_size:])
            else:
                ssq = None
        else:
            assert rec_size == static_size, (rec_size, static_size)
            ops, ssq = None, None
        return cls(rec_flag, rec_size, dictid, read, readv, write, ops, ssq)

    __repr__ = slot_repr


class FileXFR(object):
    """
    ``XrdXrootdMonFileXFR`` indicating file transfer statistics

    :param flags: unused
    :param fileid: client identifier (see :py:class:`~xrootdlib.structs.XrdXrootdMon.Map`)
    :param read: bytes read using ``read()``
    :param readv: bytes read using ``readv()``
    :param write: bytes written
    """
    __slots__ = ('flags', 'fileid', 'read', 'readv', 'write')
    struct_parser = struct.Struct('!B B h L q q q')
    size = struct_parser.size

    @property
    def xfr(self):
        return StatXFRView(self)

    def __init__(self, flags: int, fileid: int, read: int, readv: int, write: int):
        self.flags, self.fileid, self.read, self.readv, self.write = \
            flags, fileid, read, readv, write

    @classmethod
    def from_buffer(cls, buffer: bytes):
        rec_type, rec_flag, rec_size, dictid, read, readv, write = cls.struct_parser.unpack_from(buffer) \
            # type: int, int, int, int, int, int, int
        assert rec_size == cls.size, 'FileXFR must be fixed length'
        return cls(rec_flag, dictid, read, readv, write)

    __repr__ = slot_repr


class StatXFRView(object):
    __slots__ = ('_file_struct',)

    @property
    def read(self):
        return self._file_struct.read

    @property
    def readv(self):
        return self._file_struct.readv

    @property
    def write(self):
        return self._file_struct.write

    def __init__(self, file_struct: Union[FileCLS, FileXFR]):
        self._file_struct = file_struct


#: Type of records in the f stream
FileRecord = Union[FileTOD, FileDSC, FileOPN, FileCLS, FileXFR]
