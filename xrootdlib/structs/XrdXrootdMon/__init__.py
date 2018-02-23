import struct
from typing import List, Union, Dict

from .map import SrvInfo, Path, AppInfo, PrgInfo, AuthInfo, XfrInfo, UserId, MapPayload
from .redir import XROOTD_MON as RXROOTD_MON, Redirect, WindowMark, ServerIdent, Redir
from .fstat import FileTOD, FileDSC, FileOPN, FileCLS, FileRecord, FileXFR, recType
from .trace import XROOTD_MON as TXROOTD_MON, AppId, Close, Disc, Open, ReadWrite, ReadU, ReadV, Window, Trace
from ...utility import ValueCacheDict as _ValueCacheDict


class Header(object):
    """
    ``XrdXrootdMonHeader`` shared by all packets

    :param code: identifier for the record type
    :param pseq: wrapping counter for packet sequence
    :param plen: size of the packet in bytes
    :param stod: daemon start timestamp
    """
    __slots__ = ('code', 'pseq', 'plen', 'stod')
    struct_parser = struct.Struct('!c B h l')
    size = struct_parser.size

    def __init__(self, code: bytes, pseq: int, plen: int, stod: int):
        self.code, self.pseq, self.plen, self.stod = \
            code, pseq, plen, stod

    @classmethod
    def from_packet(cls, packet_header: bytes):
        code, pseq, plen, stod = cls.struct_parser.unpack_from(packet_header)  # type: bytes, int, int, int
        return cls(code, pseq, plen, stod)


class Map(object):
    """
    ``XrdXrootdMonMap`` describing transactions and general information

    :param dictid: identifier shared by all records referring to the same information
    :param userid: identifier for the client session being monitored
    :param payload: the actual information of this message

    The :py:class:`~.Map` provides general information that applies across several monitoring events.
    Events of other streams reference this with the ``dictid``,
    or the ``sid`` of the :py:class:`~.UserId` of :py:class:`~.SrvInfo` payloads.
    Note that in case of :py:class:`~.SrvInfo` payloads,
    the ``userid`` contains the *server* user data.
    """
    __slots__ = ('dictid', 'userid', 'payload')
    _parser_cache = _ValueCacheDict(1024)
    payload_dispath = {
        b'=': SrvInfo,
        b'd': Path,
        b'i': AppInfo,
        b'p': PrgInfo,
        b'u': AuthInfo,
        b'x': XfrInfo,
    }

    def __init__(self, dictid: int, userid: UserId, payload: MapPayload):
        self.dictid, self.userid, self.payload = dictid, userid, payload

    def __repr__(self):
        return '{slf.__class__.__name__}(dictid={dictid}, userid={userid}, payload={payload})'.format(
            slf=self, dictid=self.dictid, userid=self.userid, payload=self.payload)

    @classmethod
    def from_record(cls, record_data: bytes, record_code: bytes):
        message_length = len(record_data)
        parser_cache = cls._parser_cache
        try:
            struct_parser = parser_cache[message_length]
        except KeyError:
            struct_parser = parser_cache[message_length] = struct.Struct('!L%ds' % (message_length - 8 - 4))
        dictid, payload = struct_parser.unpack_from(record_data)  # type: int, bytes
        userid, _, map_info = payload.partition(b'\n')
        userid = UserId.from_buffer(userid)
        try:
            payload_type = cls.payload_dispath[record_code]
        except KeyError:
            raise ValueError('unknown record code %r' % record_code)
        else:
            payload = payload_type.from_buffer(map_info)  # type: MapPayload
            return cls(dictid, userid, payload)


class Burr(object):
    """
    ``XrdXrootdMonBurr`` describing redirection events

    :param sid: identification of the server sending events
    :param records: individual operations requested by clients

    The ``records`` field contains operation redirection records (:py:class:`Redirect`)
    framed by window marks (:py:class:`~.WindowMark`).
    In other words, ``records`` contains one *or more* sequences of records,
    with marks at the start, end and between sequences.
    """
    __slots__ = ('sid', 'records')
    payload_dispath = {
        RXROOTD_MON.REDIRECT: Redirect,
        RXROOTD_MON.REDLOCAL: Redirect,
        RXROOTD_MON.REDTIME: WindowMark,
        RXROOTD_MON.REDSID: ServerIdent,
    }

    @property
    def start(self) -> int:
        return self.records[0].timestamp

    @property
    def end(self) -> int:
        return self.records[-1].timestamp

    def __init__(self, sid: ServerIdent, records: List[Redir]):
        if not all(isinstance(record, WindowMark) for record in (records[0], records[-1])):
            raise ValueError('first and last element of `elements` must be a `WindowMark`')
        self.sid, self.records = sid, records

    @classmethod
    def from_record(cls, record_data: bytes, record_code: bytes = b'r'):
        if record_code != b'r':
            raise ValueError('unknown record code %r' % record_code)
        records = []
        record_view = memoryview(record_data)
        while record_view:
            redir_type = record_view[0] & 0xf0
            try:
                payload_type = cls.payload_dispath[redir_type]  # type: Redir
            except KeyError:
                raise ValueError('unknown redir type %r' % redir_type)
            else:
                record = payload_type.from_buffer(record_view)
                records.append(record)
                record_view = record_view[record.size:]
        if not isinstance(records[0], ServerIdent):
            raise ValueError('record data must start with a `ServerIdent`')
        return cls(records[0], records[1:])


class Fstat(object):
    """
    virtual ``XrdXrootdMonFstat`` describing the general file access

    :param tod: identifier for the server and time window
    :param records: file operations and statistics
    """
    __slots__ = ('tod', 'records')
    payload_dispath = {
        recType.isDisc: FileDSC,
        recType.isOpen: FileOPN,
        recType.isTime: FileTOD,
        recType.isClose: FileCLS,
        recType.isXFR: FileXFR,
    }

    @property
    def start(self) -> int:
        return self.tod.start

    @property
    def end(self) -> int:
        return self.tod.end

    def __init__(self, tod: FileTOD, records: List[FileRecord]):
        self.tod, self.records = tod, records

    @classmethod
    def from_record(cls, record_data: bytes, record_code: bytes = b'r'):
        if record_code != b'f':
            raise ValueError('unknown record code %r' % record_code)
        records = []
        record_view = memoryview(record_data)
        while record_view:
            redir_type = record_view[0]
            try:
                payload_type = cls.payload_dispath[redir_type]  # type: FileRecord
            except KeyError:
                raise ValueError('unknown redir type %r' % redir_type)
            else:
                record = payload_type.from_buffer(record_view)
                records.append(record)
                record_view = record_view[record.size:]
        if not isinstance(records[0], FileTOD):
            raise ValueError('record data must start with a `FileTOD`')
        return cls(records[0], records[1:])


class Buff(object):
    """
    ``XrdXrootdMonBuff`` describing trace events

    :param records: individual file operation events
    """
    __slots__ = ('records',)
    payload_dispath = {
        TXROOTD_MON.APPID: AppId,
        TXROOTD_MON.CLOSE: Close,
        TXROOTD_MON.DISC: Disc,
        TXROOTD_MON.OPEN: Open,
        TXROOTD_MON.READU: ReadU,
        TXROOTD_MON.READV: ReadV,
        TXROOTD_MON.WINDOW: Window,
        # no valid flag for ReadWrite
    }

    def __init__(self, records: List[Trace]):
        self.records = records

    @classmethod
    def from_record(cls, record_data: bytes, record_code: bytes = b't'):
        if record_code != b't':
            raise ValueError('unknown record code %r' % record_code)
        records = []
        record_view = memoryview(record_data)
        while record_view:
            redir_type = record_view[0] & 0xf0
            try:
                if redir_type >> 7:  # high order bit is set for all but ReadWrite
                    payload_type = cls.payload_dispath[redir_type]  # type: Trace
                else:
                    payload_type = ReadWrite
            except KeyError:
                raise ValueError('unknown redir type %r' % redir_type)
            else:
                record = payload_type.from_buffer(record_view)
                records.append(record)
                record_view = record_view[record.size:]
        return cls(records)


PacketRecord = Union[Map, Burr, Buff]


class Packet(object):
    """
    ``XrdXrootdMon`` packet for a map, r, t or f stream

    :param header: the header specifying type, ordering and size of the packet
    :param record: the actual information carried by the packet
    """
    __slots__ = ('header', 'record')
    record_dispath = {key: Map for key in Map.payload_dispath.keys()}  # type: Dict[bytes, PacketRecord]
    record_dispath[b'r'] = Burr
    record_dispath[b't'] = Buff
    record_dispath[b'f'] = Fstat

    @property
    def size(self):
        return self.header.plen

    def __init__(self, header: Header, record: PacketRecord):
        self.header, self.record = header, record

    def __str__(self):
        return '<{slf.__class__.__name__}@{address}>'.format(
            slf=self, address=id(self)
        )

    @classmethod
    def from_stream(cls, stream: bytes):
        header = Header.from_packet(stream)
        try:
            record_type = cls.record_dispath[header.code]  # type: PacketRecord
        except KeyError:
            raise ValueError('unknown record code %r' % header.code)
        else:
            record = record_type.from_record(memoryview(stream)[header.size:header.plen], header.code)
            return cls(header, record)


if __name__ == '__main__':
    import sys
    import time
    if len(sys.argv) != 2:
        raise SystemExit("test with 'python3 -m %s <monitor dump file>'" % __package__)
    packet_path = sys.argv[1]
    with open(packet_path, 'rb') as packet_stream:
        packet_buffer = memoryview(packet_stream.read())
    stime, packets = time.time(), 0
    while packet_buffer:
        packet = Packet.from_stream(packet_buffer)
        packets += 1
        # print(packet, packet.record)
        packet_buffer = packet_buffer[packet.size:]
    etime = time.time()
    print('%.1fs' % (etime - stime), '%dHz' % (packets / (etime - stime)))
