"""
Structs used for the *Detailed Monitoring Data Format* streams sent by servers.
See the ``all.monitor`` directive and `XRootD Monitoring`_ for details.

All types implement a ``Type[T].from_XXX(buffer: bytes) -> T`` constructor method,
where XXX describes the appropriate section.
These section are ``buffer`` or ``record``, which represent the stream buffer
either at the start of a packet or the start of a record.
Unless you explicitly have a need otherwise, use :py:meth:`Packet.from_buffer`
to read an entire packet at a time.

.. _XRootD Monitoring: http://xrootd.org/doc/dev44/xrd_monitoring.htm
"""
import struct
from typing import List, Union, Dict

from .map import SrvInfo, Path, AppInfo, PrgInfo, AuthInfo, XfrInfo, UserId, MapPayload
from .redir import XROOTD_MON as RXROOTD_MON, Redirect, WindowMark, ServerIdent, Redir
from .fstat import FileTOD, FileDSC, FileOPN, FileCLS, FileRecord, FileXFR, recType
from .trace import XROOTD_MON as TXROOTD_MON, AppId, Close, Disc, Open, ReadWrite, ReadU, ReadV, Window, Trace
from .plugin import ProxyCache, ContextCache, TCPConnectionMonitor, pluginType, PluginRecord
from .constants import XROOTD_MON_PIDMASK, XROOTD_MON_PIDSHFT


class Header(object):
    """
    ``XrdXrootdMonHeader`` shared by all packets

    :param code: identifier for the record type
    :param pseq: wrapping counter for packet sequence
    :param plen: size of the packet in bytes
    :param stod: daemon start timestamp
    """
    __slots__ = ('code', 'pseq', 'plen', 'stod')
    struct_parser = struct.Struct('!c B H l')
    size = struct_parser.size

    def __init__(self, code: bytes, pseq: int, plen: int, stod: int):
        self.code, self.pseq, self.plen, self.stod = \
            code, pseq, plen, stod

    @classmethod
    def from_buffer(cls, buffer: bytes) -> 'Header':
        """
        Extract the header from the start of a stream packet buffer

        :param buffer: buffer containing a monitor stream packet
        """
        code, pseq, plen, stod = cls.struct_parser.unpack_from(buffer)  # type: bytes, int, int, int
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
    _parser_cache = {}
    #: record type => appropriate record struct
    _payload_dispatch = {
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
    def from_record(cls, record_data: bytes, record_code: bytes) -> 'Map':
        """
        Extract the record from the record portion of a stream packet buffer

        :param record_data: buffer at the start of the record of a monitor stream packet
        :param record_code: the :py:attr:`~.Header.code` field for this packet
        """
        message_length = len(record_data)
        parser_cache = cls._parser_cache
        try:
            struct_parser = parser_cache[message_length]
        except KeyError:
            struct_parser = parser_cache[message_length] = struct.Struct('!L%ds' % (message_length - 4))
            if len(cls._parser_cache) > 128:
                print(cls._parser_cache.popitem())
        dictid, payload = struct_parser.unpack_from(record_data)  # type: int, bytes
        userid, _, map_info = payload.partition(b'\n')
        userid = UserId.from_buffer(userid)
        try:
            payload_type = cls._payload_dispatch[record_code]
        except KeyError:
            raise ValueError('unknown record code %r' % record_code)
        else:
            payload = payload_type.from_buffer(map_info)  # type: MapPayload
            return cls(dictid, userid, payload)


class Burr(object):
    """
    ``XrdXrootdMonBurr`` ("r-stream") describing redirection events

    :param sid: identification of the server sending events
    :param records: individual operations requested by clients

    The ``records`` field contains redirection records (:py:class:`~.Redirect`)
    framed by window marks (:py:class:`~.WindowMark`).
    In other words, ``records`` is a *flat* sequence of
    one *or more* sequences of records,
    with marks at the start, end and between sequences.
    """
    __slots__ = ('sid', 'records')
    #: segment identifier => appropriate record struct
    _record_dispatch = {
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
    def from_record(cls, record_data: bytes, record_code: bytes = b'r') -> 'Burr':
        """
        Extract the record from the record portion of a stream packet buffer

        :param record_data: buffer at the start of the record of a monitor stream packet
        :param record_code: the :py:attr:`~.Header.code` field for this packet

        :note: The only valid record code for this class is ``b'r'``.
        """
        if record_code != b'r':
            raise ValueError('unknown record code %r (expected %r)' % (record_code, b'r'))
        records = []
        record_view = memoryview(record_data)
        while record_view:
            redir_type = record_view[0] & 0b11110000
            try:
                if redir_type >> 7:  # high order bit is set for all but WindowMark
                    payload_type = cls._record_dispatch[redir_type]  # type: Redir
                else:
                    payload_type = WindowMark
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
    ``XrdXrootdMonFstat`` ("f-stream") describing the general file access

    :param tod: identifier for the server and time window
    :param records: file operations and statistics

    The ``records`` is a flat sequence of
    open records (:py:class:`~.FileOPN`),
    transfer records (:py:class:`~.FileXFR`, if ``fstat xfr`` is configured),
    close records (:py:class:`~.FileCLS`),
    and
    disconnect records (:py:class:`~.FileDSC`).
    As per the specification,
    for every access the records are provided in this order.
    However, records for one access may be spread over multiple time windows.
    """
    __slots__ = ('tod', 'records')
    payload_dispatch = {
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
    def from_record(cls, record_data: bytes, record_code: bytes = b'f') -> 'Fstat':
        """
        Extract the record from the record portion of a stream packet buffer

        :param record_data: buffer at the start of the record of a monitor stream packet
        :param record_code: the :py:attr:`~.Header.code` field for this packet

        :note: The only valid record code for this class is ``b'f'``.
        """
        if record_code != b'f':
            raise ValueError('unknown record code %r (expected %r)' % (record_code, b'f'))
        records = []
        record_view = memoryview(record_data)
        while record_view:
            redir_type = record_view[0]
            try:
                payload_type = cls.payload_dispatch[redir_type]  # type: FileRecord
            except KeyError:
                raise ValueError('unknown fstat type %r' % redir_type)
            else:
                record = payload_type.from_buffer(record_view)
                records.append(record)
                record_view = record_view[record.size:]
        if not isinstance(records[0], FileTOD):
            raise ValueError('record data must start with a `FileTOD`')
        return cls(records[0], records[1:])


class Buff(object):
    """
    ``XrdXrootdMonBuff`` ("t-stream") describing trace events

    :param records: individual file operation events

    The ``records`` field contains various trace records
    framed by window marks (:py:class:`~.Window`).
    In other words, ``records`` is a *flat* sequence of
    one *or more* sequences of records,
    with marks at the start, end and between sequences.
    """
    __slots__ = ('records',)
    payload_dispatch = {
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
    def from_record(cls, record_data: bytes, record_code: bytes = b't') -> 'Buff':
        """
        Extract the record from the record portion of a stream packet buffer

        :param record_data: buffer at the start of the record of a monitor stream packet
        :param record_code: the :py:attr:`~.Header.code` field for this packet

        :note: The only valid record code for this class is ``b't'``.
        """
        if record_code != b't':
            raise ValueError('unknown record code %r (expected %r)' % (record_code, b't'))
        records = []
        record_view = memoryview(record_data)
        while record_view:
            redir_type = record_view[0] & 0xf0
            try:
                if redir_type >> 7:  # high order bit is set for all but ReadWrite
                    payload_type = cls.payload_dispatch[redir_type]  # type: Trace
                else:
                    payload_type = ReadWrite
            except KeyError:
                raise ValueError('unknown redir type %r' % redir_type)
            else:
                record = payload_type.from_buffer(record_view)
                records.append(record)
                record_view = record_view[record.size:]
        return cls(records)


#: Record types in a packet
PacketRecord = Union[Map, Burr, Fstat, Buff]


class Plugin(object):
    """
    ``XrdXrootdMonGS`` ("g-stream") describing information from plug-ins such
    as Cache Context Manager, Proxy File Cache or TCP connection monitor 

    :param tBeg: UNIX time of the first entry
    :param tEnd: UNIX time of the last entry
    :param records: file operations and statistics

    """
    __slots__ = ('tBeg', 'tEnd', 'records')
    payload_dispatch = {
        pluginType.isCCM: ContextCache,
        pluginType.isPFC: ProxyCache,
        pluginType.isTCM: TCPConnectionMonitor
    }

    def __init__(self, tBeg: int, tEnd: int, records: List[PluginRecord]):
        self.tBeg = tBeg
        self.tEnd = tEnd
        self.records = records

    @classmethod
    def from_record(cls, record_data: Union[bytes, memoryview], record_code: bytes = b'g') -> 'Plugin':
        """
        Extract the record from the record portion of a stream packet buffer

        :param record_data: buffer at the start of the record of a monitor stream packet
        :param record_code: the :py:attr:`~.Header.code` field for this packet

        :note: The only valid record code for this class is ``b'g'``.
        """
        if record_code != b'g':
            raise ValueError('unknown record code %r (expected %r)' % (record_code, b'g'))

        header_format = struct.Struct('!llq')
        tBeg, tEnd, provider_id = header_format.unpack_from(record_data)
        redir_type = bytes([(provider_id >> XROOTD_MON_PIDSHFT) & XROOTD_MON_PIDMASK])
        payloads = bytes(record_data[header_format.size: -1]).decode('ascii')  # Strip null byte at end

        try:
            payload_type = cls.payload_dispatch[redir_type]  # type: PluginRecord
        except KeyError:
            print(cls.payload_dispatch)
            raise ValueError('unknown plugin type %r' % redir_type)
        else:
            records = [payload_type.from_string(line) for line in payloads.splitlines()]
        return cls(tBeg, tEnd, records)


class Packet(object):
    """
    ``XrdXrootdMon`` packet for a map, r, t, f or g stream

    :param header: the header specifying type, ordering and size of the packet
    :param record: the actual information carried by the packet
    """
    __slots__ = ('header', 'record')
    record_dispatch = {key: Map for key in Map._payload_dispatch.keys()}  # type: Dict[bytes, PacketRecord]
    record_dispatch[b'r'] = Burr
    record_dispatch[b't'] = Buff
    record_dispatch[b'f'] = Fstat
    record_dispatch[b'g'] = Plugin

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
    def from_buffer(cls, buffer: bytes):
        """
        Extract the entire packet from the start of a stream packet buffer

        :param buffer: buffer containing a monitor stream packet
        """
        header = Header.from_buffer(buffer)
        try:
            record_type = cls.record_dispatch[header.code]  # type: PacketRecord
        except KeyError:
            raise ValueError('unknown record code %r' % header.code)
        else:
            record = record_type.from_record(memoryview(buffer)[header.size:header.plen], header.code)
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
        packet = Packet.from_buffer(packet_buffer)
        packets += 1
        # print(packet, packet.record)
        packet_buffer = packet_buffer[packet.size:]
    etime = time.time()
    print('%.1fs' % (etime - stime), '%dHz' % (packets / (etime - stime)), '%dp' % packets)
