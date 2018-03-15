from typing import List

import chainlet

from ...structs.XrdXrootdMon import Burr as BurrStruct
from ...structs.XrdXrootdMon.redir import XROOTD_MON, \
    Redirect as RedirectStruct, WindowMark as WindowMarkStruct
from .map import MapInfoStore, MapInfoError, ServerInfo, UserInfo
from ...utility import slot_repr


Action = XROOTD_MON


class Redirection(object):
    __slots__ = ('action', 'target', 'port', 'client', 'path')

    def __init__(self, action: Action, target: bytes, port: int, client: UserInfo, path: bytes):
        self.action, self.target, self.port, self.client, self.path = action, target, port, client, path

    @classmethod
    def from_record(cls, record_struct: RedirectStruct, stod: int, map_store: MapInfoStore):
        assert cls != Redirection, 'only derived classes allowed for Redirection events'
        client = map_store.get_user(stod, record_struct.dictid)
        return cls(record_struct.subtype, record_struct.server, record_struct.port, client, record_struct.path)

    __repr__ = slot_repr


class XrootdRedir(Redirection):
    pass


class CmsdRedir(Redirection):
    pass


class RedirWindow(object):
    """Sequence of events in a time window"""
    __slots__ = ('server_info', 'start', 'end', 'records')

    def __init__(self, server_info: ServerInfo, start: int, end: int, records: List[Redirection]):
        self.server_info = server_info
        self.start = start
        self.end = end
        self.records = records

    def __repr__(self):
        return '<%s, start=%d, end=%d, record_size=%d, server=%s>' % (
            self.__class__.__name__, self.start, self.end, len(self.records), self.server_info
        )


convert_record_dispatch = {
    XROOTD_MON.REDIRECT: CmsdRedir.from_record,
    XROOTD_MON.REDLOCAL: XrootdRedir.from_record,
}


def digest_packet(stod: int, burr_struct: BurrStruct, map_store: MapInfoStore):
    """Digest a packet containing redir data"""
    try:
        server_info = map_store.get_server(stod, burr_struct.sid.sid)
    except KeyError:
        raise chainlet.StopTraversal
    record_iter = iter(burr_struct.records)
    this_window = next(record_iter)
    assert isinstance(this_window, WindowMarkStruct), \
        'second element of Burr packet must be a Window Mark, not %s' % type(this_window)
    records = []
    for record_struct in record_iter:
        try:
            converter = convert_record_dispatch[record_struct.type]
        except KeyError:
            assert isinstance(record_struct, WindowMarkStruct), \
                'separating element of Burr packet must be a Window Mark, not %s' % type(record_struct)
            if records:
                yield RedirWindow(
                    server_info, this_window.timestamp, this_window.timestamp + record_struct.prev_duration, records
                )
            this_window, records = record_struct, []
        else:
            try:
                record = converter(record_struct, stod, map_store)
            except MapInfoError:
                continue
            else:
                records.append(record)
    assert not records, 'no dangling records allowed after last Window Mark'
