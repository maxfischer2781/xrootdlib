from typing import List, Union

import chainlet

from ...structs.XrdXrootdMon import Header as HeaderStruct, Buff as BuffStruct
from ...structs.XrdXrootdMon.trace import XROOTD_MON, \
    Window as WindowStruct, Close as CloseStruct, Disc as DiscStruct, Open as OpenStruct
from .map import MapInfoStore, MapInfoError, ServerInfo, UserInfo, PathAccessInfo
from ...utility import slot_repr


class Disconnect(object):
    """A client disconnected from the server"""
    __slots__ = ('client', 'duration', 'forced')

    def __init__(self, client: UserInfo, duration: int, forced: bool):
        self.client, self.duration, self.forced = client, duration, forced

    @classmethod
    def from_record(cls, record_struct: DiscStruct, stod: int, map_store: MapInfoStore):
        client = map_store.get_user(stod, record_struct.dictid)
        map_store.free_user(stod, record_struct.dictid)
        return cls(client, record_struct.buflen, record_struct.flags & XROOTD_MON.FORCED)

    __repr__ = slot_repr


class Open(object):
    """A client opened a file"""
    __slots__ = ('user', 'lfn', 'filesize')

    def __init__(self, user: Union[UserInfo, PathAccessInfo], lfn: bytes, filesize: int):
        self.filesize, self.user, self.lfn = filesize, user, lfn

    @classmethod
    def from_record(cls, record_struct: OpenStruct, stod: int, map_store: MapInfoStore):
        path_info = map_store.get_path(stod, record_struct.dictid)
        return cls(path_info, path_info.path, record_struct.filesize)

    __repr__ = slot_repr


class Close(object):
    """A client closed a file"""
    __slots__ = ('user', 'lfn', 'rtot', 'wtot')

    def __init__(self, user: Union[UserInfo, PathAccessInfo], lfn: bytes, rtot: int, wtot: int):
        self.user, self.lfn, self.rtot, self.wtot = user, lfn, rtot, wtot

    @classmethod
    def from_record(cls, record_struct: CloseStruct, stod: int, map_store: MapInfoStore):
        path_info = map_store.get_path(stod, record_struct.dictid)
        map_store.free_path(stod, record_struct.dictid)
        return cls(path_info, path_info.path, record_struct.rtot, record_struct.wtot)

    __repr__ = slot_repr


class TraceWindow(object):
    """Sequence of events in a time window"""
    __slots__ = ('server_info', 'start', 'end', 'records')

    def __init__(self, server_info: ServerInfo, start: int, end: int, records: List):
        self.server_info = server_info
        self.start = start
        self.end = end
        self.records = records

    def __repr__(self):
        return '<%s, start=%d, end=%d, record_size=%d, server=%s>' % (
            self.__class__.__name__, self.start, self.end, len(self.records), self.server_info
        )


convert_record_dispatch = {
    CloseStruct: Close.from_record,
    OpenStruct: Open.from_record,
    DiscStruct: Disconnect.from_record,
}


def digest_packet(header: HeaderStruct, buff_struct: BuffStruct, map_store: MapInfoStore):
    stod = header.stod
    record_iter = iter(buff_struct.records)
    this_window = next(record_iter)
    assert isinstance(this_window, WindowStruct), \
        'first element of Buff packet must be a Window Mark, not %s' % type(this_window)
    try:
        server_info = map_store.get_server(header.stod, this_window.sid)
    except KeyError:
        raise chainlet.StopTraversal
    records = []
    for record_struct in record_iter:
        try:
            converter = convert_record_dispatch[type(record_struct)]
        except KeyError:
            assert isinstance(record_struct, WindowStruct), \
                'separating element of Buff packet must be a Window Mark, not %s' % type(record_struct)
            if records:
                yield TraceWindow(server_info, this_window.start, record_struct.end, records)
            this_window, records = record_struct, []
        else:
            try:
                record = converter(record_struct, stod, map_store)
            except MapInfoError:
                continue
            else:
                records.append(record)
    assert not records, 'no dangling records allowed after last Window Mark'
