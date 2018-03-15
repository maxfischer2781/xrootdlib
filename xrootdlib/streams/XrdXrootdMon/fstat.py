import chainlet
from typing import List, Union

from ...structs.XrdXrootdMon import Fstat as FstatStruct
from ...structs.XrdXrootdMon.fstat import recFval, FileDSC, FileOPN, FileCLS, FileXFR

from .map import MapInfoStore, MapInfoError, ServerInfo, UserInfo, PathAccessInfo


class Disconnect(object):
    """A client disconnected from the server"""
    __slots__ = ('client',)

    def __init__(self, client: UserInfo):
        self.client = client

    @classmethod
    def from_record(cls, record_struct: FileDSC, stod: int, map_store: MapInfoStore):
        client = map_store.get_user(stod, record_struct.dictid)
        map_store.free_user(stod, record_struct.dictid)
        return cls(client)


class Open(object):
    """A client opened a file"""
    __slots__ = ('client', 'lfn', 'readwrite', 'filesize')

    def __init__(self, client: Union[UserInfo, PathAccessInfo], lfn: bytes, readwrite: bool, filesize: int):
        self.readwrite, self.filesize, self.client, self.lfn = readwrite, filesize, client, lfn

    @classmethod
    def from_record(cls, record_struct: FileOPN, stod: int, map_store: MapInfoStore):
        read_write = bool(record_struct.flags & recFval.hasRW)
        if record_struct.user is not None:
            client = map_store.get_user(stod, record_struct.user)
            return cls(client, record_struct.lfn, read_write, record_struct.filesize)
        else:
            path_info = map_store.get_path(stod, record_struct.fileid)
            return cls(path_info, path_info.path, read_write, record_struct.filesize)


class Close(object):
    """A client closed a file"""
    __slots__ = ('client', 'lfn', 'stats')

    def __init__(self, client: Union[UserInfo, PathAccessInfo], lfn: bytes, stats: FileCLS):
        self.client, self.lfn, self.stats = client, lfn, stats

    @classmethod
    def from_record(cls, record_struct: FileCLS, stod: int, map_store: MapInfoStore):
        path_info = map_store.get_path(stod, record_struct.fileid)
        map_store.free_path(stod, record_struct.fileid)
        return cls(path_info, path_info.path, record_struct)


class Transfer(object):
    """A client transfered a file"""
    __slots__ = ('client', 'lfn', 'stats')

    def __init__(self, client: Union[UserInfo, PathAccessInfo], lfn: bytes, stats: FileXFR):
        self.client, self.lfn, self.stats = client, lfn, stats

    @classmethod
    def from_record(cls, record_struct: FileXFR, stod: int, map_store: MapInfoStore):
        path_info = map_store.get_path(stod, record_struct.fileid)
        map_store.free_path(stod, record_struct.fileid)
        return cls(path_info, path_info.path, record_struct)


class FstatWindow(object):
    """Sequence of Open, Close and Disconnect events in a time window"""
    __slots__ = ('server_info', 'start', 'end', 'records')

    def __init__(self, server_info: ServerInfo, start: int, end: int, records: List[Union[Disconnect, Open, Close, Transfer]]):
        self.server_info = server_info
        self.start = start
        self.end = end
        self.records = records

    def __repr__(self):
        return '<%s, start=%d, end=%d, records=%d, server=%s>' % (
            self.__class__.__name__, self.start, self.end, len(self.records), self.server_info
        )


convert_record_dispatch = {
    FileDSC: Disconnect.from_record,
    FileOPN: Open.from_record,
    FileCLS: Close.from_record,
    FileXFR: Transfer.from_record,
}


def digest_packet(stod: int, fstat_struct: FstatStruct, map_store: MapInfoStore):
    """Digest a packet containing fstat data"""
    try:
        server_info = map_store.get_server(stod, fstat_struct.tod.sid)
    except MapInfoError:
        raise chainlet.StopTraversal
    records = []
    for record_struct in fstat_struct.records:
        converter = convert_record_dispatch[type(record_struct)]
        try:
            record = converter(record_struct, stod, map_store)
        except MapInfoError:
            continue
        records.append(record)
    if not records:
        raise chainlet.StopTraversal
    return FstatWindow(server_info, fstat_struct.start, fstat_struct.end, records)
