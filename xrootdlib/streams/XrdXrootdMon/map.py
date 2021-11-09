from typing import Dict, Tuple, Union
import threading
import weakref
import time

import chainlet

from ...structs.XrdXrootdMon import Map as MapStruct
from ...structs.XrdXrootdMon.map import UserId, SrvInfo, Path, AuthInfo
from ...utility import slot_repr


class ServerInfo(object):
    __slots__ = ('protocol', 'user', 'pid', 'sid', 'host', 'program', 'version', 'instance', 'port', 'site')

    def __init__(self, user_id: UserId, server_info: SrvInfo):
        self.protocol = user_id.prot
        self.user = user_id.user
        self.pid = user_id.pid
        self.sid = user_id.sid
        self.host = user_id.host
        self.program = server_info.pgm
        self.version = server_info.ver
        self.instance = server_info.inst
        self.port = server_info.port
        self.site = server_info.site

    __repr__ = slot_repr


class UserInfo(object):
    __slots__ = ('user_id', 'server', 'auth_info')

    @property
    def protocol(self):
        return self.user_id.prot

    @property
    def user(self):
        return self.user_id.user

    @property
    def pid(self):
        return self.user_id.pid

    @property
    def host(self):
        return self.user_id.host

    def __init__(self, user_id: UserId, server_info: ServerInfo, auth_info: AuthInfo = None):
        self.user_id = user_id
        self.server = server_info
        self.auth_info = auth_info

    __repr__ = slot_repr


class PathAccessInfo(object):
    __slots__ = ('protocol', 'user', 'pid', 'server', 'host', 'path')
    # dummy attributes in case we take the place of :py:class:`UserInfo`
    auth_info = None

    def __init__(self, user_id: UserId, server_info: ServerInfo, path_info: Path):
        self.protocol = user_id.prot
        self.user = user_id.user
        self.pid = user_id.pid
        self.server = server_info
        self.host = user_id.host
        self.path = path_info.path

    __repr__ = slot_repr


MapInfo = Union[ServerInfo, UserInfo, PathAccessInfo]


class MapInfoError(Exception):
    """An item was not in the map store"""


class MapInfoStore(object):
    def __init__(self):
        self._server_info = {}  # type: Dict[Tuple[int, int], ServerInfo]
        self._user_info = {}  # type: Dict[Tuple[int, int], UserInfo]
        self._path_info = {}  # type: Dict[Tuple[int, int], PathAccessInfo]
        # parser/converter dispatch
        self._payload_dispatch = {
            SrvInfo: self._digest_map_server,
            AuthInfo: self._digest_map_auth,
            Path: self._digest_map_path,
        }
        # information lifetime control
        self._server_lifetime = {}  # type: Dict[Tuple[bytes, int], Tuple[int, int]]
        self._cleaner = MapInfoStoreCleaner(self)

    def digest_map(self, stod: int, map_struct: MapStruct):
        """Digest map data from a packet"""
        digest_method = self._payload_dispatch[type(map_struct.payload)]
        try:
            return digest_method(stod, map_struct.dictid, map_struct.userid, map_struct.payload)
        except MapInfoError:
            raise chainlet.StopTraversal

    def _digest_map_auth(self, stod: int, dictid: int, user_id: UserId, auth_info: AuthInfo):
        server_info = self.get_server(stod, user_id.sid)
        user_info = self._user_info[stod, dictid] = UserInfo(user_id, server_info, auth_info)
        return user_info

    def _digest_map_path(self, stod: int, dictid: int, user_id: UserId, path_info: Path):
        server_info = self.get_server(stod, user_id.sid)
        path_info = self._path_info[stod, dictid] = PathAccessInfo(user_id, server_info, path_info)
        return path_info

    def _digest_map_server(self, stod: int, dictid: int, user_id: UserId, server_info: SrvInfo):
        # colliding description to replace restarting instances
        _instance_identifier = (user_id.host, server_info.port)
        try:
            deprecated_sid = self._server_lifetime[_instance_identifier]
        except KeyError:
            pass
        else:
            self._cleaner.add_deletion(self._server_info.pop, deprecated_sid, None)
        server_info = self._server_info[stod, user_id.sid] = ServerInfo(user_id, server_info)
        return server_info

    def get_user(self, stod: int, dictid: int) -> UserInfo:
        try:
            return self._user_info[stod, dictid]
        except KeyError:
            raise MapInfoError

    def free_user(self, stod: int, dictid: int) -> None:
        self._cleaner.add_deletion(self._user_info.pop, (stod, dictid), None)

    def get_path(self, stod: int, dictid: int) -> PathAccessInfo:
        try:
            return self._path_info[stod, dictid]
        except KeyError:
            raise MapInfoError

    def free_path(self, stod: int, dictid: int) -> None:
        self._cleaner.add_deletion(self._path_info.pop, (stod, dictid), None)

    def get_server(self, stod: int, sid: int) -> ServerInfo:
        try:
            return self._server_info[stod, sid]
        except KeyError:
            raise MapInfoError


class MapInfoStoreCleaner(threading.Thread):
    def __init__(self, store: MapInfoStore, clean_delay: int = 30):
        super().__init__()
        self._clean_delay = clean_delay
        self._deletion_queue = []
        # weak ref to shut us down when the parent is gone
        self._parent_store = weakref.ref(store)
        self.daemon = True
        self.start()

    def run(self):
        parent_ref = self._parent_store
        while parent_ref() is not None:
            terminate_at = time.time() + self._clean_delay
            # swap the queue and wait to avoid mutation
            self._deletion_queue, deletion_queue = [], self._deletion_queue
            time.sleep(0.1)
            for instruction, args, kwargs in deletion_queue:
                instruction(*args, **kwargs)
            try:
                time.sleep(terminate_at - time.time())
            except ValueError:  # negative sleep time because we took too long
                continue

    def add_deletion(self, instruction, *args, **kwargs):
        self._deletion_queue.append((instruction, args, kwargs))
