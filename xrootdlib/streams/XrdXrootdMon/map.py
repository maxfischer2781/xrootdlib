from typing import Dict, Tuple, Union, Optional
import threading
import weakref
import time

import chainlet

from ...structs.XrdXrootdMon import Map as MapStruct
from ...structs.XrdXrootdMon.map import UserId, SrvInfo, Path, AuthInfo
from ...utility import slot_repr


class ServerInfo(object):
    __slots__ = ('protocol', 'user', 'pid', 'sid', 'host', 'program', 'version', 'instance', 'port', 'site', 'stod')

    def __init__(self, user_id: UserId, server_info: SrvInfo, stod: int):
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
        self.stod = stod

    __repr__ = slot_repr


class UserInfo(object):
    __slots__ = ('client', 'server', 'auth_info')

    @property
    def protocol(self):
        return self.client.prot

    @property
    def user(self):
        return self.client.user

    @property
    def pid(self):
        return self.client.pid

    @property
    def host(self):
        return self.client.host

    def __init__(self, client: UserId, server_info: ServerInfo, auth_info: Optional[AuthInfo] = None):
        self.client = client
        self.server = server_info
        self.auth_info = auth_info

    __repr__ = slot_repr


class PathAccessInfo(object):
    """
    Metadata of a ``client`` accessing a ``path`` on a ``server``

    Depending on the monitoring settings, ``client`` and ``auth`` may be unavailable
    and just :py:data:`None`.
    """
    __slots__ = ('client', 'server', 'path', 'auth')

    @property
    def protocol(self):
        return self.client.prot if self.client is not None else None

    @property
    def user(self):
        return self.client.user if self.client is not None else None

    @property
    def pid(self):
        return self.client.pid if self.client is not None else None

    @property
    def host(self):
        return self.client.host if self.client is not None else None

    def __init__(self, client: Optional[UserId], server: ServerInfo, path: bytes, auth: Optional[AuthInfo] = None):
        self.client = client
        self.server = server
        self.path = path
        self.auth = auth

    __repr__ = slot_repr


MapInfo = Union[ServerInfo, UserInfo, PathAccessInfo]


class MapInfoError(Exception):
    """An item was not in the map store"""


class MapInfoStore(object):
    def __init__(self):
        self._server_info: Dict[Tuple[int, int], ServerInfo] = {}
        self._user_info: Dict[Tuple[int, int], UserInfo] = {}
        self._access_info: Dict[Tuple[int, int], PathAccessInfo] = {}
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

    def _digest_map_path(self, stod: int, dictid: int, user_id: UserId, path_info: Path) -> PathAccessInfo:
        server_info = self.get_server(stod, user_id.sid)
        item = self._access_info[stod, dictid] = PathAccessInfo(user_id, server_info, path_info.path)
        return item

    def _digest_map_server(self, stod: int, dictid: int, user_id: UserId, server_info: SrvInfo):
        # colliding description to replace restarting instances
        _instance_identifier = (user_id.host, server_info.port)
        try:
            deprecated_sid = self._server_lifetime[_instance_identifier]
        except KeyError:
            pass
        else:
            self._cleaner.add_deletion(self._server_info.pop, deprecated_sid, None)
        server_info = self._server_info[stod, user_id.sid] = ServerInfo(user_id, server_info, stod)
        return server_info

    def get_user(self, stod: int, dictid: int) -> UserInfo:
        try:
            return self._user_info[stod, dictid]
        except KeyError:
            raise MapInfoError

    def free_user(self, stod: int, dictid: int) -> None:
        self._cleaner.add_deletion(self._user_info.pop, (stod, dictid), None)

    def set_access(self, server: ServerInfo, dictid: int, userid: int, path: bytes) -> PathAccessInfo:
        """Add a file access info based on raw references (i.e. FStat Open with LFN)"""
        if userid > 0:
            user = self.get_user(server.stod, userid)
            client, auth = user.client, user.auth_info
        else:
            client, auth = None, None
        item = self._access_info[server.stod, dictid] = PathAccessInfo(client, server, path, auth)
        return item

    def get_access(self, stod: int, dictid: int) -> PathAccessInfo:
        try:
            return self._access_info[stod, dictid]
        except KeyError:
            raise MapInfoError

    def free_access(self, stod: int, dictid: int) -> None:
        self._cleaner.add_deletion(self._access_info.pop, (stod, dictid), None)

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
