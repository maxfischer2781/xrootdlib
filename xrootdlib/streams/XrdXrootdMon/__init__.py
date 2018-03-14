"""
Stream of the XrdXrootdMon monitoring messages

This module presents a high-level stream representation of the :py:mod:`~xrootdlib.structs.XrdXrootdMon`
``struct`` primitives.
It provides two stream mechanisms of different complexity:

* :py:class:`~.packet_streamer` provides an ordered stream of raw :py:class:`~.Packet`
* :py:class:`~.MappedStream` provides a stream of
  :py:mod:`~.fstat`, :py:mod:`~.redir`, :py:mod:`~.trace`, and :py:mod:`~.map`
"""
import io
from typing import List, Tuple, IO

import chainlet

from ...structs.XrdXrootdMon import Packet,\
    Header as HeaderStruct, Map as MapStruct, Fstat as FstatStruct, Buff as BuffStruct, Burr as BurrStruct

from .utility import packet_from_buffer, PSeq
from .map import MapInfoStore
from .fstat import digest_packet as digest_fstat_packet
from .trace import digest_packet as digest_trace_packet
from .redir import digest_packet as digest_redir_packet

__all__ = ['packet_streamer', 'MappedStream']


@chainlet.genlet(prime=False)
def packet_streamer(packet_source: IO[bytes], sort_window: int=8):
    """
    Provide a stream of packets from a readable bytes buffer

    :param packet_source: a bytes buffer providing serialised packet data
    :param sort_window: window size in which to sort packets by their assigned order

    The ``packet_source`` may be any bytes buffer supporting ``read`` operations.
    This can be an open file, but also a socket or wrapped memory.
    While the buffer may be extended indefinitely, it should *always* contain complete packets.

    The ``sort_window`` is required to ensure ordering of the packet data.
    Since XRootD uses several packet buffers, concurrent packets may arrive in arbitrary order.
    To remove this ambiguity, ``sort_window`` packets are buffered and provided in order.

    Note that an ideal ``sort_window`` corresponds to the *number* of out-of-order packets.
    It is *not* to the maximum difference in ordering of each packet.
    """
    assert sort_window > 0, 'sort_window must not be empty'
    assert sort_window < 128, 'sort_window must be smaller than half of packet sequence range'
    buffer = []  # type: List[Tuple[Packet, PSeq]]
    while len(buffer) < sort_window:
        packet = packet_from_buffer(packet_source)
        buffer.append((packet, PSeq(packet.header.pseq)))
    while True:
        buffer.sort(key=lambda packet_pseq: packet_pseq[1], reverse=True)
        yield buffer.pop(-1)[0]
        packet = packet_from_buffer(packet_source)
        buffer.append((packet, PSeq(packet.header.pseq)))


class MappedStream(chainlet.ChainLink):
    """
    Provides a high-level representation of monitoring packets, resolving dependencies

    This provides a :py:mod:`chainlet` stream of primitives corresponding to monitoring records.
    The stream multiplexes up to four types of monitoring streams:

    :py:mod:`~.fstat` - sequence of :py:class:`~.fstat.FstatWindow`
        High level file operations, namely open, close, transfer and disconnects.

    :py:mod:`~.redir` - sequence of :py:class:`~.redir.RedirWindow`
        Client redirection for all high-level actions, such as read, write, move, chmod, etc.

    :py:mod:`~.trace` - sequence of :py:class:`~.trace.TraceWindow`
        Low level file operations, including individual read/write requests.

    :py:mod:`~.map` - individual :py:class:`~.map.MapInfo`
        High level information on servers, clients and paths.
        This information is automatically inserted into appropriate records of the sequence streams.
    """
    chain_fork = True

    def __init__(self):
        self.map_store = MapInfoStore()
        self._packet_dispatch = {
            MapStruct: self._process_map,
            FstatStruct: self._process_fstat,
            BuffStruct: self._process_trace,
            BurrStruct: self._process_redir,
        }

    def chainlet_send(self, value: Packet=None):
        processor = self._packet_dispatch[type(value.record)]
        return processor(value.header, value.record)

    def _process_map(self, header: HeaderStruct, map_struct: MapStruct):
        yield self.map_store.digest_map(header.stod, map_struct)

    def _process_fstat(self, header: HeaderStruct, map_struct: FstatStruct):
        yield digest_fstat_packet(header, map_struct, self.map_store)

    def _process_trace(self, header: HeaderStruct, trace_struct: BuffStruct):
        yield from digest_trace_packet(header, trace_struct, self.map_store)

    def _process_redir(self, header: HeaderStruct, map_struct: BurrStruct):
        yield from digest_redir_packet(header, map_struct, self.map_store)


if __name__ == '__main__':
    import sys
    if len(sys.argv) != 2:
        raise SystemExit("test with 'python3 -m %s <monitor dump file>'" % __package__)
    packet_path = sys.argv[1]
    with open(packet_path, 'rb') as packet_stream:
        chain = packet_streamer(packet_stream) >> MappedStream()
        for result in chain:
            if result is not None:
                print(result)
