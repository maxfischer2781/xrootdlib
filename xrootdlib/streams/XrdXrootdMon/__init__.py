from typing import Dict, Tuple
import io
import struct

import chainlet

from ...structs.XrdXrootdMon import Packet,\
    Header as HeaderStruct, Map as MapStruct, Fstat as FstatStruct, Buff as BuffStruct, Burr as BurrStruct

from .map import MapInfoStore
from .fstat import digest_packet as digest_fstat_packet
from .trace import digest_packet as digest_trace_packet
from .redir import digest_packet as digest_redir_packet


def packet_from_buffer(packet_source: io.BufferedReader):
    try:
        header_data = packet_source.read(HeaderStruct.size)
        header = HeaderStruct.from_buffer(header_data)
    except struct.error:
        raise StopIteration
    else:
        return Packet.from_buffer(header_data + packet_source.read(header.plen - header.size))


@chainlet.genlet(prime=False)
def packet_receiver(packet_source: io.BufferedReader, buffer_length=4):
    buffer = []
    while len(buffer) < buffer_length:
        buffer.append(packet_from_buffer(packet_source))
    while True:
        buffer.sort(key=lambda packet: packet.header.pseq, reverse=True)
        yield buffer.pop(-1)
        buffer.append(packet_from_buffer(packet_source))


class MappedStream(chainlet.ChainLink):
    chain_fork = True

    def __init__(self):
        self.map_store = MapInfoStore()
        self._packet_dispatch = {
            MapStruct: self.process_map,
            FstatStruct: self.process_fstat,
            BuffStruct: self.process_trace,
            BurrStruct: self.process_redir,
        }

    def chainlet_send(self, value: Packet=None):
        processor = self._packet_dispatch[type(value.record)]
        return processor(value.header, value.record)

    def process_map(self, header: HeaderStruct, map_struct: MapStruct):
        yield self.map_store.digest_map(header.stod, map_struct)

    def process_fstat(self, header: HeaderStruct, map_struct: FstatStruct):
        yield digest_fstat_packet(header, map_struct, self.map_store)

    def process_trace(self, header: HeaderStruct, trace_struct: BuffStruct):
        yield from digest_trace_packet(header, trace_struct, self.map_store)

    def process_redir(self, header: HeaderStruct, map_struct: BurrStruct):
        yield from digest_redir_packet(header, map_struct, self.map_store)


if __name__ == '__main__':
    import sys
    if len(sys.argv) != 2:
        raise SystemExit("test with 'python3 -m %s <monitor dump file>'" % __package__)
    packet_path = sys.argv[1]
    with open(packet_path, 'rb') as packet_stream:
        chain = packet_receiver(packet_stream) >> MappedStream()
        for result in chain:
            if result is not None:
                print(result)
