from typing import Union
import argparse
import time
import socket
import collections

import chainlet

from xrootdlib.streams.XrdXrootdMon import stream_packets, map_streams, Packet, PluginStruct
from xrootdlib.structs.XrdXrootdMon.plugin import ProxyCache
from xrootdlib.streams.XrdXrootdMon.map import ServerInfo, UserInfo, PathAccessInfo
from xrootdlib.streams.XrdXrootdMon.redir import RedirWindow
from xrootdlib.streams.XrdXrootdMon.fstat import FstatWindow, Transfer
from xrootdlib.streams.XrdXrootdMon.trace import TraceWindow


def readable_source(source: str):
    """
    Convert ``source`` to an object supporting ``.read(buffer_size)``

    Supports the following sources:

    * udp IPv4 address [``hostname:port``]
    * file system path
    """
    try:
        host, port = source.split(':')
    except ValueError:
        return open(source, 'rb')
    else:
        udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        udp_socket.bind((host, int(port)))
        # XRootD monitor packets are AT MOST 64kb in size
        return udp_socket.makefile(mode='rb', buffering=64*1024)


# formatting helpers for individual information pieces
def timerange(start: int, end: int):
    """Format a timerange indicated by a ``start`` and ``end`` timestamp"""
    return '%s %s-%s' % (
        time.strftime('%Y-%m-%d', time.localtime(start)),
        time.strftime('%H:%M:%S', time.localtime(start)),
        time.strftime('%H:%M:%S', time.localtime(end))
    )


def site_id(server: ServerInfo):
    """Format a server identifier"""
    return '{site} via {instance}@{host}:{port}'.format(
        site=server.site.decode(), host=server.host.decode(),
        port=server.port, instance=server.instance.decode()
    )


def pretty_user(user: Union[UserInfo, PathAccessInfo]):
    """Format a user identifier"""
    def decode(raw) -> str:
        return raw.decode() if raw is not None else "<unknown>"

    return '{user}@{host}({pid}) [{protocol}]'.format(
        user=decode(user.user), host=decode(user.host), pid=user.pid, protocol=decode(user.protocol)
    )


# formatter for specific information streams
@chainlet.genlet
def print_packet(initial=1):
    """Print general information on packets"""
    count = initial
    code_map = {
        b'=': 'SrvInfo',
        b'd': 'Path',
        b'i': 'AppInfo',
        b'p': 'PrgInfo',
        b'u': 'AuthInfo',
        b'x': 'XfrInfo',
        b'r': 'Burr',
        b't': 'Buff',
        b'f': 'Fstat',
        b'g': 'Plugin',
    }
    value = yield
    assert isinstance(value, Packet)
    while True:
        print('[P%3d] %s [%5dB] #%6d "%s"' % (
            value.header.pseq, value.header.code.decode(), value.header.plen, count,
            code_map[value.header.code]
        ))
        value = yield value
        count += 1


@chainlet.funclet
def print_redir(value):
    """Print detailed information on redirection packets"""
    if isinstance(value, RedirWindow):
        print('Redir:', site_id(value.server_info), '[%s]' % timerange(value.start, value.end))
        for idx, record in enumerate(value.records):
            print(' %4dR' % idx, record.action.name,
                  '%s:%s/%s' % (record.target.decode(), record.port, record.path.decode()))
            print('      ', pretty_user(record.client))
    return value


@chainlet.funclet
def print_fstat(value):
    """Print detailed information on file statistics packets"""
    if isinstance(value, FstatWindow):
        print('FStat:', site_id(value.server_info), '[%s]' % timerange(value.start, value.end))
        for idx, record in enumerate(value.records):
            if type(record) == Transfer:
                continue
            print(' %4dF' % idx, '{:<10}'.format(type(record).__name__), getattr(record, 'lfn', b'').decode())
            print('      ', pretty_user(record.client))
    return value


@chainlet.funclet
def print_fstat_sum(value):
    """Print summary information on file statistics packets"""
    if isinstance(value, FstatWindow):
        print('FStat:', site_id(value.server_info), '[%s]' % timerange(value.start, value.end))
        counts = collections.Counter(type(record).__name__ for record in value.records)
        print(
            ' %4d Total' % sum(counts.values()),
            *('%4d %s' % (count, name) for name, count in sorted(counts.items()))
        )
    return value


@chainlet.funclet
def print_trace_sum(value):
    """Print summary information on file access trace packets"""
    if isinstance(value, TraceWindow):
        print('Trace:', site_id(value.server_info), '[%s]' % timerange(value.start, value.end))
        counts = collections.Counter(type(record).__name__ for record in value.records)
        print(
            ' %4d Total' % sum(counts.values()),
            *('%4d %s' % (count, name) for name, count in sorted(counts.items()))
        )
    return value


@chainlet.funclet
def print_server(value):
    """Print detailed information on server identification packets"""
    if isinstance(value, ServerInfo):
        print('Server', site_id(value))
    return value

@chainlet.funclet
def print_cache(value):
    """
    Print some of the information from packets sent by cache plugin.
    Other plugins are not yet supported.
    """
    if isinstance(value, PluginStruct):
        if type(value.records[0]) == ProxyCache:
            for idx, record in enumerate(value.records):
                print(' %4dF' % idx, '{:<10}'.format(type(record).__name__), getattr(record, 'lfn', b''))
                print(' Access count: {:}'.format(record.access_cnt))
    return value


PRINT_MAP = {
    'packet': print_packet,
    'redir': print_redir,
    'fstat': print_fstat,
    'fstats': print_fstat_sum,
    'traces': print_trace_sum,
    'server': print_server,
    'plugin': print_cache
}


def print_type(identifier: str):
    try:
        printer = PRINT_MAP[identifier]
    except KeyError:
        raise argparse.ArgumentTypeError(
            "unknown information type '%s' (expected any of '%s')" % (identifier, "', '".join(PRINT_MAP))
        )
    else:
        return printer()


# command line interface
CLI = argparse.ArgumentParser(description="Pretty-print xrd.monitor stream")
CLI.add_argument(
    'SOURCE',
    help='file system path or UDP IPv4 "address:port" to xrd.monitor stream',
    type=readable_source
)
CLI.add_argument(
    'WHAT',
    help='the information to print from the stream',
    nargs='*',
    type=print_type,
    default=[printer() for printer in PRINT_MAP.values()],
)


if __name__ == '__main__':
    options = CLI.parse_args()
    with options.SOURCE as packet_stream:
        chain = stream_packets(packet_stream)
        # operations on raw packets
        for what in (elem for elem in options.WHAT if isinstance(elem, print_packet)):
            chain >>= what
        chain >>= map_streams()
        # operations on mapped records
        for what in (elem for elem in options.WHAT if not isinstance(elem, print_packet)):
                chain >>= what
        for result in chain:
            pass
