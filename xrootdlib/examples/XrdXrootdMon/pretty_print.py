import argparse
import time
import socket

import chainlet

from xrootdlib.streams.XrdXrootdMon import stream_packets, map_streams, Packet
from xrootdlib.streams.XrdXrootdMon.map import ServerInfo, UserInfo
from xrootdlib.streams.XrdXrootdMon.redir import RedirWindow
from xrootdlib.streams.XrdXrootdMon.fstat import FstatWindow, Disconnect, Open, Close, Transfer


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


def pretty_user(user: UserInfo):
    """Format a user identifier"""
    return '{user}@{host}({pid}) [{protocol}]'.format(
        user=user.user.decode(), host=user.host.decode(), pid=user.pid, protocol=user.protocol.decode()
    )


# formatter for specific information streams
@chainlet.genlet
def print_packet(initial=1):
    """Print general information on packets"""
    count = initial
    value = yield
    assert isinstance(value, Packet)
    while True:
        print('[P%3d] %s [%5dB] #%6d' % (value.header.pseq, value.header.code.decode(), value.header.plen, count))
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
            print(' %4dF' % idx, '{:<10}'.format(type(record).__name__), record.lfn.decode() if hasattr(record, 'lfn') else '')
            print('      ', pretty_user(record.client))
    return value


@chainlet.funclet
def print_server(value):
    """Print detailed information on server identification packets"""
    if isinstance(value, ServerInfo):
        print('Server', site_id(value))
    return value


PRINT_MAP = {
    'packet': print_packet,
    'redir': print_redir,
    'fstat': print_fstat,
    'server': print_server,
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
