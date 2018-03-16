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


CLI = argparse.ArgumentParser("Pretty-print xrd.monitor stream")
CLI.add_argument('SOURCE', help='file system path or UDP IPv4 address:port to xrd.monitor stream', type=readable_source)


# formatting helpers for individual information pieces
def timerange(start: int, end: int):
    return '%s %s-%s' % (
        time.strftime('%Y-%m-%d', time.localtime(start)),
        time.strftime('%H:%M:%S', time.localtime(start)),
        time.strftime('%H:%M:%S', time.localtime(end))
    )


def site_id(server: ServerInfo):
    return '{site} via {instance}@{host}:{port}'.format(
        site=server.site.decode(), host=server.host.decode(),
        port=server.port, instance=server.instance.decode()
    )


def pretty_user(user: UserInfo):
    return '{user}@{host}({pid}) [{protocol}]'.format(
        user=user.user.decode(), host=user.host.decode(), pid=user.pid, protocol=user.protocol.decode()
    )


# formatter for specific information streams
@chainlet.genlet
def print_packet(initial=1):
    count = initial
    value = yield
    assert isinstance(value, Packet)
    while True:
        print('Packet %3d [%6d]' % (value.header.pseq, count))
        value = yield value
        count += 1


@chainlet.funclet
def print_redir(value):
    if isinstance(value, RedirWindow):
        print('Redir:', site_id(value.server_info), '[%s]' % timerange(value.start, value.end))
        for idx, record in enumerate(value.records):
            print('  %3d:' % idx, record.action.name,
                  '%s:%s/%s' % (record.target.decode(), record.port, record.path.decode()))
            print('      ', pretty_user(record.client))
    return value


@chainlet.funclet
def print_fstat(value):
    if isinstance(value, FstatWindow):
        print('FStat:', site_id(value.server_info), '[%s]' % timerange(value.start, value.end))
        for idx, record in enumerate(value.records):
            if type(record) == Transfer:
                continue
            print('  %3d:' % idx, '{:<10}'.format(type(record).__name__), record.lfn.decode() if hasattr(record, 'lfn') else '')
            print('      ', pretty_user(record.client))
    return value


@chainlet.funclet
def print_server(value):
    if isinstance(value, ServerInfo):
        print('Server', site_id(value))
    return value


if __name__ == '__main__':
    options = CLI.parse_args()
    with options.SOURCE as packet_stream:
        chain = stream_packets(packet_stream) >> print_packet() >> map_streams() >> print_server() >> print_redir() >> print_fstat()
        for result in chain:
            pass
