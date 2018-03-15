import argparse
import time
import socket

import chainlet

from xrootdlib.streams.XrdXrootdMon import stream_packets, map_streams
from xrootdlib.streams.XrdXrootdMon.map import ServerInfo, UserInfo
from xrootdlib.streams.XrdXrootdMon.redir import RedirWindow
from xrootdlib.streams.XrdXrootdMon.fstat import FstatWindow, Disconnect, Open, Close, Transfer


def readable_source(source: str):
    try:
        host, port = source.split(':')
    except ValueError:
        return open(source, 'rb')
    else:
        udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        udp_socket.bind((host, int(port)))
        return udp_socket.makefile(mode='rb')


CLI = argparse.ArgumentParser("Pretty-print xrd.monitor stream from files or UDP")
CLI.add_argument('SOURCE', help='path or address to xrd.monitor stream', type=readable_source)


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


if __name__ == '__main__':
    options = CLI.parse_args()
    with options.SOURCE as packet_stream:
        chain = stream_packets(packet_stream) >> map_streams() >> print_redir() >> print_fstat()
        for result in chain:
            pass
