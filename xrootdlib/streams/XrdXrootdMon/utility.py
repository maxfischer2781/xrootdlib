from typing import IO
import struct

from xrootdlib.structs.XrdXrootdMon import Header as HeaderStruct, Packet


class PacketBufferExhausted(Exception):
    """The buffer of packet data is exhausted"""


def packet_from_buffer(packet_source: IO[bytes]):
    """Read a packet from a bytes buffer"""
    try:
        header_data = packet_source.read(HeaderStruct.size)
        header = HeaderStruct.from_buffer(header_data)
    except struct.error:
        raise PacketBufferExhausted
    else:
        return Packet.from_buffer(header_data + packet_source.read(header.plen - header.size))


class PSeq(object):
    """
    Sortable *Packet Sequence*, an Integer from a wrapping (0, 255) range

    :param pseq: the ``pseq`` of a packet

    This represents the XRootD Packet Sequence for the purpose of comparisons.
    It ensures that comparisons respects wrapping from 255 to 0.
    In effect, a high-valued PSeq compares *less than* a low-valued PSeq.

    :warning: This class does not implement a full Integer interface.
    """
    __slots__ = ('_value',)

    def __init__(self, pseq: int):
        assert 0 <= pseq <= 255, 'pseq must be an Integer from 0 to 255'
        self._value = pseq

    def __eq__(self, other: 'PSeq') -> bool:
        return self._value == other._value

    def __ne__(self, other: 'PSeq') -> bool:
        return not self == other

    def __gt__(self, other: 'PSeq') -> bool:
        if self._value < 64 and other._value >= 191:
            return True
        elif other._value < 64 and self._value >= 191:
            return False
        return self._value > other._value

    # Note:
    # - Python guarantees to use __lt__ for sorting
    # - PSeq is intended for DESCENDING orrdering
    # - the likely test case is `small < large`
    # - __lt__ should be optimised for `self < other` tests
    def __lt__(self, other: 'PSeq') -> bool:
        if other._value < 64 and self._value >= 191:
            return True
        elif self._value >= 64 or other._value < 191:
            return self._value < other._value
        return False

    def __ge__(self, other: 'PSeq') -> bool:
        return self == other or self > other

    def __le__(self, other: 'PSeq') -> bool:
        return self == other or self < other

    def __repr__(self):
        return '<packet sequence %s>' % self._value

    def __str__(self):
        return str(self._value)

    def __int__(self):
        return self._value
