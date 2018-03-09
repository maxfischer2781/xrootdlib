import weakref
from collections import deque
from typing import AnyStr, Dict


def parse_cgi(cgi_data: AnyStr) -> Dict[AnyStr, AnyStr]:
    """
    Parse cgi data in the form ``&key1=value1&key2=value2`` to a mapping

    :param cgi_data: raw CGI data in as unicode or bytes
    :return: a mapping from keys to values

    Note that this does not perform any implicit type conversions:
    keys and values have the same type as ``cgi_data``.
    For example, a value of ``b'1'`` is not converted to the integer ``1``.

    .. code:: python

        >>> parse_cgi(b'&foo=1')
        {b'foo': b'1'}
    """
    amp, equ = ('&', '=') if isinstance(cgi_data, str) else (b'&', b'=')
    data = {}
    for key_value in cgi_data.split(amp):
        if key_value:
            key, value = key_value.split(equ)
            data[key] = value
    return data


def verbose_repr(self):
    return '{slf.__class__.__name__}({attrs})'.format(
        slf=self, attrs=', '.join((attr + '=' + repr(getattr(self, attr))) for attr in self.__slots__)
    )


def field_repr(self):
    return '{slf.__class__.__name__}({attrs})'.format(
        slf=self, attrs=', '.join(repr(getattr(self, attr)) for attr in self.__slots__)
    )
