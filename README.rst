============================================================
``xrootdlib`` - Tools for working with the XRootD middleware
============================================================

The ``xrootdlib`` offers building blocks and basic tools to work with the XRootD_ data access middleware.
It is meant to facilitate auxiliary work, such as monitoring, accounting and orchestration.

Package Overview
----------------

``xrootdlib.streams``
    Stream-like converter, reader and representations for various XRootD information sources.
    Each stream produces a pre-processed representation of information,
    which directly exposes all relevant information.

``xrootdlib.structs``
    Representations of various ``struct`` used by XRootD to provide or digest data.
    Each data structure exposes both a flat, high-performance Python interface
    as well as views replicating the ``struct`` interface.
    Data structures support the conversion to and from raw bytes.

    ``xrootdlib.structs.XrdXrootdMon``
        Structs used for the *Detailed Monitoring Data Format* streams sent by servers.
        See the ``all.monitor`` directive and `XRootD Monitoring`_ for details.

Compatibility
-------------

This package requires Python 3.4 or newer.
It is tested with CPython (aka ``python3``) and PyPy (aka ``pypy3``).

.. _XRootD: http://xrootd.org

.. _XRootD Monitoring: http://xrootd.org/doc/dev44/xrd_monitoring.htm
