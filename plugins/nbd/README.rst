// SPDX-License-Identifier: GPL-2.0

========
ublk-nbd
========

Motivation
==========

As one attempt of using io_uring to implement network storage based on ublk
framework, make one basic nbd client with ublk/io_uring, which could be for
replacing linux kernel nbd driver.

Howto
=====

ublk add -t nbd [-q $NR_QUEUES ] [ -d $QUEUE_DEPTH ]  [--host $HOST_IP_OR_NAME | --unix $UNIX_SOCKET_PATH] [--send_zc]

Like ``nbd-client`` [#nbd_client]_, ublk-nbd supports both tcp and unix socket.

``--host $HOST_IP_OR_NAME`` points to nbd server's IP address or domain name if
tcp socket is used.

``--unix $UNIX_SOCKET_PATH`` points to unix socket path if unix socket is used.

The option of ``--send_zc`` enables ``io_uring send zero copy``
[#io_uring_send_zc]_, which is only used for handling ublk write IO.

Design
======

Handshake
---------

Borrow code from ``nbd`` [#nbd]_  project.

Transmission
------------

Traditionally the transmission phase is implemented as kernel driver of
``nbd driver`` [#nbd_driver]_. Now we have ublk framework, so it is
possible to move it out of linux kernel.

NBD protocol [#nbd_protocol]_ is simple, for each block IO request,
nbd client sends 24byte request header, nbd server responds with one
16 byte nbd reply. For READ request, the returned IO data follows the
reply, and now ublk-nbd implements nbd simple reply only, and doesn't
support structured reply which isn't implemented by ``nbd driver``
[#nbd_driver]_ too. For WRITE request, IO data needs to follow the
24byte request header.

For every IO request delivered from ublk driver, ublk-nbd target code
handles this IO in one dedicated coroutine bound to IO tag, the
IO handling includes:

- sending nbd request
- sending WRITE data
- reading nbd reply
- reading nbd READ data

One extra dedicated coroutine is responsible for reading reply and
data in case of READ request via io_uring & recv(nonblocking) hybrid
approach. recv(nonblocking) is always tried first:

- if the whole reply or data in case of READ is done by recv, wakeup
  IO handling coroutine for completing this IO

- if partial reply or data is read, keep to read via recv(nonblocking)
  until the whole reply or data is read or the max tries are reached.

- otherwise, io_uring is used for handling the remained reply/data

If io_uring is used finally for reading reply or data, when the CQE is
received, wakeup IO handling coroutine for completing the IO.

Each IO's handling coroutine is responsible for sending nbd request and
WRITE data in case of WRITE request via io_uring SQE, then wait for
reply or data in case of READ request, which is notified from the recv
coroutine.

Even though everything is actually done asynchronously in single pthread
for each nbd queue, programming with coroutine still looks like every
step done step by step, so it becomes easier to write efficient async
IO code with coroutine. Like other ublk targets, c++20 coroutine is used,
which is stackless and efficient.

Given stream socket is used by nbd, sending request header and data to
socket has to be serialized, and io_uring's SQE chain is taken with
help of IOSQE_IO_LINK. There are two chains, one is current chain, another
chain is next chain. Before each socket send IO in current chain is sent
to socket, new IO request is staggered into next chain. After the whole
current chain is done, the next chain is started to be submitted. And
the chain stuff is handled in ublk target callback of ->handle_io_background().

Test
====

make test T=nbd


TODO
====

TLS support
-----------

Timeout handling
----------------

More NBD features
-----------------

- structured replies

References
==========

.. [#nbd] https://github.com/NetworkBlockDevice/nbd
.. [#nbd_client] https://github.com/NetworkBlockDevice/nbd/blob/master/nbd-client.c
.. [#nbd_driver] https://github.com/torvalds/linux/blob/master/drivers/block/nbd.c
.. [#nbd_protocol] https://github.com/NetworkBlockDevice/nbd/blob/master/doc/proto.md
.. [#io_uring_send_zc] https://lwn.net/Articles/879724/
