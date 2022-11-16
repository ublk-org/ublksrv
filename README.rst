
============================
Userspace block driver(ublk)
============================

Introduction
============

This is the userspace daemon part(ublksrv) of the ublk framework, the other
part is ``ublk driver`` [#userspace]_  which supports multiple queue.

The two parts communicate by io_uring's IORING_OP_URING_CMD with one
per-queue shared cmd buffer for storing io command, and the buffer is
read only for ublksrv, each io command can be indexed by io request tag
directly, and the command is written by ublk driver, and read by ublksrv
after getting notification from ublk driver.

For example, when one READ io request is submitted to ublk block driver, ublk
driver stores the io command into cmd buffer first, then completes one
IORING_OP_URING_CMD for notifying ublksrv, and the URING_CMD is issued to
ublk driver beforehand by ublksrv for getting notification of any new io
request, and each URING_CMD is associated with one io request by tag,
so depth for URING_CMD is same with queue depth of ublk block device.

After ublksrv gets the io command, it translates and handles the ublk io
request, such as, for the ublk-loop target, ublksrv translates the request
into same request on another file or disk, like the kernel loop block
driver. In ublksrv's implementation, the io is still handled by io_uring,
and share same ring with IORING_OP_URING_CMD command. When the target io
request is done, the same IORING_OP_URING_CMD is issued to ublk driver for
both committing io request result and getting future notification of new
io request.

So far, the ublk driver needs to copy io request pages into userspace buffer
(pages) first for write before notifying the request to ublksrv, and copy
userspace buffer(pages) to the io request pages after ublksrv handles
READ. Also looks linux-mm can't support zero copy for this case yet. [#zero_copy]_

More ublk targets will be added with this framework in future even though only
ublk-loop and ublk-null are implemented now.

libublksrv is also generated, and it helps to integrate ublk into existed
project. One example of demo_null is provided for how to make a ublk
device over libublksrv.

Quick start
===========

how to build ublksrv:
--------------------

  autoreconf -i

  ./configure

  make

note: './configure' requires liburing 2.2 package installed, if liburing 2.2
isn't available in your distribution, please configure via the following
command, or refer to ``build_with_liburing_src`` [#build_with_liburing_src]_

  PKG_CONFIG_PATH=${LIBURING_DIR} \
  ./configure \
    CFLAGS="-I${LIBURING_DIR}/src/include" \
    CXXFLAGS="-I${LIBURING_DIR}/src/include" \
    LDFLAGS="-L${LIBURING_DIR}/src"

and LIBURING_DIR points to directory of liburing source code, and liburing
needs to be built before running above commands. Also IORING_SETUP_SQE128
has to be supported in the liburing source.

c++20 is required for building ublk utility, but libublksrv and demo_null.c &
demo_event.c can be built independently:

#build libublksrv

make -C lib/

#build demo_null && demo_event

make -C lib/

make demo_null demo_event


help
----

- ublk help

add one ublk-null disk
----------------------

- ublk add -t null


add one ublk-loop disk
----------------------

- ublk add -t loop -f /dev/vdb

or

- ublk add -t loop -f 1.img


add one qcow2 disk
------------------

- ublk add -t qcow2 -f test.qcow2

note: qcow2 support is experimental, see details in qcow2 status [#qcow2_status]_
and readme [#qcow2_readme]_


remove one ublk disk
--------------------

- ublk del -n 0		#remove /dev/ublkb0

- ublk del -a		#remove all ublk devices

list ublk devices
---------------------

- ublk list

- ublk list -v	#with all device info dumped


un-privileged mode
==================

At default, controling ublk device needs privileged user, since
/dev/ublk-control is permitted for administrator only, and this
is called privileged mode.

For un-privilege mode, /dev/ublk-control needs to be allowed for
all users, so the following udev rule need to be added:

KERNEL=="ublk-control", MODE="0666", OPTIONS+="static_node=ublk-control"

Also when new ublk device is added, we need ublk to change device
ownership to the device's real owner, so the following rules are
needed:

KERNEL=="ublkc*",RUN+="ublk_chown.sh %k"
KERNEL=="ublkb*",RUN+="ublk_chown.sh %k"

``ublk_chown.sh`` can be found under ``util/`` too.

``util/ublk_dev.rules`` includes the above rules.

With the above two administrator changes, un-privileged user can
create/delete/list/use ublk device, also anyone which isn't permitted
can't access and control this ublk devices(ublkc*/ublkb*)

Un-privileged user can pass '--un-previleged=1' to 'ublk add' for creating
un-privileged ublk device, then the created ublk device is only available
for the owner and administrator.

test
====

run all built tests
-------------------

make test T=all


run test group
--------------

make test T=null

make test T=loop

make test T=generic


run single test
---------------

make test T=generic/001

make test T=null/001

make test T=loop/001
...

run specified tests or test groups
----------------------------------

make test T=generic:loop/001:null


Debug
=====

ublksrv is running as one daemon process, so most of debug messages won't be
shown in terminal. If any issue is observed, please collect log via command
of "journalctl | grep ublksrvd"


License
=======

nlohmann(include/nlohmann/json.hpp) is from [#nlohmann]_, which is covered
by MIT license.

The library functions (all code in lib/ directory and include/ublksrv.h)
are covered by dual licensed LGPL and MIT, see COPYING.LGPL and LICENSE.

qcow2 target code is covered by GPL-2.0, see COPYING.

All other source code are covered by dual licensed GPL and MIT, see
COPYING and LICENSE.

References
==========

.. [#ublk_driver] https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/drivers/block/ublk_drv.c?h=v6.0
.. [#zero_copy] https://lore.kernel.org/all/20220318095531.15479-1-xiaoguang.wang@linux.alibaba.com/
.. [#nlohmann] https://github.com/nlohmann/json
.. [#qcow2_status] https://github.com/ming1/ubdsrv/blob/master/qcow2/STATUS.rst
.. [#qcow2_readme] https://github.com/ming1/ubdsrv/blob/master/qcow2/README.rst
.. [#build_with_liburing_src] https://github.com/ming1/ubdsrv/blob/master/build_with_liburing_src
