Status
======

So far, only verified on images created by 'qemu-img create -f qcow2 $IMG $SIZE'.

And only support basic read/write function on qcow2 image, not support compression
yet, not support snapshot, not support extra options which require extra command
line options.

Not see regression on xfstest tests(XFS) by using ublk-qcow2 as test device, and
pass kernel building test(mount ublk-qcow2 as XFS, and clone & build linux kernel).
Not see image destruction by killing ublk daemon when running IO on this image,
only issue is cluster leak in this test, which is usually harmless.

So far it is experimental.


TODO
====

Compression is planned to be added, so that cloud image use case can be covered.

Sequential IO code path could be improved by increasing block queue limit of
chunk_sectors to 512K or other proper size.

C++ style cleanup. The last time I programming C++ is ~20years ago. So maybe
modern C++ features/styles should be applied more.

Meta data flushing improvement, this part of code isn't clean enough, IMO.

All kinds of cleanup, such as slice_cache<Template> should be converted to
slice_cache<Qcow2SliceMeta>.

Cover more tests with supported qcow2 options.

Coroutine improvement, the current c++20 stackless coroutine doesn't support
nested calling, it is a bit hard to use. If this area can be improved without
hurting performance, it will help much on building new ublk target/backend.

MQ support, and one problem is still related with coroutine, where more than
one per-queue pthread may wait for one single event, which is usually done
in one single queue/pthread.
