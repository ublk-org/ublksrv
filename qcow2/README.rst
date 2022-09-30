
==========
ublk-qcow2
==========

Motivation
==========

ublk-qcow2 is started for serving for the four purposes:

- building one complicated target from scratch helps libublksrv APIs/functions
  become mature/stable more quickly, since qcow2 is complicated and needs more
  requirement from libublksrv compared with other simple ones(loop, null)

- there are several attempts of implementing qcow2 driver in kernel, such as
  ``qloop`` [#qloop]_, ``dm-qcow2`` [#dm_qcow2]_ and
  ``in kernel qcow2(ro)`` [#in_kernel_qcow2_ro]_, so ublk-qcow2 might useful
  for covering requirement in this field

- performance comparison with qemu-nbd, and it was my 1st thought to evaluate
  performance of ublk/io_uring backend by writing one ublk-qcow2 since ublksrv
  is started

- help to abstract common building block or design pattern for writing new ublk
  target/backend

Howto
=====

ublk add -t qcow2 -f $PATH_QCOW2_IMG

So far not add any command line options yet. The default L2 cache size is 1MB,
and default refcount cache size is 256KB. Both l2 and refcount slice size is
4K. With DEBUG_QCOW2_META_STRESS enabled, two l2 slices and refcount slices
are allowed, and ublk-qcow2 is verified with this minimum cache size setting.


Design
======

Based on ublk framework
-----------------------

Based on libublksrv and common target code

IO size
-------

For simplifying handling of cluster mapping, the chunk_sectors of block layer
queue limit is aligned with QCOW2's cluster size, this way guarantees that at
most one l2 lookup is needed for handling one ublk-qcow2 IO, meantime one time
of IO is enough to handling one ublk-qcow2 IO. But this way may hurt big chunk
sequential IO a bit. In future, the chunk_sectors may be increased to 512KB,
then it is enough to load L2 slice at most once for handling one ublk IO, but
this big IO needs to be splitted to at most 512K/cluster_size small IOs.


Async io
--------

Target/backend is implemented by io_uring only, and shares same io_uring
for handling both ublk io command and qcow2 IOs.

Any IO from ublk driver has one unique tag, and any meta IO is assigned by one
tag from ublk-qcow2 too. Each IO(includes meta IO) is handled in one coroutine
context, so coroutine is always bound with one unique IO tag. IO is always
submitted via io_uring in async style, then the coroutine is suspended after
the submission. Once the IO is completed, the coroutine is resumed for further
processing.

Metadata update
---------------

soft update approach is taken for maintaining qcow2 meta-data integrity in the
event of a crash or power outage.

All metadata is updated asynchronously.

- meta entry dependency on cluster

  When one entry of l1/refcount table/l2/refcount blk table needs to be
  updated: 1) if the pointed cluster needs to be allocated, the entry is
  updated after the allocated cluster is discarded/zeroed, then any
  following reading on this mapping will get correct data. During the
  period, any read on any sectors in this cluster will return zero, and
  any write IO won't be started until the entry is updated. So cluster
  discard/zeroed is always done before updating meta entry pointing to
  this cluster and writing io data to any sector in this cluster.

- io data writing depends on zeroed cluster

  If the cluster isn't zeroed, the io write has to wait until the zeroing
  is done; the io read has to return zero during the period of zeroing
  cluster

- L2/refcount blk entry can be writeback iff the pointed cluster is zeroed

  Meantime the cluster for holding the table needs to be zeroed too

- L1 entry depends on l2 table(cache slice)

  The L1 dirty entry can only be updated iff the pointed l2 table becomes
  clean, that means: 1) the pointed cluster needs to be zeroed; 2) all dirty
  slices need to be updated

- refcount table entry depends on refcount blk

  The refcount table dirty entry can only be updated iff the pointed refcount
  blk becomes clean, that means: 1) the pointed cluster needs to be zeroed; 2)
  all dirty slices need to be updated


Meta data flushing to image
---------------------------

When any meta(L1/L2/refcount table/refcount blk) is being flushed to image,
IO code path can't update the in-ram meta data until the meta is flushed to
image, when the dirty flag is cleared.

Any meta is always flushed in background:

- when cache slice is added to dirty list, these cache slices will be started
  to flush after all current IOs are handled

- meta data flushing when io_uring is idle

- periodic meta data flushing

How to flushing meta data
~~~~~~~~~~~~~~~~~~~~~~~~~

1) allocate one tag for flushing one meta chain, and soft update has to be
  respected, start from the lowest cluster zeroing IO to the upper layer of
  updating l1 or refcount table

2) from implementation viewpoint, find the meta flush chains from top to bottom

  - find one oldest dirty entry in top meta(l1 or refcount table) or
  specified index(flushing from slice dirty list), suppose the index is A,
  then figure out all dirty entries in the 512 byte range which includes
  index A

  - for each dirty entry in the candidates
     -- for each dirty slices in this cluster pointed by the dirty entry,
     check if any pointed cluster by the slice is zeroed, if there is any,
     wait until all clusters are zeroed

     -- figure out the pointed cluster, if the cluster isn't zeroed yet,
     zero it now

     -- flushing all dirty slices in this cluster

  - flush all meta entries in this 512byte area

How to retrieve meta object after the meta io is done
-----------------------------------------------------

- use add_meta_io/del_meta_io/get_meta_io to meta flushing


L2/refcount blk slice lifetime
------------------------------

- meta slice idea is from QEMU, and both l2/refcount block table takes one
  cluster, and slice size is configurable, and at default both l2 &
  refcount block slice is 4K, so either one l2 mapping is needed or
  refcount block meta is needed, just the 4k part is loaded from image,
  and when flushing slice to image, it is still the whole slice flushed
  out.

- For each kind of slice, one lru cache is maintained, new slice is added
  to the lru cache, and if it is less accessed, the slice will be moved
  towards end of the lru cache. The lru cache capacity is fixed when
  starting ublk-qcow2, but it is configurable, and the default size is 1MB,
  so one lru cache may hold at most 256 l2 or refcount block slices.
  Finally, one slice may be evicted from the lru cache.

- Grab two reference count in slice_cache<T>::alloc_slice(), so alloc_slice()
  always returns one valid slice object, but it may not be in the lru list
  because it can be evicted in nested alloc_slice() if lru capacity is
  run out of. Note, ->wakeup_all() could trigger another alloc_slice.

- When one slice is evicted from lru cache, one reference is dropped. If
  the slice is clean, it will be added into per-device free list, which
  will be iterated over for slice releasing when current IO batch are
  handled. If the slice is dirty, the slice will be delayed to add to the
  free list after flushing of this slice is completed.

- when one slice is evicted from lru cache, it is moved to evicted slices
  map, and the slice is still visible via find_slice(slice key, true), but
  it becomes read only after being evicted from lru cache.

- one slice is visible via find_slice() from allocation to freeing, and the
  slice becomes invisible in when the slice is destructed, see
  Qcow2L2Table::~Qcow2L2Table() and Qcow2RefcountBlock::~Qcow2RefcountBlock()

Cluster state object lifetime
-----------------------------

Cluster state object is for tracking if one cluster is zeroed, and will be freed
anytime after its state becomes QCOW2_ALLOC_ZEROED.

Tracking dirty index
--------------------

For both l2 slice and refcount blk slice, the minimum flushing unit is single
slice, so we don't trace exact dirty index for the two.

For l1 table and refcount table, the minimum flushing unit is 512byte or logical
block size, so just track which 512byte unit is dirty.

IOWaiter
-----------------
- can't write one slice when the slice is being loaded from image or being
  stored to image 
- after one slice is evicted from lru cache, it becomes read only automatically,
  but the in-progress load/flush is guaranteed to be completed.
- ``class IOWaiter`` is invented for handling all kinds of wait/wakeup, which
  could become part of libublksrv in future


Implementation
==============

C++
---

ublk-qcow2 is basically implemented by C++, not depends on any 3rd party
library, except for in-tree lrucache helper and nlohmann jason lib(only for
setting up target), and built on c++ standard library almost completely.
The frequently used component is c++'s unordered map, which is for building
l2/refcount blk slice lru cache.

c++20 is needed just for the coroutine feature, but the usage(only co_wait()
and co_resume() is used) is simple, and could be replaced with other
coroutine implementation if c++20 is one blocker.


Coroutine with exception & IO tag
---------------------------------

IO tag is 1:1 with coroutine context, where the IO is submitted to io_uring, and
completed finally in this coroutine context. When waiting for io completion,
coroutine is suspended, and once the io is done by io_uring, the coroutine
is resumed, then IO handling can move on.

Anywhere depends on one event which is usually modeled as one state change,
the context represented by io tag is added via io_waiter.add_waiter(),
then one io exception is thrown, and the exception is caught and the current
coroutine is suspended. Once the state is changed to expected value, the
waiter will be waken up via io_waiter.wakeup_all(), then the coroutine
context waiting for the state change is resumed.

C++20 coroutine is stackless, and it is very efficient, but hard to use,
and it doesn't support nested coroutine, so programming with C++20 coroutine
is not very easy, and this area should be improved in future.

References
==========

.. [#qloop] https://upcommons.upc.edu/bitstream/handle/2099.1/9619/65757.pdf?sequence=1&isAllowed=y
.. [#dm_qcow2] https://lwn.net/Articles/889429/
.. [#in_kernel_qcow2_ro] https://lab.ks.uni-freiburg.de/projects/kernel-qcow2/repository 
