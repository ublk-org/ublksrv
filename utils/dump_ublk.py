#!/usr/bin/drgn

import sys
from drgn import cast, NULL, sizeof, Object
from drgn.helpers.linux.xarray import xa_for_each
from drgn.helpers.linux.idr import idr_for_each_entry

def dump_request(h, tag, ubq):
    rq = h.tags.rqs[tag]
    data_addr = rq.address_of_().value_() + sizeof(prog.type("struct request"))
    data = Object(prog, 'struct ublk_rq_data', address=data_addr)
    #print(rq.address_of_(), data.address_of_())
    print("    request: tag {} int_tag {} rq_flags {:x} cmd_flags {:x} state {} ref {} ublk_io ref {}".
          format(
              rq.tag.value_(),
              rq.internal_tag.value_(),
              rq.rq_flags.value_(),
              rq.cmd_flags.value_(),
              rq.state.value_(),
              rq.ref.value_(),
              data.ref.value_(),
              ));
    io=ubq.ios[tag];
    io_base = ubq.ios[0];
    print("    ublk io: res {} flags {:x} cmd {} idx {}".format(
            ubq.ios[tag].res.value_(),
            ubq.ios[tag].flags.value_(),
            ubq.ios[tag].cmd.value_(),
            io.address_of_() - io_base.address_of_(),
        ));
    if rq.state.value_() == 1:
        print("    uring_cmd: flags {:x}".format(
            ubq.ios[tag].cmd.flags.value_()))
        #print(cast("struct io_kiocb *", ubq.ios[tag].cmd))


def dump_ubq(q_idx, ubq, h):
    print("ubq: idx {} flags {:x} force_abort {} canceling {} fail_io {}".
          format(q_idx, ubq.flags.value_(),
                 ubq.force_abort.value_(),
                 ubq.canceling.value_(),
                 ubq.fail_io.value_(),
                 ))
    if verbose == 0:
        return

    for idx in range(ubq.q_depth):
        io = ubq.ios[idx];
        rq = h.tags.rqs[idx]
        f = io.flags.value_()
        cmd = io.cmd.value_()
        res = io.res.value_()
        print("    io-{} flags {:x} cmd {:x} res {} rq state {} tag {}".format(
            idx, f, cmd, res, rq.state.value_(),
              rq.tag.value_()))

def dump_ub(ub):
    print("ublk dev_info: id {} state {} flags {:x} ub: state {:x}".format(
            ub.dev_info.dev_id.value_(),
            ub.dev_info.state.value_(),
            ub.dev_info.flags.value_(),
            ub.state.value_(),
        ))
    print("blk_mq: q(freeze_depth {} quiesce_depth {})".format(
        ub.ub_disk.queue.mq_freeze_depth.value_(),
        ub.ub_disk.queue.quiesce_depth.value_(),
        ))

def dump_blk_queues(ub):
    for idx, entry in xa_for_each(ub.ub_disk.queue.hctx_table.address_of_()):
        h = cast("struct blk_mq_hw_ctx *", entry)
        #print("hw queue", h)
        #print("flush queue", h.fq)
        ubq = cast("struct ublk_queue *", h.driver_data)
        dump_ubq(idx, ubq, h)
        ts = 0
        sb = h.tags.bitmap_tags.sb
        for i in range(sb.map_nr):
            ts = i << sb.shift
            active_tags = sb.map[i].word & ~sb.map[i].cleared
            for i in range(64):
                if (1 << i) & active_tags:
                    dump_request(h, ts + i, ubq)

verbose=int(sys.argv[1], 10)
ublk_index_idr = prog["ublk_index_idr"]

for i, ub in idr_for_each_entry(ublk_index_idr.address_of_(), "struct ublk_device"):
    dump_ub(ub)
    dump_blk_queues(ub)
    print("")
