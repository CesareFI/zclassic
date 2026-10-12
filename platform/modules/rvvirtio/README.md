# zclassic23/rvvirtio

Standalone VIRTIO 1.2 device models for the built-in RISC-V machine: the
MMIO transport (version 2), split virtqueues, virtio-blk (device 2),
virtio-net (device 1), a multiport virtio-console (device 3) and virtio-entropy
(device 4). There is no CPU core in here. The embedding emulator
supplies guest memory through `read`/`write` callbacks and an `irq` callback,
and forwards MMIO accesses to `rvvirtio_mmio_read` / `rvvirtio_mmio_write`.

* Every guest address and length is validated (address wrap first, then the
  callback). A failing callback or a malformed ring sets
  `DEVICE_NEEDS_RESET`; the device never touches host memory on its own.
* Descriptor chains are walked with a bound equal to the table size, so a
  loop or an over-long chain is a device error, never a hang.
* virtio-blk talks to a caller backend (`size`, `pread`, `pwrite`, `flush`);
  sector range checks are overflow-free. A request with more than
  `RVVIRTIO_BLK_REQ_BYTES_MAX` (1 MiB) of data is refused with IOERR before any
  backend callback, and one notify is capped in requests and bytes (rest left
  pending: `rvvirtio_blk_pending` / `rvvirtio_blk_service`). virtio-net hands transmitted frames
  to a caller `tx` callback and takes received frames through
  `rvvirtio_net_receive`.
* virtio-console offers VIRTIO_CONSOLE_F_MULTIPORT only. Host-to-guest writes
  return the bytes accepted into buffers the guest already posted (the caller
  keeps the suffix); a short `from_guest` acceptance stops that port until
  `rvvirtio_console_port_resume`. Ports carry a generation counter. Callbacks
  must not call back into the device.
* virtio-entropy (device 4, one queue, no features, no config space) fills only
  the device-writable bytes of a request from the embedder's `fill` callback,
  at most `RVVIRTIO_RNG_REQ_BYTES_MAX` (4096) per request and exactly
  `RVVIRTIO_RNG_NOTIFY_BYTES_MAX` (64 KiB) per notify at most (a request that
  would pass that is cut to what is left); a request with a
  readable descriptor completes with length 0. When `fill` returns 0 the
  request stays available and `rvvirtio_rng_pending` reports it
  (`rvvirtio_rng_service` continues). Counters: requests, bytes, empty fills,
  malformed.
* No allocation, no host clock, no I/O, no globals; all state lives in
  caller-owned structs. The package depends only on `zclassic23/base` (byte-order codec).
* Written from the OASIS VIRTIO 1.2 specification only.
