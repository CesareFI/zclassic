/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: virtio-entropy (VIRTIO 1.2, section 5.4) fed only by a caller
 * callback. No host randomness, device file or clock is used here. */

#include "rvvirtio_priv.h"

#include <string.h>

static_assert(RVVIRTIO_RNG_REQ_BYTES_MAX < UINT32_MAX,
              "the used length (bytes written) must fit uint32_t");
static_assert(RVVIRTIO_RNG_CHUNK > 0 && RVVIRTIO_RNG_REQ_BYTES_MAX % RVVIRTIO_RNG_CHUNK == 0,
              "a request is a whole number of fill chunks");
static_assert(RVVIRTIO_RNG_NOTIFY_BYTES_MAX >= RVVIRTIO_RNG_REQ_BYTES_MAX,
              "a notify can serve at least one maximal request");

struct rng_result {
    uint64_t written; /* bytes put into the guest buffer */
    bool complete;    /* publish a used element (else the request stays available) */
    bool dry;         /* the source returned 0 during this request */
};

/* 5.4.6: fill the device-writable bytes of the popped chain from the source,
 * at most budget of them (what this notify may still deliver, never 0).
 * A chain with a device-readable byte or no writable byte completes with 0. */
static struct rng_result rng_request(struct rvvirtio_rng *r, uint64_t budget)
{
    struct rvvirtio_dev *d = &r->dev;
    struct rng_result res = {0, true, false};
    uint64_t want = RVVIRTIO_RNG_CLAMP(d->chain.out_len);
    if (!RVVIRTIO_RNG_READABLE_OK(d->chain.in_len) || want == 0) {
        r->counters.malformed++;
        return res;
    }
    if (want > budget)
        want = budget; /* the notify's byte cap is exact */
    while (res.written < want) {
        uint64_t left = want - res.written;
        size_t n = left < RVVIRTIO_RNG_CHUNK ? (size_t)left : RVVIRTIO_RNG_CHUNK;
        size_t got = r->ops.fill(r->ops.ctx, r->chunk, n);
        if (got == 0) {
            r->counters.empty_fills++;
            res.dry = true;
            break;
        }
        if (got > n)
            got = n;
        if (!rvvirtio_chain_write(d, res.written, r->chunk, got)) {
            res.complete = false; /* device is NEEDS_RESET */
            return res;
        }
        res.written += got;
        if (got < n)
            break; /* short: the source has nothing more right now */
    }
    res.complete = res.written > 0;
    return res;
}

/* One notify's worth of work: at least the first available request, then stop
 * at the request or byte cap, or when the source ran dry (rvvirtio.h). */
static void rng_run(struct rvvirtio_rng *r)
{
    struct rvvirtio_dev *dev = &r->dev;
    uint64_t moved = 0;
    r->pending = false;
    for (uint32_t served = 0; served < RVVIRTIO_RNG_NOTIFY_REQS_MAX; served++) {
        if (moved >= RVVIRTIO_RNG_NOTIFY_BYTES_MAX)
            break;
        if (rvvirtio_queue_pop(dev, 0) != RVVIRTIO_POP_OK)
            return; /* empty, or the device is now NEEDS_RESET */
        struct rng_result res = rng_request(r, RVVIRTIO_RNG_NOTIFY_LEFT(moved));
        if (!rvvirtio_dev_running(dev))
            return;
        if (res.complete) {
            uint64_t used = res.written;
            if (!rvvirtio_queue_push(dev, 0, used > UINT32_MAX ? UINT32_MAX : (uint32_t)used))
                return;
            r->counters.requests++;
            r->counters.bytes += res.written;
            moved += res.written;
        }
        if (res.dry)
            break;
    }
    r->pending = rvvirtio_queue_has_avail(dev, 0);
}

static void rng_notify(struct rvvirtio_dev *dev, uint32_t queue)
{
    if (queue != 0)
        return;
    rng_run((struct rvvirtio_rng *)dev);
}

static void rng_on_reset(struct rvvirtio_dev *dev)
{
    ((struct rvvirtio_rng *)dev)->pending = false;
}

/* The FreeBSD driver enqueues and notifies inside attach, before the transport
 * sets DRIVER_OK (virtio_random.c:184,284; virtio_mmio.c:851,858), and the
 * transport drops a notify until DRIVER_OK. It never notifies that request
 * again, so serve whatever is waiting the moment DRIVER_OK is set. */
static void rng_on_driver_ok(struct rvvirtio_dev *dev)
{
    struct rvvirtio_rng *r = (struct rvvirtio_rng *)dev;
    if (r->dev.queues[0].ready)
        rng_run(r);
}

void rvvirtio_rng_service(struct rvvirtio_rng *rng)
{
    if (rvvirtio_dev_running(&rng->dev) && rng->dev.queues[0].ready)
        rng_run(rng);
}

bool rvvirtio_rng_pending(const struct rvvirtio_rng *rng)
{
    return rng->pending;
}

struct rvvirtio_rng_counters rvvirtio_rng_counters_get(const struct rvvirtio_rng *rng)
{
    return rng->counters;
}

bool rvvirtio_rng_init(struct rvvirtio_rng *rng, const struct rvvirtio_mem *mem,
                       const struct rvvirtio_rng_ops *ops)
{
    if (mem == NULL || ops == NULL || mem->read == NULL || mem->write == NULL ||
        ops->fill == NULL)
        return false;
    memset(rng, 0, sizeof(*rng));
    rng->ops = *ops;
    rvvirtio_dev_setup(&rng->dev, mem, RVVIRTIO_DEVICE_ID_ENTROPY, 0, 1);
    rng->dev.notify = rng_notify;
    rng->dev.on_reset = rng_on_reset;
    rng->dev.on_driver_ok = rng_on_driver_ok;
    return true;
}
