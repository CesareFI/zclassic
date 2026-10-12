/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: module-internal queue, guest-memory and policy helpers. */
#ifndef RVVIRTIO_PRIV_H
#define RVVIRTIO_PRIV_H

#include "base/serialize_le.h"
#include "rvvirtio/rvvirtio.h"

/* 2.7.5: descriptor flags. */
#define RVVIRTIO_DESC_F_NEXT 1u
#define RVVIRTIO_DESC_F_WRITE 2u
#define RVVIRTIO_DESC_F_INDIRECT 4u
#define RVVIRTIO_DESC_SIZE 16u
/* 2.7.6: VRING_AVAIL_F_NO_INTERRUPT suppresses used-buffer notifications. */
#define RVVIRTIO_AVAIL_F_NO_INTERRUPT 1u

/* Policy points. A chain may visit at most `limit` descriptors (2.7.5: no
 * loops, never longer than the queue); a request must fit the disk (5.2.6).
 * Overridable only so a test can compile a deliberately broken twin. */
#ifndef RVVIRTIO_CHAIN_BOUND_OK
#define RVVIRTIO_CHAIN_BOUND_OK(steps, limit) ((steps) < (limit))
#endif
#ifndef RVVIRTIO_SECTOR_RANGE_OK
#define RVVIRTIO_SECTOR_RANGE_OK(sector, nsect, capacity) \
    ((sector) <= (capacity) && (nsect) <= (capacity) - (sector))
#endif

/* Admission bound for one block request (the guard of the bounded-request
 * rule in rvvirtio.h). Overridable only so a test can compile a twin without it. */
#ifndef RVVIRTIO_BLK_BYTES_OK
#define RVVIRTIO_BLK_BYTES_OK(bytes) ((bytes) <= RVVIRTIO_BLK_REQ_BYTES_MAX)
#endif

/* Bytes a from_guest callback accepted: the suffix it declined stays in the
 * guest buffer. Overridable only for the test twin that drops the suffix. */
#ifndef RVVIRTIO_ACCEPTED
#define RVVIRTIO_ACCEPTED(accepted, offered) (accepted)
#endif

/* Entropy request policy (the rules of rvvirtio.h, virtio-entropy). CLAMP is
 * the per-request byte cap; READABLE_OK admits only chains with no
 * device-readable bytes; NOTIFY_LEFT is what a notify that has delivered
 * `moved` bytes (always below the cap) may still deliver. Overridable only so
 * a test can compile a twin without them. */
#ifndef RVVIRTIO_RNG_CLAMP
#define RVVIRTIO_RNG_CLAMP(bytes) \
    ((bytes) > RVVIRTIO_RNG_REQ_BYTES_MAX ? (uint64_t)RVVIRTIO_RNG_REQ_BYTES_MAX : (bytes))
#endif
#ifndef RVVIRTIO_RNG_READABLE_OK
#define RVVIRTIO_RNG_READABLE_OK(in_len) ((in_len) == 0)
#endif
#ifndef RVVIRTIO_RNG_NOTIFY_LEFT
#define RVVIRTIO_RNG_NOTIFY_LEFT(moved) (RVVIRTIO_RNG_NOTIFY_BYTES_MAX - (moved))
#endif

enum rvvirtio_pop {
    RVVIRTIO_POP_EMPTY = 0,
    RVVIRTIO_POP_OK,
    RVVIRTIO_POP_ERROR, /* device now NEEDS_RESET */
};

/* Byte order lives in base/serialize_le.h (the one fixed-width codec). */
static inline uint16_t rvvirtio_le16(const uint8_t *p) { return zcl_read_u16_le(p); }
static inline uint32_t rvvirtio_le32(const uint8_t *p) { return zcl_read_u32_le(p); }
static inline uint64_t rvvirtio_le64(const uint8_t *p) { return zcl_read_u64_le(p); }
static inline void rvvirtio_put_le16(uint8_t *p, uint16_t v) { zcl_write_u16_le(p, v); }
static inline void rvvirtio_put_le32(uint8_t *p, uint32_t v) { zcl_write_u32_le(p, v); }

/* True when the device may process queues (DRIVER_OK, not NEEDS_RESET). */
bool rvvirtio_dev_running(const struct rvvirtio_dev *dev);

/* True when queue qi may be served: running, or FEATURES_OK without
 * NEEDS_RESET for a queue named in early_queues. */
bool rvvirtio_queue_live(const struct rvvirtio_dev *dev, uint32_t qi);

/* Guest memory through the callbacks; failure (including address wrap) sets
 * NEEDS_RESET and returns false. */
bool rvvirtio_gm_read(struct rvvirtio_dev *dev, uint64_t gpa, void *buf,
                      size_t n);
bool rvvirtio_gm_write(struct rvvirtio_dev *dev, uint64_t gpa, const void *buf,
                       size_t n);

/* Common setup shared by the device models. */
void rvvirtio_dev_setup(struct rvvirtio_dev *dev, const struct rvvirtio_mem *mem,
                        uint32_t device_id, uint64_t features, uint32_t nqueues);
void rvvirtio_dev_reset(struct rvvirtio_dev *dev);
void rvvirtio_irq_update(struct rvvirtio_dev *dev);

/* Queue helpers (2.7). pop loads dev->chain; push completes it. */
enum rvvirtio_pop rvvirtio_queue_pop(struct rvvirtio_dev *dev, uint32_t qi);
/* True when the avail ring offers a head beyond last_avail. A failing ring read
 * sets NEEDS_RESET and returns false. */
bool rvvirtio_queue_has_avail(struct rvvirtio_dev *dev, uint32_t qi);
bool rvvirtio_queue_push(struct rvvirtio_dev *dev, uint32_t qi, uint32_t len);

/* Byte streams over the popped chain: `readable` is the concatenation of the
 * device-readable segments, writable of the device-writable ones. */
bool rvvirtio_chain_read(struct rvvirtio_dev *dev, uint64_t off, void *buf,
                         size_t n);
bool rvvirtio_chain_write(struct rvvirtio_dev *dev, uint64_t off,
                          const void *buf, size_t n);

#endif /* RVVIRTIO_PRIV_H */
