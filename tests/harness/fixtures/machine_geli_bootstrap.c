/* Copyright 2026 Rhett Creighton; SPDX-License-Identifier: Apache-2.0
 * purpose: Internal PUBLIC mounted-GELI acceptance with bounded private-port observation.
 * Included fixture; never exports guest console. */
#define FM_KERNEL_SHA "2445a0ca747bb28eac52c8c2bb861ee9be06f3c7353587d88e3c3fcbb832b2f4"
#define FM_PORT 4u
#define FM_TRACE_MAX 32u
#define FM_SB_DATA_BYTE UINT64_C(73760)
#include "platform/time_compat.h"
#define FM_DIAG_KERNEL_SHA "f7e7379fb08fd0035cf67bd98d5896376e103ab80851363d2c1f1a16a53e675d"
#define FM_DIAG_WORK UINT64_C(600000000)
struct fm_pc_symbol_range { uint64_t start,size; const char *name; };
struct fm_pc_text_range { uint64_t start,end; };
struct fm_pc_image {
    const char *kernel_sha;
    struct fm_pc_symbol_range symbols[9];
    struct fm_pc_text_range text[2];
};
struct fm_read_trace { uint64_t off, first_unwritten; size_t len, unwritten; };
struct fm_pc_origin {
    const struct rvmachine *machine;
    uint64_t retired;
    unsigned step;
    uint32_t host,device;
};
struct fm_pc_counts {
    uint32_t mode[4],symbol[10],unknown_count,observations;
    uint64_t unknown_pc[4];
    bool invalid,limited;
};
struct fm_state {
    struct fg_state disk;
    char line[256];
    size_t line_len;
    uint32_t epoch;
    bool overflow, ready, delivered, child, wrong, wrong_diag, auth;
    bool newfs_done;
    bool newfs_old_sb_read_failed, newfs_recovery_read_failed;
    unsigned newfs_rc;
    bool mount_done, mount_error, mount_integrity_error;
    unsigned mount_rc;
    bool umount_done;
    unsigned umount_rc;
    bool flush_done, flush_open_error, flush_ioctl_error;
    unsigned flush_rc;
    uint8_t written[FG_VOLUME_BYTES / 512u];
    struct fm_read_trace reads[FM_TRACE_MAX];
    unsigned read_count;
    bool read_trace_full, partial_write_observed;
    bool tamper, superblock_data_read;
    unsigned mount_step;
    bool diagnostic,diagnostic_ram128;
    const struct fm_pc_image *diagnostic_image;
    uint64_t diagnostic_admitted,diagnostic_last;
    uint32_t diagnostic_seen;
    uint64_t diagnostic_work[16];
    struct fm_pc_counts pc[16];
    uint32_t pc_crossings,pc_rejected;
};

static bool fm_disk_read(void *ctx, uint64_t off, void *buf, size_t n)
{
    struct fm_state *s = ctx;
    bool ok = fg_read(&s->disk, off, buf, n);
    if (!ok || s->disk.script.fired != s->mount_step || s->mount_step == 0 || s->mount_done ||
        off > FG_VOLUME_BYTES || n > FG_VOLUME_BYTES - off) return ok;
    if (off <= FM_SB_DATA_BYTE && n > FM_SB_DATA_BYTE - off)
        s->superblock_data_read = true;
    if (s->read_count == FM_TRACE_MAX) { s->read_trace_full = true; return ok; }
    struct fm_read_trace *t = &s->reads[s->read_count++];
    t->off = off; t->len = n; t->first_unwritten = UINT64_MAX;
    uint64_t end = off + n;
    for (uint64_t sector = off / 512u; sector < (end + 511u) / 512u; sector++) {
        if (s->written[sector] != 0) continue;
        if (t->unwritten++ == 0) t->first_unwritten = sector * 512u;
    }
    return ok;
}

static bool fm_disk_write(void *ctx, uint64_t off, const void *buf, size_t n)
{
    struct fm_state *s = ctx;
    bool ok = fg_write(&s->disk, off, buf, n);
    if (!ok || off > FG_VOLUME_BYTES || n > FG_VOLUME_BYTES - off) return ok;
    if (off % 512u != 0 || n % 512u != 0) s->partial_write_observed = true;
    uint64_t end = off + n;
    for (uint64_t sector = (off + 511u) / 512u; sector < end / 512u; sector++)
        s->written[sector] = 1;
    return ok;
}

static bool fm_disk_flush(void *ctx)
{
    struct fm_state *s = ctx;
    return fg_flush(&s->disk);
}

static void fm_line(struct fm_state *s)
{
    /* Only fixed PUBLIC observations survive this bounded private matcher. */
    if (strcmp(s->line, "PUBLIC_BOOTSTRAP_RAW_READY\r\n") == 0) {
        struct rvmachine *m = s->disk.m;
        /* Read-only callback snapshot; delivery happens after run returns. */
        if (s->ready || m == NULL || m->conport_count <= FM_PORT ||
            !m->con.ports[FM_PORT].host_open || !m->con.ports[FM_PORT].guest_open)
            s->overflow = true;
        else { s->epoch = m->conports[FM_PORT].generation; s->ready = true; }
    }
    if (strcmp(s->line, "PUBLIC_BOOTSTRAP_CHILD delivered32=1 eof=1 reaped=1 timely=1 exited=1 status=0\r\n") == 0)
        s->child = true;
    if (strcmp(s->line, "PUBLIC_BOOTSTRAP_CHILD delivered32=1 eof=1 reaped=1 timely=1 exited=1 status=1\r\n") == 0)
        s->wrong = true;
    if (strcmp(s->line, "geli: Wrong key for vtbd0.\r\n") == 0) s->wrong_diag = true;
    if (strstr(s->line, "AuthenticationAlgorithm: HMAC/SHA256") != NULL) s->auth = true;
}

static void fm_line_diagnostics(struct fm_state *s)
{
    /* Fixed source-bound diagnostic prefixes; never retain/export their suffix. */
    if (strncmp(s->line, "newfs: can't read old UFS1 superblock:",
                sizeof "newfs: can't read old UFS1 superblock:" - 1u) == 0)
        s->newfs_old_sb_read_failed = true;
    if (strncmp(s->line, "newfs: can't read recovery area:",
                sizeof "newfs: can't read recovery area:" - 1u) == 0)
        s->newfs_recovery_read_failed = true;
    if (strncmp(s->line, "mount: /dev/vtbd0.eli:",
                sizeof "mount: /dev/vtbd0.eli:" - 1u) == 0) {
        s->mount_error = true;
        if (strstr(s->line, "Integrity check failed") != NULL)
            s->mount_integrity_error = true;
    }
}

static void fm_line_status(struct fm_state *s)
{
    if (strncmp(s->line, "PUBLIC_MOUNT_RC:", 16) == 0) {
        char *end = NULL;
        unsigned long rc = strtoul(s->line + 16, &end, 10);
        if (s->mount_done || s->line[16] < '0' || s->line[16] > '9' ||
            end == NULL || strcmp(end, "\r\n") != 0 || rc > 255)
            s->overflow = true;
        else { s->mount_done = true; s->mount_rc = (unsigned)rc; }
    }
    if (strncmp(s->line, "PUBLIC_UMOUNT_RC:", 17) == 0) {
        char *end = NULL;
        unsigned long rc = strtoul(s->line + 17, &end, 10);
        if (s->umount_done || s->line[17] < '0' || s->line[17] > '9' ||
            end == NULL || strcmp(end, "\r\n") != 0 || rc > 255)
            s->overflow = true;
        else { s->umount_done = true; s->umount_rc = (unsigned)rc; }
    }
}

static void fm_line_barrier(struct fm_state *s)
{
    if (strncmp(s->line, "PUBLIC_GELI_FLUSH_OPEN:", 23) == 0) s->flush_open_error = true;
    if (strncmp(s->line, "PUBLIC_GELI_FLUSH_IOCTL:", 24) == 0) s->flush_ioctl_error = true;
    if (strncmp(s->line, "PUBLIC_FLUSH_RC:", 16) == 0) {
        char *end = NULL;
        unsigned long rc = strtoul(s->line + 16, &end, 10);
        if (s->flush_done || s->line[16] < '0' || s->line[16] > '9' ||
            end == NULL || strcmp(end, "\r\n") != 0 || rc > 255)
            s->overflow = true;
        else { s->flush_done = true; s->flush_rc = (unsigned)rc; }
    }
}

static void fm_line_newfs_status(struct fm_state *s)
{
    if (strncmp(s->line, "PUBLIC_NEWFS_RC:", 16) == 0) {
        char *end = NULL;
        unsigned long rc = strtoul(s->line + 16, &end, 10);
        if (s->newfs_done || s->line[16] < '0' || s->line[16] > '9' ||
            end == NULL || strcmp(end, "\r\n") != 0 || rc > 255)
            s->overflow = true;
        else { s->newfs_done = true; s->newfs_rc = (unsigned)rc; }
    }
}

static void fm_console(void *ctx, uint8_t byte)
{
    struct fm_state *s = ctx;
    if (s->line_len == sizeof s->line - 1u) {
        s->overflow = true;
        s->line_len = 0;
    }
    s->line[s->line_len++] = (char)byte;
    s->line[s->line_len] = '\0';
    if (byte == '\n') {
        fm_line(s);
        fm_line_diagnostics(s);
        fm_line_status(s);
        fm_line_barrier(s);
        fm_line_newfs_status(s);
        memory_cleanse(s->line, sizeof s->line);
        s->line_len = 0;
    }
    rvmachine_script_console(&s->disk.script, s->disk.m, byte);
}

static size_t fm_sink(void *ctx, unsigned port, const uint8_t *bytes, size_t n)
{
    (void)ctx; (void)port; (void)bytes; (void)n;
    /* Private TX is refused by the device before this sink. Public T/P idle. */
    return 0;
}

static bool fm_deliver(struct fm_state *s, bool wrong)
{
    if (!s->ready || s->delivered) return true;
    struct rvmachine *m = s->disk.m;
    uint32_t epoch = rvmachine_conport_generation(m, FM_PORT);
    if (!rvmachine_conport_guest_open(m, FM_PORT) ||
        rvmachine_conport_queued(m, FM_PORT) != 0 || epoch == 0 || epoch != s->epoch)
        return fg_refuse("PUBLIC receiver readiness epoch");
    uint8_t bytes[32];
    for (size_t i = 0; i < sizeof bytes; ++i) bytes[i] = (uint8_t)(i + (wrong ? 33u : 1u));
    bool ok = rvmachine_keyfile_deliver(m, FM_PORT, epoch, bytes, sizeof bytes);
    memory_cleanse(bytes, sizeof bytes);
    if (!ok) return fg_refuse("PUBLIC one-shot delivery");
    s->delivered = true;
    return true;
}

static bool fm_create(struct fm_state *s, struct rvmachine_disk **outer,
                      const uint8_t *kernel, size_t n)
{
    struct rvmachine_config config = {
        .ram_bytes = s->diagnostic ? (s->diagnostic_ram128 ? UINT64_C(128)<<20 : UINT64_C(256)<<20) : RVMACHINE_RAM_DEFAULT,
        .disk = *outer, .cleanse_on_destroy = true,
        .bootargs = "-s kern.random.initial_seeding.bypass_before_seeding=0",
        .console = fm_console, .console_ctx = s,
        .entropy = fg_entropy, .entropy_ctx = &s->disk, .entropy_fail_closed = true,
        .boot_seed = fg_seed, .boot_seed_ctx = &s->disk,
        .conport_count = 5, .private_keyfile_port_plus_one = 5,
        .conport_names = {"z23.l0.t", "z23.l0.p", "z23.l1.t", "z23.l1.p", "z23.bootstrap.keyfile"},
        .conport_sink = fm_sink, .conport_ctx = s
    };
    if (rvmachine_create(&s->disk.m, &config) != RVMACHINE_OK) return fg_refuse("PUBLIC private machine create");
    *outer = NULL;
    return !rvmachine_public_export_allowed(s->disk.m) &&
        rvmachine_load_kernel(s->disk.m, kernel, n) == RVMACHINE_OK;
}

static bool fm_mount_valid(struct fm_state *s)
{
    if (s->mount_done && ((!s->tamper && s->mount_rc != 0) ||
                          (s->tamper && s->mount_rc == 0)))
        return fg_refuse("PUBLIC filesystem mount outcome contradicts selected phase");
    return true;
}

static bool fm_phase_valid(struct fm_state *s, bool wrong)
{
    if ((!wrong && s->wrong) || (wrong && s->child))
        return fg_refuse("PUBLIC child outcome contradicts selected phase");
    if (s->newfs_done && s->newfs_rc != 0)
        return fg_refuse("PUBLIC filesystem formatter returned nonzero");
    if (!fm_mount_valid(s)) return false;
    if (s->umount_done && s->umount_rc != 0)
        return fg_refuse("PUBLIC filesystem unmount returned nonzero");
    if (s->flush_done && s->flush_rc != 0)
        return fg_refuse("PUBLIC filesystem barrier returned nonzero");
    return true;
}

static bool fm_after_run(struct fm_state *s, struct rvmachine_result *r,
                         enum rvmachine_status status, uint64_t *used)
{
    if (!fg_work(r, used) || s->disk.entropy_failed || s->disk.volume.failed ||
        s->overflow || status != RVMACHINE_OK)
        return fg_refuse("PUBLIC mounted final boundary");
    return true;
}

static bool fm_diagnostic_clock(struct fm_state *s)
{
    if(!s->diagnostic)return true;
    int64_t now=platform_time_monotonic_ms();
    if(now<=0 || (uint64_t)now<s->diagnostic_last ||
        (uint64_t)now-s->diagnostic_admitted>=UINT64_C(120000))
        return fg_refuse("PUBLIC formatting deadline/clock");
    s->diagnostic_last=(uint64_t)now;
    return true;
}
static bool fm_diagnostic_return(struct fm_state *s,uint64_t used,unsigned before,
    const struct rvmachine *machine,uint32_t epoch,uint32_t device_epoch)
{
    if(!s->diagnostic)return true;
    if(used>FM_DIAG_WORK || !fm_diagnostic_clock(s))return fg_refuse("PUBLIC formatting returned bound");
    unsigned step=s->disk.script.fired;
    if(step>=16 || step<before)return fg_refuse("PUBLIC formatting step range");
    /* One returned upper boundary for the newest enqueued step. A skipped
     * step stays unknown; no invented per-command or exact retirement cost. */
    /* PUBLIC metadata only: epoch zero is legal before receiver opening.
     * Delivery remains mandatory in fm_receiver_proof, never inferred here. */
    if(step!=before && machine==s->disk.m && epoch==rvmachine_conport_generation(s->disk.m,FM_PORT) &&
        device_epoch==s->disk.m->con.ports[FM_PORT].generation){
        s->diagnostic_seen|=UINT32_C(1)<<step;
        s->diagnostic_work[step]=used;
    }
    return true;
}
/* Selected exact FUNC intervals from retained f7e ELF. Nonselected S PCs
 * remain OTHER; U/M/unknown never borrow these kernel symbol labels. */
static const struct fm_pc_image fm_pc_original={
    .kernel_sha=FM_DIAG_KERNEL_SHA,
    .symbols={
    {UINT64_C(0xffffffc00055b8b0),144,"copyout"},
    {UINT64_C(0xffffffc0000cb254),1196,"rijndaelEncrypt"},
    {UINT64_C(0xffffffc000559252),22,"memset"},
    {UINT64_C(0xffffffc00055b940),144,"copyin"},
    {UINT64_C(0xffffffc0005648e0),30,"pmap_zero_page"},
    {UINT64_C(0xffffffc000562c8a),2100,"pmap_enter"},
    {UINT64_C(0xffffffc000559112),288,"memcpy"},
    {UINT64_C(0xffffffc0000cb700),1196,"rijndaelDecrypt"},
    {UINT64_C(0xffffffc0000cd668),8716,"_libmd_SHA256_Transform"}
    },
    .text={{UINT64_C(0xffffffc000000000),UINT64_C(0xffffffc0005854de)},
        {UINT64_C(0xffffffc0026e1730),UINT64_C(0xffffffc0026e1790)}}
};
/* Independently reviewed one-object memset candidate. Hash and intervals
 * derive from the same stripped ELF; no protected-profile admission. */
static const struct fm_pc_image fm_pc_candidate={
    .kernel_sha="b54f5b75042a526567aaf0b7ce2b1d41c43778c79d7c5b3684f540dcaab5fb43",
    .symbols={
        {UINT64_C(0xffffffc00055b910),144,"copyout"},
        {UINT64_C(0xffffffc0000cb254),1196,"rijndaelEncrypt"},
        {UINT64_C(0xffffffc000559252),110,"memset"},
        {UINT64_C(0xffffffc00055b9a0),144,"copyin"},
        {UINT64_C(0xffffffc000564940),30,"pmap_zero_page"},
        {UINT64_C(0xffffffc000562cea),2100,"pmap_enter"},
        {UINT64_C(0xffffffc000559112),288,"memcpy"},
        {UINT64_C(0xffffffc0000cb700),1196,"rijndaelDecrypt"},
        {UINT64_C(0xffffffc0000cd668),8716,"_libmd_SHA256_Transform"}
    },
    .text={{UINT64_C(0xffffffc000000000),UINT64_C(0xffffffc00058553e)},
        {UINT64_C(0xffffffc0026e1790),UINT64_C(0xffffffc0026e17f0)}}
};
static bool fm_pc_image_qualified(const struct fm_pc_image *image)
{
    if(image==NULL || image->kernel_sha==NULL ||
        strcmp(image->kernel_sha,"UNQUALIFIED_IMAGE_NO_DISPATCH")==0)
        return fg_refuse("PUBLIC diagnostic image not qualified");
    for(unsigned t=0;t<2;t++)
        if(image->text[t].start>=image->text[t].end)
            return fg_refuse("PUBLIC diagnostic text interval");
    for(unsigned i=0;i<9;i++){
        const struct fm_pc_symbol_range *r=&image->symbols[i];
        if(r->name==NULL || r->size==0 || r->size>UINT64_MAX-r->start)
            return fg_refuse("PUBLIC diagnostic symbol interval");
        bool contained=false;
        for(unsigned t=0;t<2;t++)
            if(r->start>=image->text[t].start && r->start<image->text[t].end &&
                r->size<=image->text[t].end-r->start)contained=true;
        if(!contained)return fg_refuse("PUBLIC diagnostic symbol outside text");
    }
    return true;
}
static bool fm_pc_increment(uint32_t *count)
{
    if(*count==UINT32_MAX)return false;
    ++*count;return true;
}
static unsigned fm_pc_symbol(const struct fm_pc_image *image,uint64_t pc)
{
    for(unsigned i=0;i<9;i++)
        if(pc>=image->symbols[i].start && pc-image->symbols[i].start<image->symbols[i].size)return i;
    return 9;
}
static bool fm_pc_kernel_text(const struct fm_pc_image *image,uint64_t pc)
{
    for(unsigned i=0;i<2;i++)
        if(pc>=image->text[i].start && pc<image->text[i].end)return true;
    return false;
}
static void fm_pc_unknown(const struct fm_pc_image *image,struct fm_pc_counts *counts,uint64_t pc)
{
    if(!fm_pc_kernel_text(image,pc))return;
    for(unsigned i=0;i<counts->unknown_count;i++)if(counts->unknown_pc[i]==pc)return;
    if(counts->unknown_count<4)counts->unknown_pc[counts->unknown_count++]=pc;
}
static bool fm_pc_current(const struct fm_state *s,const struct fm_pc_origin *before,
    const struct rvmachine_result *r)
{
    return before->machine==s->disk.m && r->retired>before->retired &&
        r->pc==s->disk.m->hart.pc && before->host==rvmachine_conport_generation(s->disk.m,FM_PORT) &&
        before->device==s->disk.m->con.ports[FM_PORT].generation;
}
static void fm_pc_observe(struct fm_state *s,const struct fm_pc_origin *before,
    const struct rvmachine_result *r)
{
    if(!s->diagnostic)return;
    if(before->step!=s->disk.script.fired){
        (void)fm_pc_increment(&s->pc_crossings);return;
    }
    if(before->step>=16 || !fm_pc_current(s,before,r)){
        (void)fm_pc_increment(&s->pc_rejected);return;
    }
    struct fm_pc_counts *counts=&s->pc[before->step];
    if(counts->observations==65536){counts->limited=true;return;}
    counts->observations++;
    unsigned mode=3;
    switch(s->disk.m->hart.priv){case RVEMU_PRIV_U:mode=0;break;
        case RVEMU_PRIV_S:mode=1;break;case RVEMU_PRIV_M:mode=2;break;default:break;}
    if(!fm_pc_increment(&counts->mode[mode]))counts->invalid=true;
    if(mode!=1)return;
    unsigned symbol=fm_pc_symbol(s->diagnostic_image,r->pc);
    if(!fm_pc_increment(&counts->symbol[symbol]))counts->invalid=true;
    if(symbol==9)fm_pc_unknown(s->diagnostic_image,counts,r->pc);
}
static bool fm_run(struct fm_state *s, struct rvmachine_result *r, bool wrong)
{
    for (;;) {
        uint64_t used;
        uint64_t cap=s->diagnostic?FM_DIAG_WORK:FG_MAX_WORK;
        if (!fg_work(r, &used) || used >= cap || s->disk.entropy_failed || s->disk.volume.failed)
            return fg_refuse("PUBLIC mounted work/source boundary");
        if(!fm_diagnostic_clock(s))return false;
        if (!fm_deliver(s, wrong)) return false;
        uint64_t left = cap - used;
        unsigned before=s->disk.script.fired;
        const struct rvmachine *machine=s->disk.m;
        uint32_t epoch=rvmachine_conport_generation(s->disk.m,FM_PORT);
        uint32_t device_epoch=s->disk.m->con.ports[FM_PORT].generation;
        struct fm_pc_origin origin={machine,r->retired,before,epoch,device_epoch};
        enum rvmachine_status status = rvmachine_run(s->disk.m, left < 4096 ? left : 4096, r);
        if (!fm_after_run(s, r, status, &used)) return false;
        if(!fm_diagnostic_return(s,used,before,machine,epoch,device_epoch))return false;
        fm_pc_observe(s,&origin,r);
        if (!fm_phase_valid(s, wrong)) return false;
        if (rvmachine_script_met(&s->disk.script)) return true;
        if (r->stop != RVMACHINE_STOP_BUDGET) return fg_refuse("PUBLIC mounted incomplete stop");
    }
}

static bool fm_step(struct fm_state *s, const char *marker, const char *body, bool final)
{
    /* Keep the generated canonical tty input below the qualified 256 limit. */
    if (strlen(body) + (final ? 113u : 40u) >= 256u) return fg_refuse("PUBLIC mounted tty line bound");
    return fg_add_step(&s->disk, marker, body, final);
}

static bool fm_write_steps(struct fm_state *s, const char *next)
{
    if (!fm_step(s, next,
            "dd if=/dev/zero of=/dev/vtbd0.eli bs=4096 count=16 conv=fsync && dd if=/dev/zero of=/dev/vtbd0.eli bs=4096 seek=17 count=1 conv=notrunc,fsync && ", false) ||
            !fm_step(s, next,
            "newfs -U /dev/vtbd0.eli; public_rc=$?; printf '\\120\\125\\102\\114\\111\\103\\137\\116\\105\\127\\106\\123\\137\\122\\103:%s\\n' \"$public_rc\"; [ \"$public_rc\" = 0 ] && ", false) ||
            !fm_step(s, next,
            "mount -t ufs /dev/vtbd0.eli /z23/identity; public_rc=$?; printf '\\120\\125\\102\\114\\111\\103\\137\\115\\117\\125\\116\\124\\137\\122\\103:%s\\n' \"$public_rc\"; [ \"$public_rc\" = 0 ] && ", false) ||
            !fm_step(s, next, "dd if=/PUBLIC_PAYLOAD.bin of=/z23/identity/public.bin bs=4096 count=1 conv=fsync && ", false) ||
            !fm_step(s, next,
            "umount /z23/identity; public_rc=$?; printf '\\120\\125\\102\\114\\111\\103\\137\\125\\115\\117\\125\\116\\124\\137\\122\\103:%s\\n' \"$public_rc\"; [ \"$public_rc\" = 0 ] && ", false) ||
            !fm_step(s, next,
            "/sbin/geli-mounted-flush; public_rc=$?; printf '\\120\\125\\102\\114\\111\\103\\137\\106\\114\\125\\123\\110\\137\\122\\103:%s\\n' \"$public_rc\"; [ \"$public_rc\" = 0 ] && ", false)) return false;
    return true;
}

static bool fm_health_steps(struct fm_state *s, const char *next)
{
    if (!fm_step(s, "# ", "[ \"$(sysctl -n kern.random.initial_seeding.bypass_before_seeding)\" = 0 ] && ", false) ||
        !fm_step(s, next, "[ \"$(sysctl -n kern.random.initial_seeding.read_random_bypassed_before_seeding)\" = 0 ] && ", false) ||
        !fm_step(s, next, "[ \"$(sysctl -n kern.random.initial_seeding.arc4random_bypassed_before_seeding)\" = 0 ] && ", false) ||
        !fm_step(s, next, "{ read -r -t 2 PUBLIC_RANDOM < /dev/random; public_rc=$?; unset PUBLIC_RANDOM; [ \"$public_rc\" = 0 ]; } && ", false)) return false;
    return true;
}

static bool fm_session_steps(struct fm_state *s, const char *next, bool write, bool wrong)
{
    if (wrong) {
        if (!fm_step(s, next, "/sbin/geli-bootstrap-public --public-wrong-key; public_rc=$?; [ \"$public_rc\" = 6 ] && [ ! -e /dev/vtbd0.eli ] && ", false)) return false;
        if (!fm_step(s, next, "[ ! -e /dev/vtbd0.eli ] && ", true)) return false;
    } else {
        if (!fm_step(s, next, "/sbin/geli-bootstrap-public && geli list vtbd0.eli && ", false)) return false;
        if (s->tamper) {
            if (!fm_step(s, next,
                "mount -t ufs /dev/vtbd0.eli /z23/identity; public_rc=$?; printf '\\120\\125\\102\\114\\111\\103\\137\\115\\117\\125\\116\\124\\137\\122\\103:%s\\n' \"$public_rc\"; [ \"$public_rc\" != 0 ] && ", false) ||
                !fm_step(s, next, "[ ! -e /z23/identity/public.bin ] && ", true)) return false;
            return rvmachine_script_until(&s->disk.script, "FIXTURE-GELI-PHASE-OK\r\n", 23);
        }
        /* Authenticate newfs prereads and the observed second superblock page. */
        if (write && !fm_write_steps(s, next)) return false;
        if (!fm_step(s, next, "mount -t ufs -o ro,noatime /dev/vtbd0.eli /z23/identity && ", false) ||
            !fm_step(s, next, "cmp /PUBLIC_PAYLOAD.bin /z23/identity/public.bin && [ ! -e /z23/identity/public.wrong ] && ", false) ||
            !fm_step(s, next, "umount /z23/identity && /sbin/geli-mounted-flush && ", true)) return false;
    }
    return rvmachine_script_until(&s->disk.script, "FIXTURE-GELI-PHASE-OK\r\n", 23);
}

static bool fm_diagnostic_script(struct fm_state *s)
{
    static const char *const bodies[]={
        "geli init -B none -P -K /PUBLIC_BOOTSTRAP_LITERAL.key -a HMAC/SHA256 -e AES-XTS -l 256 -s 4096 /dev/vtbd0 && ",
        "/sbin/geli-bootstrap-public && geli list vtbd0.eli && ",
        "dd if=/dev/zero of=/dev/vtbd0.eli bs=4096 seek=2 count=2 conv=fsync && dd if=/dev/zero of=/dev/vtbd0.eli bs=4096 seek=15 count=3 conv=notrunc,fsync && ",
        "newfs -U /dev/vtbd0.eli; public_rc=$?; printf '\\120\\125\\102\\114\\111\\103\\137\\116\\105\\127\\106\\123\\137\\122\\103:%s\\n' \"$public_rc\"; [ \"$public_rc\" = 0 ] && ",
        "mount -t ufs /dev/vtbd0.eli /z23/identity; public_rc=$?; printf '\\120\\125\\102\\114\\111\\103\\137\\115\\117\\125\\116\\124\\137\\122\\103:%s\\n' \"$public_rc\"; [ \"$public_rc\" = 0 ] && ",
        "umount /z23/identity && /sbin/geli-mounted-flush && "
    };
    const char *next="FG-NEXT\r\n";
    rvmachine_script_init(&s->disk.script);
    if(!rvmachine_script_add(&s->disk.script,"Enter full pathname",19,"\n",1) ||
        !fm_health_steps(s,next))return false;
    for(size_t i=0;i<sizeof bodies/sizeof bodies[0];i++)
        if(!fm_step(s,next,bodies[i],i+1==sizeof bodies/sizeof bodies[0]))return false;
    return rvmachine_script_until(&s->disk.script,"FIXTURE-GELI-PHASE-OK\r\n",23);
}
static bool fm_script(struct fm_state *s, const char *phase)
{
    if(s->diagnostic)return fm_diagnostic_script(s);
    bool write = strcmp(phase, "mounted-write") == 0;
    bool wrong = strcmp(phase, "mounted-wrong") == 0;
    s->tamper = strcmp(phase, "mounted-tamper") == 0;
    s->mount_step = write ? 10u : s->tamper ? 7u : 0u;
    if (!write && !wrong && !s->tamper && strcmp(phase, "mounted-read") != 0) return false;
    const char *next = "FG-NEXT\r\n";
    rvmachine_script_init(&s->disk.script);
    if (!rvmachine_script_add(&s->disk.script, "Enter full pathname", 19, "\n", 1)) return false;
    if (!fm_health_steps(s, next)) return false;
    if (write && !fm_step(s, next,
        "geli init -B none -P -K /PUBLIC_BOOTSTRAP_LITERAL.key -a HMAC/SHA256 -e AES-XTS -l 256 -s 4096 /dev/vtbd0 && ", false)) return false;
    return fm_session_steps(s, next, write, wrong);
}

static bool fm_receiver_proof(struct fm_state *s)
{
    struct rvmachine *m = s->disk.m;
    if (!s->delivered || s->epoch != rvmachine_conport_generation(m, FM_PORT) ||
        rvmachine_conport_queued(m, FM_PORT) != 0 ||
        rvmachine_conport_consumed(m, FM_PORT) != 32 ||
        !rvmachine_boot_seed_cleared(m) || s->disk.volume.failed || s->disk.entropy_failed)
        return fg_refuse("PUBLIC mounted receiver/source proof");
    return true;
}

static bool fm_tamper_proof(struct fm_state *s)
{
    return s->child && s->auth && s->mount_done && s->mount_rc != 0 &&
        s->mount_integrity_error && s->superblock_data_read && s->disk.write_seq == 0;
}

static bool fm_proof(struct fm_state *s, const char *phase)
{
    bool wrong = strcmp(phase, "mounted-wrong") == 0;
    if (!fm_receiver_proof(s)) return false;
    if(s->diagnostic && (!s->newfs_done || s->newfs_rc || !s->mount_done || s->mount_rc))return false;
    if (wrong) return s->wrong && s->wrong_diag && !s->child && s->disk.write_seq == 0;
    if (s->tamper) return fm_tamper_proof(s);
    return s->child && s->auth && s->disk.flushes > 0 &&
        s->disk.flush_seq > s->disk.write_seq;
}

static void fm_refusal(struct fm_state *s, struct rvmachine_result *r, const char *phase)
{
        /* Declared PUBLIC setup metadata only; never console/queue/RAM bytes. */
        uint64_t used = 0;
        bool work_valid = fg_work(r, &used);
        bool epoch_current = s->disk.m != NULL && s->epoch != 0 &&
            s->epoch == rvmachine_conport_generation(s->disk.m, FM_PORT);
        if (printf("PUBLIC_MOUNTED_REFUSAL phase=%s fired=%u steps=%u goal=%u ready=%u delivered=%u child=%u wrong=%u diag=%u auth=%u overflow=%u epoch_current=%u work_valid=%u work=%llu source_failed=%u backend_failed=%u newfs_done=%u newfs_rc=%u newfs_old_sb_read_failed=%u newfs_recovery_read_failed=%u mount_done=%u mount_rc=%u mount_error=%u mount_integrity_error=%u umount_done=%u umount_rc=%u retired=%llu fw=%llu device=%llu\n",
            phase, s->disk.script.fired, s->disk.script.count,
            (unsigned)s->disk.script.until_seen, (unsigned)s->ready,
            (unsigned)s->delivered, (unsigned)s->child, (unsigned)s->wrong,
            (unsigned)s->wrong_diag, (unsigned)s->auth, (unsigned)s->overflow,
            (unsigned)epoch_current, (unsigned)work_valid,
            (unsigned long long)used, (unsigned)s->disk.entropy_failed,
            (unsigned)s->disk.volume.failed, (unsigned)s->newfs_done, s->newfs_rc,
            (unsigned)s->newfs_old_sb_read_failed,
            (unsigned)s->newfs_recovery_read_failed,
            (unsigned)s->mount_done, s->mount_rc, (unsigned)s->mount_error,
            (unsigned)s->mount_integrity_error,
            (unsigned)s->umount_done, s->umount_rc,
            (unsigned long long)r->retired, (unsigned long long)r->fw_calls,
            (unsigned long long)r->device_work) < 0 || fflush(stdout) != 0)
            (void)fg_refuse("PUBLIC refusal metadata output");
        for (unsigned i = 0; i < s->read_count; i++) {
            const struct fm_read_trace *t = &s->reads[i];
            if (printf("PUBLIC_MOUNT_READ index=%u off=%llu len=%zu sectors_without_full_write=%zu first_without_full_write=%llu trace_full=%u partial_write_observed=%u\n",
                i, (unsigned long long)t->off, t->len, t->unwritten,
                (unsigned long long)t->first_unwritten, (unsigned)s->read_trace_full,
                (unsigned)s->partial_write_observed) < 0)
                (void)fg_refuse("PUBLIC read metadata output");
        }
        if (fflush(stdout) != 0) (void)fg_refuse("PUBLIC read metadata flush");
        if (printf("PUBLIC_BARRIER_OBSERVATION done=%u rc=%u open_error=%u ioctl_error=%u flushes=%llu write_seq=%llu flush_seq=%llu\n",
            (unsigned)s->flush_done, s->flush_rc, (unsigned)s->flush_open_error,
            (unsigned)s->flush_ioctl_error, (unsigned long long)s->disk.flushes,
            (unsigned long long)s->disk.write_seq, (unsigned long long)s->disk.flush_seq) < 0 ||
            fflush(stdout) != 0) (void)fg_refuse("PUBLIC barrier metadata output");
}

static bool fm_emit(struct fm_state *s, struct rvmachine_result *r, const char *phase)
{
    uint64_t used;
    if (!fg_work(r, &used)) return false;
    if (printf("PUBLIC_MOUNTED_PROOF phase=%s delivered=32 queued=0 child=%u wrong=%u flushes=%llu write_seq=%llu flush_seq=%llu work=%llu mount_rc=%u superblock_data_read=%u integrity=%u\n",
        phase, (unsigned)s->child, (unsigned)(s->wrong && s->wrong_diag),
        (unsigned long long)s->disk.flushes, (unsigned long long)s->disk.write_seq,
        (unsigned long long)s->disk.flush_seq, (unsigned long long)used, s->mount_rc,
        (unsigned)s->superblock_data_read, (unsigned)s->mount_integrity_error) < 0 || fflush(stdout) != 0) return false;
    return true;
}

static void fm_cleanup(struct fm_state *s, struct rvmachine_disk *outer,
                        struct platform_private_file *owner, uint8_t *kernel)
{
    if (s != NULL) rvmachine_destroy(s->disk.m);
    rvmachine_disk_close(outer);
    if (s != NULL) rvmachine_disk_close(s->disk.inner);
    platform_private_file_close(owner);
    free(kernel);
    if (s != NULL) memory_cleanse(s, sizeof *s);
    free(s);
}

static bool fm_pc_phase_emit(const struct fm_pc_image *image,const struct fm_pc_counts *p,unsigned phase)
{
    if(printf("PUBLIC_PC_ENDPOINT phase=%u u=%u s=%u m=%u unknown=%u invalid=%u limited=%u\n",
        phase,p->mode[0],p->mode[1],p->mode[2],p->mode[3],(unsigned)p->invalid,(unsigned)p->limited)<0)return false;
    for(unsigned i=0;i<9;i++){
        if(p->symbol[i] && printf("PUBLIC_PC_SYMBOL phase=%u symbol=%s samples=%u\n",
            phase,image->symbols[i].name,p->symbol[i])<0)return false;
    }
    if(printf("PUBLIC_PC_S_OTHER phase=%u samples=%u\n",phase,p->symbol[9])<0)return false;
    for(unsigned i=0;i<p->unknown_count;i++)
        if(printf("PUBLIC_PC_S_EXAMPLE phase=%u index=%u pc=%016llx\n",phase,i,
            (unsigned long long)p->unknown_pc[i])<0)return false;
    return true;
}
static bool fm_pc_emit(const struct fm_state *s)
{
    if(!s->diagnostic)return true;
    if(printf("PUBLIC_PC_SCOPE endpoint_only=1 crossings=%u rejected=%u\n",
        s->pc_crossings,s->pc_rejected)<0)return false;
    for(unsigned i=0;i<16;i++)if(!fm_pc_phase_emit(s->diagnostic_image,&s->pc[i],i))return false;
    return true;
}
static bool fm_diagnostic_emit(const struct fm_state *s)
{
    if(!s->diagnostic)return true;
    for(unsigned i=0;i<16;i++){
        if(!(s->diagnostic_seen&(UINT32_C(1)<<i)))continue;
        if(printf("PUBLIC_FORMAT_RETURN step=%u work=%llu upper_boundary=1\n",i,
            (unsigned long long)s->diagnostic_work[i])<0)
            return fg_refuse("PUBLIC formatting metadata output");
    }
    if(!fm_pc_emit(s))return fg_refuse("PUBLIC PC metadata output");
    return fflush(stdout)==0 || fg_refuse("PUBLIC formatting metadata flush");
}
static bool fm_setup(struct fm_state *s,struct platform_private_file *owner,
    struct rvmachine_disk **outer,char **argv,uint8_t **kernel,size_t *kernel_len)
{
    bool candidate=strcmp(argv[1],"mounted-format-candidate")==0;
    s->diagnostic_ram128=strcmp(argv[1],"mounted-format-diagnostic-128m")==0;
    s->diagnostic=candidate || s->diagnostic_ram128 || strcmp(argv[1],"mounted-format-diagnostic")==0;
    s->diagnostic_image=candidate?&fm_pc_candidate:&fm_pc_original;
    if(s->diagnostic){
        int64_t now=platform_time_monotonic_ms();
        if(now<=0)return fg_refuse("PUBLIC formatting admission clock");
        s->diagnostic_admitted=s->diagnostic_last=(uint64_t)now;
        if(!fm_pc_image_qualified(s->diagnostic_image))return false;
    }
    const char *expected=s->diagnostic?s->diagnostic_image->kernel_sha:FM_KERNEL_SHA;
    if(!fg_bind(&s->disk,owner,outer,argv[2],argv[3],kernel,kernel_len,expected))return false;
    rvmachine_disk_close(*outer);
    *outer=NULL;
    return rvmachine_disk_open_backend(outer,FG_VOLUME_BYTES,fm_disk_read,
        fm_disk_write,fm_disk_flush,s)==RVMACHINE_OK &&
        fm_script(s,argv[1]) && fm_create(s,outer,*kernel,*kernel_len);
}
static int fm_main(int argc, char **argv)
{
    if (argc != 4 || strcmp(FM_KERNEL_SHA, "UNQUALIFIED_IMAGE_NO_DISPATCH") == 0)
        return fg_refuse("mounted image packet not yet qualified") ? 0 : 2;
    struct platform_private_file owner;
    struct rvmachine_disk *outer = NULL;
    struct fm_state *s = calloc(1, sizeof *s);
    struct rvmachine_result r = {0};
    uint8_t *kernel = NULL;
    size_t kernel_len = 0;
    int rc = 1;
    platform_private_file_init(&owner);
    if (s == NULL) { (void)fg_refuse("PUBLIC mounted allocation"); goto out; }
    if(!fm_setup(s,&owner,&outer,argv,&kernel,&kernel_len))goto out;
    if (!fm_run(s, &r, strcmp(argv[1], "mounted-wrong") == 0) || !fm_proof(s, argv[1])) goto out;
    if (!fm_emit(s, &r, argv[1])) goto out;
    rc = 0;
out:
    if (rc != 0) (void)fg_refuse("PUBLIC mounted final acceptance");
    if (rc != 0 && s != NULL) fm_refusal(s, &r, argv[1]);
    if(s!=NULL && !fm_diagnostic_emit(s))rc=1;
    fm_cleanup(s, outer, &owner, kernel);
    return rc;
}
