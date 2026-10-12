/* Copyright 2026 Rhett Creighton; SPDX-License-Identifier: Apache-2.0
 * Fixed PUBLIC initial-volume preparation, shared with host refusal controls. */
static bool gb_prepare_live(int64_t end)
{
    int64_t now=GB_PREP_NOW();
    return now>=0 && now<end;
}
static bool gb_prepare_page(int fd, off_t offset, int64_t end)
{
    const unsigned char zero[4096]={0};
    size_t used=0;
    while (used<sizeof zero) {
        if (!gb_prepare_live(end)) return false;
        ssize_t n=GB_PREP_WRITE(fd,zero+used,sizeof zero-used,offset+(off_t)used);
        int saved_errno=errno;
        if (!gb_prepare_live(end)) return false;
        if (n<0 && saved_errno==EINTR) continue;
        if (n<=0 || (size_t)n>sizeof zero-used) return false;
        used+=(size_t)n;
    }
    return true;
}
static bool gb_prepare_pages(int fd, int64_t end)
{
    static const off_t offsets[]={8192,12288,61440,65536,69632};
    for (unsigned i=0;i<sizeof offsets/sizeof offsets[0];i++) {
        if (!gb_prepare_page(fd,offsets[i],end)) return false;
        if (i==1 || i==4) {
            if (!gb_prepare_live(end) || GB_PREP_SYNC(fd)!=0 || !gb_prepare_live(end)) return false;
        }
    }
    return true;
}
static bool gb_prepare_provider(int fd, int64_t end)
{
    struct stat st;
    off_t size=0;
    return fd>=3 && gb_prepare_live(end) && GB_PREP_STAT(fd,&st)==0 && S_ISCHR(st.st_mode) &&
        gb_prepare_live(end) && GB_PREP_SIZE(fd,&size)==0 && size==14909440 &&
        gb_prepare_live(end) && GB_PREP_CONFINE(fd) && gb_prepare_live(end);
}
static bool gb_initial_prepare(int64_t end)
{
    if (!gb_prepare_live(end)) {
        (void)GB_PREP_DIAG("PUBLIC_BOOTSTRAP_PREPARE_DEADLINE\n",end);
        return false;
    }
    int fd=GB_PREP_OPEN("/dev/vtbd0.eli",O_RDWR|O_CLOEXEC);
    if (fd<0) {
        (void)GB_PREP_DIAG("PUBLIC_BOOTSTRAP_PREPARE_OPEN\n",end);
        return false;
    }
    bool ok=gb_prepare_provider(fd,end) && gb_prepare_pages(fd,end);
    /* The successful open owns this descriptor even if it aliases missing stdio.
     * Close exactly once; retrying an ambiguous close could target another fd. */
    bool closed=GB_PREP_CLOSE(fd)==0;
    bool timely=gb_prepare_live(end);
    if (!ok || !closed || !timely) {
        (void)GB_PREP_DIAG("PUBLIC_BOOTSTRAP_PREPARE_REFUSED\n",end);
        return false;
    }
    return true;
}
static bool gb_prepare_finish(bool initial, bool attach_ok, int64_t end)
{
    if (!attach_ok) return false;
    return !initial || gb_initial_prepare(end);
}
