<!-- Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. -->
# Guest loopback SSH with hybrid post-quantum key exchange

## Purpose

Show, inside the unmodified FreeBSD 15.1 riscv64 guest on the built-in RV64
machine, that an `sshd` and `ssh` pair on loopback negotiates a hybrid
post-quantum key exchange (`mlkem768x25519-sha256`,
`sntrup761x25519-sha512`), refuses a classical-only client offer, and refuses
a pinned host key that differs from the server's. Then probe, read only,
whether the published GENERIC kernel exposes the designed `z23.l0.t` virtio
console port.

The helper and launcher for that route are described in
[`2026-10-11-guest-port-raw-helper.md`](./2026-10-11-guest-port-raw-helper.md),
which leaves FreeBSD execution and negotiated key exchange unverified.

## Inputs

| input | value |
| --- | --- |
| binary `Z` | `build/bin/z23.dev`, sha256 `fcfa7bec53683b7284c4e50de16f0c6190cb27fbaf3fa80b736764933bd9b753` (lane tree at `20deadc8c`) |
| kernel `K` | `~/.cache/z23/freebsd-15.1-riscv64/boot/kernel/kernel`, sha256 `69320e312d5601c5fe228aa3bcbdc4bbc55e0d86a4cf9e68eb6ffdc7247701b1`, FreeBSD 15.1-RELEASE GENERIC |
| disk `D` | `~/.cache/z23/freebsd-15.1-riscv64/disk.raw`, sha256 `084980a2299d2a8bca7033fc4eefcc8e22b64096e7952ce63366d8408605ff15` before and after every boot |
| boot input | `$S/boot-pq.json`, sha256 `593edcadc3cee0547a7aea03ac2cd6e15e9fb2b7d74ce3d89ce4a4751377655e` |
| host CPU | AMD Ryzen 7 PRO 8840U w/ Radeon 780M Graphics (host load average about 37 during the runs: another build was running) |
| host compiler on PATH | gcc 16.1.1 20260430 (not used to build anything here) |
| date | 2026-10-11T17:30:12-04:00 (2026-10-11T21:30:12Z) to 2026-10-11T21:40:49Z |
| guest software | `ssh -V`: `OpenSSH_10.0p2, OpenSSL 3.5.6 7 Apr 2026` |

`S` is the scratch directory. Guest disk writes are held in an in-memory
overlay (`overlay_blocks` 4 in the main run); the disk file was not opened for
writing: `inputs.disk.changed` is `false`, the mtime is unchanged, and the
sha256 above is identical before and after.

## Method

One single-user boot with host-seeded entropy (`"entropy":"host"`,
`"early_seed":"host"`). A console script, fired in order after the
single-user shell prompt, did the following inside the guest:

1. Printed `sysctl kern.random.initial_seeding` and the `random` lines of `dmesg`.
2. `mount -u -w /`; `mount -t tmpfs tmpfs /tmp`. Every generated file lives on that tmpfs.
3. `ifconfig lo0 inet 127.0.0.1/8 up`.
4. `ssh-keygen -q -t ed25519 -N ''` three times in `/tmp`: host key `hk`, user key `uk`, and a second host key `wk` used only as the wrong pin.
5. `ak` (authorized keys) is the user public key; `kh` is `[127.0.0.1]:2222 <hk.pub type and key>`, `kh2` is the same line with the `wk` key.
6. Wrote `/tmp/sc`: `ListenAddress 127.0.0.1`, `Port 2222`, `HostKey /tmp/hk`, `KexAlgorithms mlkem768x25519-sha256,sntrup761x25519-sha512`, `PubkeyAuthentication yes`, `PasswordAuthentication no`, `KbdInteractiveAuthentication no`, `AuthorizedKeysFile /tmp/ak`, `PermitRootLogin prohibit-password`, `StrictModes no`, `PidFile /tmp/sshd.pid`, `UsePAM no`; checked with `sshd -t`; started with `/usr/sbin/sshd -f /tmp/sc -E /tmp/sshd.log`.
7. Ran four client cases, each `ssh -vv -p 2222 -i /tmp/uk -o GlobalKnownHostsFile=/dev/null -o StrictHostKeyChecking=yes -o BatchMode=yes -o UserKnownHostsFile=<kh|kh2> -o KexAlgorithms=<alg> root@127.0.0.1 'echo z23-pq-ok-$((6*7))'`, filtered by `grep -E 'kex: algorithm|z23-pq-ok|Authenticated|no matching|Host key verification'`.

Setup facts: `/var/empty` already exists in the release image (`dr-xr-xr-x 2 root wheel`), so no privilege-separation directory had to be created; the scripted `mkdir -p /var/empty` changed nothing. `StrictModes no` was set as specified and is not shown to be required. Console input lines must stay below about 500 characters; a 520 character line was truncated by the guest tty in an earlier attempt (`$S/out-run1-truncated-line.txt`), and the configuration is therefore written in three shorter commands.

## Command

```sh
Z=build/bin/z23.dev
$Z dev app machine boot --input="$(cat $S/boot-pq.json)" > $S/res.json
```

`boot-pq.json` fields: `kernel` K, `disk` D, `ram_mib` 1024,
`bootargs` `-s vfs.root.mountfrom=ufs:/dev/vtbd0p3`, `max_instr` 6000000000,
`entropy` `host`, `early_seed` `host`, `until` `ALL-DONE-2`,
`transcript` `$S/out.txt`, and the 16 `type_after` pairs described above.

## Receipt

| field | value |
| --- | --- |
| `stop` | `requested`, all 16 script steps fired |
| `retired` | 2080752813 |
| `skip` | 21701435 |
| `fw_calls` | 39352 |
| `device_work` | 3543 |
| `guest_time` | 229776716 (timebase 10000000 Hz) |
| `elapsed_ms` (wall) | 635865 |
| `console_bytes` | 12402 |
| `overlay_blocks` | 4 |
| `transcript_sha256` | `292250fb251cdc9be69a0f9387e3b2fca06e3a9c9872f4a67dfc2e6ad6a70e01` |
| `entropy` | `host_os_csprng`, `guest_rng_health` `unobserved` |
| `early_seed` | `host_os_csprng`, 2048 bytes, `cleared` true |

Wall time is far above the 16 million instructions per second seen on an idle
host because the host was loaded.

## Entropy state, as observed before key generation

```
kern.random.initial_seeding.disable_bypass_warnings: 0
kern.random.initial_seeding.arc4random_bypassed_before_seeding: 0
kern.random.initial_seeding.read_random_bypassed_before_seeding: 0
kern.random.initial_seeding.bypass_before_seeding: 1
random: no preloaded entropy cache
random: read 2048 bytes from platform bootloader
random: unblocking device.
random: entropy device external interface
```

Both bypass counters (`arc4random_bypassed_before_seeding`,
`read_random_bypassed_before_seeding`) were 0 when read, which was before the
`ssh-keygen` commands; the device was unblocked from a 2048 byte boot seed
taken from the host OS CSPRNG. `bypass_before_seeding: 1` is the kernel
setting that permits a bypass; it is not a counter. The counters were not read
a second time after key generation. The machine reports
`guest_rng_health: unobserved`: nothing in this run measures the quality of the
seed itself.

## Observed lines

Key exchange cases (verbatim from the transcript):

```
debug1: kex: algorithm: mlkem768x25519-sha256
Authenticated to 127.0.0.1 ([127.0.0.1]:2222) using "publickey".
debug1: Sending command: echo z23-pq-ok-$((6*7))
z23-pq-ok-42
```

```
debug1: kex: algorithm: sntrup761x25519-sha512
Authenticated to 127.0.0.1 ([127.0.0.1]:2222) using "publickey".
debug1: Sending command: echo z23-pq-ok-$((6*7))
z23-pq-ok-42
```

Classical-only client offer:

```
debug1: kex: algorithm: (no match)
Unable to negotiate with 127.0.0.1 port 2222: no matching key exchange method found. Their offer: mlkem768x25519-sha256,sntrup761x25519-sha512,ext-info-s,kex-strict-s-v00@openssh.com
```

Wrong pinned host key (key exchange completed, host key check refused):

```
debug1: kex: algorithm: mlkem768x25519-sha256
Host key verification failed.
```

Server log tail (`/tmp/sshd.log`):

```
Accepted publickey for root from 127.0.0.1 port 15904 ssh2: ED25519 SHA256:faUicgiB5JUMIBQ14M9nzSYLB9H2KuCUljxt6zMH/r0
Received disconnect from 127.0.0.1 port 15904:11: disconnected by user
Disconnected from user root 127.0.0.1 port 15904
Unable to negotiate with 127.0.0.1 port 25774: no matching key exchange method found. Their offer: curve25519-sha256,ext-info-c,kex-strict-c-v00@openssh.com [preauth]
Connection closed by 127.0.0.1 port 19914 [preauth]
```

`sockstat -4l` showed `root sshd 46 7 tcp4 127.0.0.1:2222 *:*`. `sshd -t -f /tmp/sc`
returned 0.

`ssh -Q kex` in the guest:

```
diffie-hellman-group1-sha1
diffie-hellman-group14-sha1
diffie-hellman-group14-sha256
diffie-hellman-group16-sha512
diffie-hellman-group18-sha512
diffie-hellman-group-exchange-sha1
diffie-hellman-group-exchange-sha256
ecdh-sha2-nistp256
ecdh-sha2-nistp384
ecdh-sha2-nistp521
curve25519-sha256
curve25519-sha256@libssh.org
sntrup761x25519-sha512
sntrup761x25519-sha512@openssh.com
mlkem768x25519-sha256
```

## Results

| case | expected | observed |
| --- | --- | --- |
| client `KexAlgorithms=mlkem768x25519-sha256`, pinned correct host key | `kex: algorithm` is the ML-KEM hybrid; publickey login; command output | `kex: algorithm: mlkem768x25519-sha256`, `Authenticated ... using "publickey"`, `z23-pq-ok-42` |
| client `KexAlgorithms=sntrup761x25519-sha512`, pinned correct host key | NTRU Prime hybrid; login; command output | `kex: algorithm: sntrup761x25519-sha512`, `Authenticated ... using "publickey"`, `z23-pq-ok-42` |
| client `KexAlgorithms=curve25519-sha256` against a hybrid-only server | `no matching key exchange method found` | `kex: algorithm: (no match)` and `Unable to negotiate ... no matching key exchange method found`; no login |
| client pins a different Ed25519 host key | host key verification failure | `Host key verification failed.`; no command output |
| `sshd -t`, `sshd` start, listening socket | return 0, listener on 127.0.0.1:2222 | `SSHDT-RC=0`, `SSHD-RC=0`, listener present |
| disk file unchanged by the boot | identical sha256 | `084980a2...ff15` before and after; `inputs.disk.changed` false |

## Designed port route probe (read only)

Inputs: one `ports` row, `{"name":"z23.l0.t","input":"$S/port-in.bin","expect":"$S/port-expect.bin"}`,
with one-byte files (`x` and `y`), same K and D, same host entropy. The run
ends with `PORT_GOAL_MISSED` by construction: no guest program opens the port,
so the fixture bytes are never exchanged (`p0=0/0/0/0@2`). That refusal is the
expected result of the probe and is not an SSH result. No helper was built or
installed. The probe input is `$S/port-probe2.json` (sha256
`aa42725d750bac96afa2c4a697bc3018861b9b058b081e44a1b714c55fd3ad1b`),
transcript `$S/port2.txt` (sha256
`390c099a4d86855e2b88f55f7771fb52e812e4196442c6438a13aeff6c74d7ae`).

Boot without loading modules (`stop=requested`, `retired=434239821`):

```
Id Refs Address                Size Name
 1    1 0xffffffc000000000   a90d58 kernel
ls: /dev/vtcon*: No such file or directory
ls: /dev/vtcon/: No such file or directory
virtio_mmio0: <VirtIO MMIO adapter> mem 0x10001000-0x10001fff irq 3 on simplebus0
vtblk0: <VirtIO Block Adapter> on virtio_mmio0
virtio_mmio1: <VirtIO MMIO adapter> mem 0x10002000-0x10002fff irq 4 on simplebus0
virtio_mmio2: <VirtIO MMIO adapter> mem 0x10003000-0x10003fff irq 5 on simplebus0
```

The console adapter transport exists (`virtio_mmio2` at 0x10003000) but no
driver attaches at boot; `virtio_console` is not in the kernel (`kldstat` shows
only `kernel`) and no `/dev/vtcon` node exists.

Boot with `kldload virtio_console` typed at the prompt
(`$S/port-probe.json`, transcript `$S/port-run1.txt`, sha256
`c340faf519dc4ad28110c34aad972c4b01893347763dc9c84b44f9db1bd132ec`):

```
vtcon0: <VirtIO Console Adapter> on virtio_mmio2
virtio_mmio2: host features: 0x110000002 <Version1,RingIndirectDesc,MultiplePorts>
virtio_mmio2: negotiated features: 0x100000002 <Version1,MultiplePorts>
```

The module loaded, `vtcon0` attached on `virtio_mmio2` and negotiated
`MultiplePorts`. The next shell prompt did not return before the instruction
budget (`stop=budget`, `retired=2999938689` of a 3000000000 budget), so the
following `ls /dev/vtcon*` and `dmesg` output were not observed. This
configuration was run once; a longer budget was not tried, so whether the
`kldload` command eventually completes is not established.

## What this does not establish

- The exchange is loopback inside one guest: client and server are processes of the same FreeBSD instance on `127.0.0.1`. No host-to-guest or machine-to-machine route was used, and the guest has no network device.
- Host and user keys are classical Ed25519, because OpenSSH has no post-quantum signature algorithm. Only the key exchange is hybrid post-quantum; authentication of the peer is not.
- The keys are disposable and exist only in guest tmpfs. Nothing is said about key handling in a deployed route.
- Seeding was observed with both bypass counters at 0 before key generation, but the guest random device health is `unobserved`, and the counters were not re-read afterwards. The host seed comes from the host OS CSPRNG; no claim is made about its use inside the guest beyond the kernel lines quoted.
- The ssh transcript hash and receipt come from a single run. Instruction counts and wall time depend on host load and were not repeated.
- The `z23.l0.t` port was not exercised: no bytes crossed it, no guest helper ran, and with the published GENERIC kernel the console driver is a loadable module whose load did not return a prompt within 3e9 instructions. SSH over that port is untested.
- Whether the negotiated algorithms are the ones the designed route will request is not shown; the fixed launcher requests `mlkem768x25519-sha256` only.
- Key exchange timing and the cost of the hybrid algorithms were not isolated from boot and keygen cost.

## Boot input

`boot-pq.json` as run, with the home directory and the scratch directory
abbreviated to `~` and `$S` (the sha256 above is of the unabbreviated file):

```json
{"kernel":"~/.cache/z23/freebsd-15.1-riscv64/boot/kernel/kernel","disk":"~/.cache/z23/freebsd-15.1-riscv64/disk.raw","ram_mib":1024,"bootargs":"-s vfs.root.mountfrom=ufs:/dev/vtbd0p3","max_instr":6000000000,"entropy":"host","early_seed":"host","until":"ALL-DONE-2","transcript":"$S/out.txt","type_after":[
["RETURN for /bin/sh:","\n"],
["# ","echo SEED-BEGIN; sysctl kern.random.initial_seeding; dmesg | grep -i random; echo SEED-END-$((1+1))\n"],
["# ","mount -u -w / ; mount -t tmpfs tmpfs /tmp ; echo MNT-RC=$? ; mount | grep tmpfs\n"],
["# ","ifconfig lo0 inet 127.0.0.1/8 up; ls -ld /var/empty; mkdir -p /var/empty; ifconfig lo0 | grep inet\n"],
["# ","cd /tmp; ssh-keygen -q -t ed25519 -N '' -f hk; ssh-keygen -q -t ed25519 -N '' -f uk; ssh-keygen -q -t ed25519 -N '' -f wk; ls hk uk wk; echo KEYS-$((1+1))\n"],
["# ","cp uk.pub ak; chmod 600 ak; echo '[127.0.0.1]:2222 '$(cut -d' ' -f1,2 hk.pub) > kh; echo '[127.0.0.1]:2222 '$(cut -d' ' -f1,2 wk.pub) > kh2; wc -l kh kh2; echo KH-$((1+1))\n"],
["# ","(echo ListenAddress 127.0.0.1; echo Port 2222; echo HostKey /tmp/hk; echo PubkeyAuthentication yes; echo PasswordAuthentication no) > sc\n"],
["# ","(echo KexAlgorithms mlkem768x25519-sha256,sntrup761x25519-sha512; echo KbdInteractiveAuthentication no; echo UsePAM no) >> sc\n"],
["# ","(echo AuthorizedKeysFile /tmp/ak; echo PermitRootLogin prohibit-password; echo StrictModes no; echo PidFile /tmp/sshd.pid) >> sc; /usr/sbin/sshd -t -f /tmp/sc; echo SSHDT-RC=$?\n"],
["# ","/usr/sbin/sshd -f /tmp/sc -E /tmp/sshd.log; echo SSHD-RC=$?; sockstat -4l | grep 2222\n"],
["# ","ssh -V 2>&1; ssh -Q kex 2>&1; echo Q-$((1+1))\n"],
["# ","ssh -vv -p 2222 -i /tmp/uk -o GlobalKnownHostsFile=/dev/null -o StrictHostKeyChecking=yes -o BatchMode=yes -o UserKnownHostsFile=/tmp/kh -o KexAlgorithms=mlkem768x25519-sha256 root@127.0.0.1 'echo z23-pq-ok-$((6*7))' 2>&1 | grep -E 'kex: algorithm|z23-pq-ok|Authenticated|no matching|Host key verification'; echo CASE-MLKEM-END-$((1+1))\n"],
["# ","ssh -vv -p 2222 -i /tmp/uk -o GlobalKnownHostsFile=/dev/null -o StrictHostKeyChecking=yes -o BatchMode=yes -o UserKnownHostsFile=/tmp/kh -o KexAlgorithms=sntrup761x25519-sha512 root@127.0.0.1 'echo z23-pq-ok-$((6*7))' 2>&1 | grep -E 'kex: algorithm|z23-pq-ok|Authenticated|no matching|Host key verification'; echo CASE-SNTRUP-END-$((1+1))\n"],
["# ","ssh -vv -p 2222 -i /tmp/uk -o GlobalKnownHostsFile=/dev/null -o StrictHostKeyChecking=yes -o BatchMode=yes -o UserKnownHostsFile=/tmp/kh -o KexAlgorithms=curve25519-sha256 root@127.0.0.1 'echo z23-pq-ok-$((6*7))' 2>&1 | grep -E 'kex: algorithm|z23-pq-ok|Authenticated|no matching|Host key verification'; echo CASE-CURVE-END-$((1+1))\n"],
["# ","ssh -vv -p 2222 -i /tmp/uk -o GlobalKnownHostsFile=/dev/null -o StrictHostKeyChecking=yes -o BatchMode=yes -o UserKnownHostsFile=/tmp/kh2 -o KexAlgorithms=mlkem768x25519-sha256 root@127.0.0.1 'echo z23-pq-ok-$((6*7))' 2>&1 | grep -E 'kex: algorithm|z23-pq-ok|Authenticated|no matching|Host key verification'; echo CASE-WRONGPIN-END-$((1+1))\n"],
["# ","tail -5 /tmp/sshd.log; echo ALL-DONE-$((1+1))\n"]
]}

```
