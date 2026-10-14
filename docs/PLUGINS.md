<!-- Copyright 2026 Rhett Creighton - Apache License 2.0 -->

# Signed plugin store

`z23 plugin` keeps plugin executables under `~/.z23/plugins`. A plugin is
installed only when its manifest is strictly formed, its detached Ed25519
signature verifies against a key listed in `trusted_keys`, and the executable
matches the SHA3-512 in the signed manifest. The daemon is not involved: these
commands read and write files only.

## Layout

```text
~/.z23/plugins/
  trusted_keys                      one public key per line
  NAME/
    generations/<SHA3-512 hex>/
      NAME                          executable, mode 0555
      NAME.plugin.json              manifest, mode 0444
      NAME.plugin.sig               signature, mode 0444
    current    -> generations/<id>  symbolic link
    last-good  -> generations/<id>  symbolic link
```

The generation id is the executable's SHA3-512 as 128 lowercase hex
characters. Installing stores a generation and leaves `current` alone.
`switch` and `rollback` replace the links by creating a temporary symbolic link
beside them and renaming it over the old one, so a reader sees the old or the
new target and never a missing link. An interrupted swap leaves `current`
unchanged; the next swap removes the leftover temporary link.

## Permissions

`trusted_keys` must be a regular file owned by you and not writable by group or
others. `~/.z23/plugins`, each `NAME` directory and each `generations`
directory must be real directories with the same ownership and mode rule.
Nothing inside the store may be a symbolic link except `current` and
`last-good`, whose targets must have the form `generations/<128 hex>`. A
violation is refused with `PLUGIN_TRUST_INSECURE`.

## Manifest

`NAME.plugin.json` must contain exactly these keys. An unknown or repeated key
is refused.

```json
{
  "schema": "z23.plugin.v1",
  "name": "hello",
  "version": "1.0.0",
  "interface_version": 1,
  "sha3_512": "<128 lowercase hex: SHA3-512 of the executable>",
  "capabilities": ["fs.read", "clock"]
}
```

- `name`: 1 to 32 characters from `a-z`, `0-9`, `-`; it must match the file
  name `NAME.plugin.json`.
- `version`: 1 to 64 characters from `A-Za-z0-9.+-`.
- `interface_version`: integer, at least 1.
- `capabilities`: distinct entries from `fs.read`, `fs.write`, `net.client`,
  `net.server`, `process.spawn`, `clock`, `ui.panel`.

## Signature

`NAME.plugin.sig` is a JSON object with exactly `sig_alg`, `public_key` and
`signature`:

```json
{"sig_alg":"ed25519","public_key":"<64 hex>","signature":"<128 hex>"}
```

`sig_alg` must be `ed25519`. The signature covers the 64-byte SHA3-512 digest
of the bytes `z23.plugin.manifest.v1`, one NUL byte, and the exact bytes of
`NAME.plugin.json`. Any edit to the manifest, including whitespace, invalidates
it.

## Trust file

`~/.z23/plugins/trusted_keys` holds one full Ed25519 public key per line as 64
hex characters. Blank lines are ignored; any other line is refused. The file
must exist and name at least one key.

```sh
mkdir -p ~/.z23/plugins
printf '%s\n' <64-hex-public-key> >> ~/.z23/plugins/trusted_keys
```

## Commands

```sh
z23 plugin install ./hello.plugin.json     # signature file and executable sit beside it
z23 plugin list
z23 plugin switch hello <128-hex generation>
z23 plugin rollback hello
```

- `install` verifies the source files, copies them to a staging directory,
  verifies the copy again, then renames it into `generations/`. Installing a
  generation that is already stored and verifies reports `already_present` and
  changes nothing. A stored generation that fails verification is moved aside
  and replaced by the verified staged copy, so `current` never keeps pointing
  at a broken generation.
- `list` prints, for each plugin, `current`, `last_good` and every stored
  generation.
- `switch` verifies the generation again, sets `last-good` to the previous
  `current`, then points `current` at the generation. Switching to the
  generation that is already current changes nothing.
- `rollback` verifies the `last-good` generation again and points `current` at
  it.

`install`, `switch` and `rollback` are owner commands and are never accepted
from a mesh peer. Their authority is the publisher signature checked against
the owner's trust file on every install, switch and rollback; the node daemon
state is untouched.

## Refusal codes

Every refusal carries `error.code` and `error.next_action`.

| Code | Meaning |
| --- | --- |
| `PLUGIN_ARGUMENT` | Missing or malformed argument, or `HOME` is not absolute. |
| `PLUGIN_NO_TRUST` | `trusted_keys` is absent or names no key. |
| `PLUGIN_TRUST_MALFORMED` | A `trusted_keys` line is not 64 hex characters. |
| `PLUGIN_MANIFEST_MISSING` | The manifest file does not exist. |
| `PLUGIN_MANIFEST_INVALID` | Not JSON, wrong schema, or a field outside its rules. |
| `PLUGIN_MANIFEST_DUPLICATE_KEY` | A manifest key appears twice. |
| `PLUGIN_MANIFEST_UNKNOWN_KEY` | A manifest key is not in the schema. |
| `PLUGIN_SIG_MISSING` | The signature file does not exist. |
| `PLUGIN_SIG_INVALID` | Signature file is malformed or has unknown or repeated keys. |
| `PLUGIN_SIG_ALG` | `sig_alg` is not `ed25519`. |
| `PLUGIN_KEY_UNTRUSTED` | The signing key is not in `trusted_keys`. |
| `PLUGIN_SIG_BAD` | The signature does not verify for the manifest bytes. |
| `PLUGIN_EXE_MISSING` | The executable does not exist. |
| `PLUGIN_EXE_HASH` | The executable's SHA3-512 differs from the manifest. |
| `PLUGIN_NOT_INSTALLED` | No plugin of that name is stored. |
| `PLUGIN_NO_GENERATION` | The named generation is not stored. |
| `PLUGIN_NO_LAST_GOOD` | No `switch` has recorded a last-good generation. |
| `PLUGIN_TRUST_INSECURE` | `trusted_keys` or the store has a wrong owner, is group or world writable, or contains a symbolic link or non-regular file. |
| `PLUGIN_IO` | A file operation failed; check permissions and free space. |

## Tests

```sh
make CC=gcc-14 t-fast-exact ONLY=plugin_store
```
