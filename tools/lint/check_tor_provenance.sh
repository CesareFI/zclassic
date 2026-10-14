#!/bin/sh
# Copyright 2026 Rhett Creighton - Apache License 2.0
# purpose: the bundled Tor archives are bound to the vendor/tor commit, bytes and compiler.
exec "$(dirname "$0")/../../build/bin/z23-lint" check-tor-provenance "$@"
