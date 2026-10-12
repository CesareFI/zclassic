# Copyright 2026 Rhett Creighton. Licensed under Apache-2.0.

add_executable(zcl-blue-wallet-review
    src/blue_wallet_review_cli.c
    src/blue_mainnet_branch.c
    src/blue_chain_tip.c
    src/blue_utxo.c
    src/blue_payment_live.c
    src/blue_payment_simulate.c
    src/blue_payment_screen.c
    src/blue_payment_review.c
    src/zcl_tx_replay_zip243.c
    src/zcl_tx_stream.c
    src/zcl_tx_prevout.c
    src/zcl_tx_script_facts.c
    src/zcl_tx_review.c
    src/zcl_zip243.c
    src/zcl_zip243_host.c
    src/zcl_base58.c
    src/ledger_hid.c
    src/ledger_probe.c
    ../../contexts/commons/packages/zsha256/src/zsha256.c
    ../../core/modules/crypto/src/blake2b.c
    ../../platform/modules/base/src/log_level.c
    ../../platform/modules/base/src/safe_alloc.c
    ../../platform/modules/json/src/json.c)
target_include_directories(zcl-blue-wallet-review PRIVATE
    include
    ../../contexts/commons/packages/zsha256/include
    ../../core/modules/crypto/include
    ../../platform/modules/util/include
    ../../platform/modules/base/include
    ../../platform/modules/json/include)
target_compile_definitions(zcl-blue-wallet-review PRIVATE
    _POSIX_C_SOURCE=200809L)
target_compile_options(zcl-blue-wallet-review PRIVATE
    -Wall -Wextra -Werror -pedantic)

add_executable(zcl-blue-shielded-review
    src/blue_shielded_review_cli.c
    src/blue_shielded_review_client.c
    src/blue_shielded_review_app.c
    src/blue_shielded_review_apdu.c
    src/blue_review_screen.c
    src/blue_mainnet_branch.c
    src/zcl_tx_shielded_replay.c
    src/zcl_tx_shielded_stream.c
    src/zcl_tx_review.c
    src/zcl_tx_script_facts.c
    src/zcl_zip243.c
    src/zcl_zip243_host.c
    src/zcl_base58.c
    src/ledger_hid.c
    src/ledger_probe.c
    ../../contexts/commons/packages/zsha256/src/zsha256.c
    ../../core/modules/crypto/src/blake2b.c
    ../../platform/modules/base/src/log_level.c)
target_include_directories(zcl-blue-shielded-review PRIVATE
    include
    ../../contexts/commons/packages/zsha256/include
    ../../core/modules/crypto/include
    ../../platform/modules/util/include
    ../../platform/modules/base/include)
target_compile_definitions(zcl-blue-shielded-review PRIVATE
    _POSIX_C_SOURCE=200809L)
target_compile_options(zcl-blue-shielded-review PRIVATE
    -Wall -Wextra -Werror -pedantic)
