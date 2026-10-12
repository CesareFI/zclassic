# Copyright 2026 Rhett Creighton. Licensed under Apache-2.0.
cmake_minimum_required(VERSION 3.21)
project(zcl_ledger C)

set(CMAKE_C_STANDARD 23)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

option(ZCL_LEDGER_REVIEW_ONLY
    "Build the read-only Blue wallet reviewer without OpenSSL or PNG" OFF)
if(ZCL_LEDGER_REVIEW_ONLY)
    include(cmake/ReviewOnly.cmake)
    return()
endif()

add_library(ledger_hid STATIC src/ledger_hid.c src/ledger_probe.c)
target_include_directories(ledger_hid PUBLIC include)
target_compile_options(ledger_hid PRIVATE -Wall -Wextra -Werror -pedantic)

find_package(OpenSSL 3 REQUIRED COMPONENTS Crypto)
find_package(PNG REQUIRED)
add_library(zcl_sha256 STATIC
    ../../contexts/commons/packages/zsha256/src/zsha256.c)
target_include_directories(zcl_sha256 PUBLIC
    ../../contexts/commons/packages/zsha256/include)
target_compile_options(zcl_sha256 PRIVATE -Wall -Wextra -Werror -pedantic)
add_library(zcl_host_crypto STATIC
    src/zcl_host_crypto.c
    ../../contexts/commons/packages/zripemd/src/zripemd.c)
target_include_directories(zcl_host_crypto PUBLIC include PRIVATE
    ../../vendor/include
    ../../contexts/commons/packages/zripemd/include)
target_link_libraries(zcl_host_crypto PUBLIC zcl_sha256 PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/../../vendor/lib/libsecp256k1.a)
target_compile_options(zcl_host_crypto PRIVATE
    -Wall -Wextra -Werror -pedantic)
if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    target_compile_options(zcl_host_crypto PRIVATE
        -fsanitize=address,undefined -fno-omit-frame-pointer)
endif()
add_library(blue_payment_fixture STATIC src/blue_payment_fixture.c)
target_include_directories(blue_payment_fixture PUBLIC include)
target_link_libraries(blue_payment_fixture PUBLIC zcl_sha256)
target_compile_options(blue_payment_fixture PRIVATE
    -Wall -Wextra -Werror -pedantic)
if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    target_compile_options(blue_payment_fixture PRIVATE
        -fsanitize=address,undefined -fno-omit-frame-pointer)
endif()
add_library(zcl_base58 STATIC src/zcl_base58.c)
target_include_directories(zcl_base58 PUBLIC include)
target_compile_options(zcl_base58 PRIVATE -Wall -Wextra -Werror -pedantic)

add_library(zcl_address STATIC src/zcl_address.c)
target_include_directories(zcl_address PUBLIC include)
target_link_libraries(zcl_address PUBLIC zcl_base58 zcl_host_crypto)
target_compile_options(zcl_address PRIVATE -Wall -Wextra -Werror -pedantic)

add_library(zcl_sign_test STATIC src/zcl_sign_test.c)
target_include_directories(zcl_sign_test PUBLIC include)
target_link_libraries(zcl_sign_test PUBLIC OpenSSL::Crypto)
target_compile_options(zcl_sign_test PRIVATE -Wall -Wextra -Werror -pedantic)

add_executable(zcl-blue-sign-test src/blue_sign_test_cli.c)
target_link_libraries(zcl-blue-sign-test PRIVATE ledger_hid zcl_address zcl_sign_test)
target_compile_options(zcl-blue-sign-test PRIVATE -Wall -Wextra -Werror -pedantic)

add_library(zcl_tx_review STATIC src/zcl_tx_review.c)
target_include_directories(zcl_tx_review PUBLIC include)
target_compile_options(zcl_tx_review PRIVATE -Wall -Wextra -Werror -pedantic)

add_library(zcl_tx_previous_stream STATIC src/zcl_tx_previous_stream.c)
target_include_directories(zcl_tx_previous_stream PUBLIC include)
target_compile_options(zcl_tx_previous_stream PRIVATE
    -Wall -Wextra -Werror -pedantic)

add_library(zcl_tx_script_facts STATIC src/zcl_tx_script_facts.c)
target_include_directories(zcl_tx_script_facts PUBLIC include)
target_link_libraries(zcl_tx_script_facts PUBLIC zcl_tx_review)
target_compile_options(zcl_tx_script_facts PRIVATE -Wall -Wextra -Werror -pedantic)

add_library(zcl_zip243 STATIC src/zcl_zip243.c)
target_include_directories(zcl_zip243 PUBLIC include)
target_link_libraries(zcl_zip243 PUBLIC zcl_tx_review)
target_compile_options(zcl_zip243 PRIVATE -Wall -Wextra -Werror -pedantic)

add_library(zcl_zip243_host_hash STATIC
    src/zcl_zip243_host.c
    ../../core/modules/crypto/src/blake2b.c
    ../../platform/modules/base/src/log_level.c)
target_include_directories(zcl_zip243_host_hash PUBLIC
    include
    ../../core/modules/crypto/include
    ../../platform/modules/util/include
    ../../platform/modules/base/include)
target_compile_definitions(zcl_zip243_host_hash PRIVATE _POSIX_C_SOURCE=200809L)
target_compile_options(zcl_zip243_host_hash PRIVATE -Wall -Wextra -Werror -pedantic)

add_library(blue_sapling_ock STATIC src/blue_sapling_ock.c)
target_include_directories(blue_sapling_ock PUBLIC include)
target_compile_options(blue_sapling_ock PRIVATE -Wall -Wextra -Werror -pedantic)
if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    target_compile_options(blue_sapling_ock PRIVATE
        -fsanitize=address,undefined -fno-omit-frame-pointer)
endif()

add_library(blue_sapling_aead STATIC src/blue_sapling_aead.c)
target_include_directories(blue_sapling_aead PUBLIC include)
target_compile_options(blue_sapling_aead PRIVATE
    -Wall -Wextra -Werror -pedantic)
if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    target_compile_options(blue_sapling_aead PRIVATE
        -fsanitize=address,undefined -fno-omit-frame-pointer)
endif()

add_library(blue_sapling_memo STATIC src/blue_sapling_memo.c)
target_include_directories(blue_sapling_memo PUBLIC include)
target_link_libraries(blue_sapling_memo PUBLIC zcl_sha256)
target_compile_options(blue_sapling_memo PRIVATE
    -Wall -Wextra -Werror -pedantic)
if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    target_compile_options(blue_sapling_memo PRIVATE
        -fsanitize=address,undefined -fno-omit-frame-pointer)
endif()

add_executable(test-blue-sapling-memo tests/test_blue_sapling_memo.c)
target_link_libraries(test-blue-sapling-memo PRIVATE blue_sapling_memo)
target_compile_options(test-blue-sapling-memo PRIVATE
    -Wall -Wextra -Werror -pedantic)
if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    target_compile_options(test-blue-sapling-memo PRIVATE
        -fsanitize=address,undefined -fno-omit-frame-pointer)
    target_link_options(test-blue-sapling-memo PRIVATE
        -fsanitize=address,undefined)
endif()
add_test(NAME blue-sapling-memo COMMAND test-blue-sapling-memo)

add_executable(test-blue-sapling-ock
    tests/test_blue_sapling_ock.c
    src/blue_sapling_epk.c
    src/blue_sapling_cm.c
    src/blue_sapling_group_hash.c
    src/blue_jubjub_lowmem.c src/blue_jubjub_arithmetic.c
    src/blue_jubjub_encode.c src/blue_jubjub_decode.c
    src/blue_fr_ct.c src/blue_fr_sqrt.c src/blue_fs_ct.c
    src/blue_mod256.c
    ../../core/modules/sapling/src/fr.c
    ../../core/modules/sapling/src/fr_avx512.c
    ../../core/modules/crypto/src/simd_dispatch.c
    ../../core/modules/crypto/src/blake2s.c
    ../../core/modules/crypto/src/chacha20poly1305.c)
target_link_libraries(test-blue-sapling-ock PRIVATE
    blue_sapling_ock blue_sapling_aead blue_sapling_kdf blue_sapling_memo
    zcl_zip243_host_hash)
target_include_directories(test-blue-sapling-ock PRIVATE
    ../../core/modules/sapling/include
    ../../core/modules/crypto/include
    ../../platform/modules/base/include
    ../../platform/modules/support/include
    ../../platform/modules/platform/include
    ../../platform/modules/util/include)
target_compile_definitions(test-blue-sapling-ock PRIVATE
    _POSIX_C_SOURCE=200809L)
target_compile_options(test-blue-sapling-ock PRIVATE
    -Wall -Wextra -Werror -pedantic)
if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    target_compile_options(test-blue-sapling-ock PRIVATE
        -O2 -fsanitize=address,undefined -fno-omit-frame-pointer)
    target_link_options(test-blue-sapling-ock PRIVATE
        -fsanitize=address,undefined)
endif()
add_test(NAME blue-sapling-ock COMMAND test-blue-sapling-ock
    ${CMAKE_CURRENT_SOURCE_DIR}/tests/fixtures/simnet-sapling-spend.hex)

add_library(blue_sapling_kdf STATIC src/blue_sapling_kdf.c)
target_include_directories(blue_sapling_kdf PUBLIC include)
target_compile_options(blue_sapling_kdf PRIVATE -Wall -Wextra -Werror -pedantic)
if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    target_compile_options(blue_sapling_kdf PRIVATE
        -fsanitize=address,undefined -fno-omit-frame-pointer)
endif()

add_executable(test-blue-sapling-kdf tests/test_blue_sapling_kdf.c)
target_link_libraries(test-blue-sapling-kdf PRIVATE
    blue_sapling_kdf zcl_zip243_host_hash)
target_compile_options(test-blue-sapling-kdf PRIVATE
    -Wall -Wextra -Werror -pedantic)
if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    target_compile_options(test-blue-sapling-kdf PRIVATE
        -fsanitize=address,undefined -fno-omit-frame-pointer)
    target_link_options(test-blue-sapling-kdf PRIVATE
        -fsanitize=address,undefined)
endif()
add_test(NAME blue-sapling-kdf COMMAND test-blue-sapling-kdf)

add_library(zcl_tx_prevout STATIC src/zcl_tx_prevout.c)
target_include_directories(zcl_tx_prevout PUBLIC include)
target_link_libraries(zcl_tx_prevout PUBLIC zcl_tx_script_facts zcl_zip243)
target_compile_options(zcl_tx_prevout PRIVATE -Wall -Wextra -Werror -pedantic)

add_library(zcl_tx_stream STATIC src/zcl_tx_stream.c)
target_include_directories(zcl_tx_stream PUBLIC include)
target_compile_options(zcl_tx_stream PRIVATE -Wall -Wextra -Werror -pedantic)

add_library(zcl_tx_stream_zip243 STATIC src/zcl_tx_stream_zip243.c)
target_include_directories(zcl_tx_stream_zip243 PUBLIC include)
target_link_libraries(zcl_tx_stream_zip243 PUBLIC zcl_tx_stream)
target_compile_options(zcl_tx_stream_zip243 PRIVATE -Wall -Wextra -Werror -pedantic)

add_library(zcl_tx_replay_zip243 STATIC src/zcl_tx_replay_zip243.c)
target_include_directories(zcl_tx_replay_zip243 PUBLIC include)
target_link_libraries(zcl_tx_replay_zip243 PUBLIC zcl_tx_stream)
target_compile_options(zcl_tx_replay_zip243 PRIVATE -Wall -Wextra -Werror -pedantic)

add_library(blue_payment_review STATIC src/blue_payment_review.c)
target_include_directories(blue_payment_review PUBLIC include)
target_link_libraries(blue_payment_review PUBLIC zcl_tx_replay_zip243)
target_compile_options(blue_payment_review PRIVATE -Wall -Wextra -Werror -pedantic)

add_library(blue_payment_screen STATIC src/blue_payment_screen.c)
target_include_directories(blue_payment_screen PUBLIC include)
target_link_libraries(blue_payment_screen PUBLIC blue_payment_review zcl_base58)
target_compile_options(blue_payment_screen PRIVATE -Wall -Wextra -Werror -pedantic)

add_library(blue_mainnet_branch STATIC src/blue_mainnet_branch.c)
target_include_directories(blue_mainnet_branch PUBLIC include)
target_compile_options(blue_mainnet_branch PRIVATE
    -Wall -Wextra -Werror -pedantic)
if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    target_compile_options(blue_mainnet_branch PRIVATE
        -fsanitize=address,undefined -fno-omit-frame-pointer)
endif()

add_library(blue_payment_apdu STATIC src/blue_payment_apdu.c)
target_include_directories(blue_payment_apdu PUBLIC include)
target_link_libraries(blue_payment_apdu PUBLIC blue_payment_screen
    zcl_tx_previous_stream blue_mainnet_branch)
target_compile_options(blue_payment_apdu PRIVATE -Wall -Wextra -Werror -pedantic)

add_library(blue_review_protocol STATIC src/blue_review_protocol.c)
target_include_directories(blue_review_protocol PUBLIC include)
target_link_libraries(blue_review_protocol PUBLIC zcl_tx_review zcl_zip243)
target_compile_options(blue_review_protocol PRIVATE -Wall -Wextra -Werror -pedantic)

add_library(blue_review_screen STATIC src/blue_review_screen.c)
target_include_directories(blue_review_screen PUBLIC include)
target_link_libraries(blue_review_screen PUBLIC zcl_tx_script_facts zcl_base58)
target_compile_options(blue_review_screen PRIVATE -Wall -Wextra -Werror -pedantic)

add_library(blue_review_app STATIC device-blue-review/src/blue_review_app.c
    src/blue_review_accessible.c)
target_include_directories(blue_review_app PUBLIC include)
target_link_libraries(blue_review_app PUBLIC blue_review_protocol blue_review_screen)
target_compile_options(blue_review_app PRIVATE -Wall -Wextra -Werror -pedantic)

add_library(blue_review_simulate STATIC src/blue_review_simulate.c)
target_include_directories(blue_review_simulate PUBLIC include)
target_link_libraries(blue_review_simulate PUBLIC blue_review_app zcl_zip243_host_hash OpenSSL::Crypto)
target_compile_options(blue_review_simulate PRIVATE -Wall -Wextra -Werror -pedantic)

add_executable(zcl-tx-review src/tx_review_cli.c)
target_link_libraries(zcl-tx-review PRIVATE zcl_address zcl_tx_review zcl_tx_script_facts zcl_zip243_host_hash blue_review_protocol blue_review_simulate ledger_hid OpenSSL::Crypto)
target_compile_options(zcl-tx-review PRIVATE -Wall -Wextra -Werror -pedantic)

add_library(blue_bagl_canvas STATIC src/blue_bagl_canvas.c)
target_include_directories(blue_bagl_canvas PUBLIC include)
target_link_libraries(blue_bagl_canvas PUBLIC PNG::PNG)
target_compile_options(blue_bagl_canvas PRIVATE -Wall -Wextra -Werror -pedantic)

add_library(blue_payment_render STATIC src/blue_payment_render.c)
target_include_directories(blue_payment_render PUBLIC include)
target_link_libraries(blue_payment_render PUBLIC blue_payment_screen blue_bagl_canvas)
target_compile_options(blue_payment_render PRIVATE -Wall -Wextra -Werror -pedantic)

add_library(blue_payment_simulate STATIC src/blue_payment_simulate.c)
target_include_directories(blue_payment_simulate PUBLIC include)
target_link_libraries(blue_payment_simulate PUBLIC blue_payment_screen
    zcl_zip243_host_hash zcl_sha256)
target_compile_options(blue_payment_simulate PRIVATE -Wall -Wextra -Werror -pedantic)

add_library(blue_payment_live STATIC src/blue_payment_live.c)
target_include_directories(blue_payment_live PUBLIC include)
target_link_libraries(blue_payment_live PUBLIC blue_payment_simulate
    zcl_tx_stream zcl_sha256)
target_compile_options(blue_payment_live PRIVATE -Wall -Wextra -Werror -pedantic)

add_library(blue_chain_tip STATIC src/blue_chain_tip.c
    ../../platform/modules/json/src/json.c
    ../../platform/modules/base/src/safe_alloc.c)
target_include_directories(blue_chain_tip PUBLIC include
    ../../platform/modules/json/include ../../platform/modules/base/include)
target_compile_options(blue_chain_tip PRIVATE -Wall -Wextra -Werror -pedantic)
add_library(blue_utxo STATIC src/blue_utxo.c)
target_include_directories(blue_utxo PUBLIC include)
target_link_libraries(blue_utxo PUBLIC blue_chain_tip zcl_tx_prevout
    zcl_tx_script_facts zcl_sha256)
target_compile_options(blue_utxo PRIVATE -Wall -Wextra -Werror -pedantic)
add_executable(zcl-blue-wallet-review src/blue_wallet_review_cli.c
    src/blue_mainnet_branch.c)
target_include_directories(zcl-blue-wallet-review PRIVATE include)
target_link_libraries(zcl-blue-wallet-review PRIVATE blue_payment_live blue_utxo
    ledger_hid zcl_sha256)
target_compile_options(zcl-blue-wallet-review PRIVATE
    -Wall -Wextra -Werror -pedantic)

add_executable(zcl-blue-payment-sim src/blue_payment_sim_cli.c)
target_link_libraries(zcl-blue-payment-sim PRIVATE blue_payment_simulate
    blue_payment_render)
target_compile_options(zcl-blue-payment-sim PRIVATE -Wall -Wextra -Werror -pedantic)

add_library(blue_wallet_receive STATIC src/blue_wallet_receive.c)
target_include_directories(blue_wallet_receive PUBLIC include)
target_compile_options(blue_wallet_receive PRIVATE -Wall -Wextra -Werror -pedantic)

add_library(blue_wallet_protocol STATIC src/blue_wallet_protocol.c)
target_include_directories(blue_wallet_protocol PUBLIC include)
target_compile_options(blue_wallet_protocol PRIVATE -Wall -Wextra -Werror -pedantic)

add_library(blue_wallet_render STATIC src/blue_wallet_render.c)
target_include_directories(blue_wallet_render PUBLIC include)
target_link_libraries(blue_wallet_render PUBLIC blue_wallet_receive blue_bagl_canvas)
target_compile_options(blue_wallet_render PRIVATE -Wall -Wextra -Werror -pedantic)

add_executable(zcl-blue-wallet-preview src/blue_wallet_preview_cli.c)
target_link_libraries(zcl-blue-wallet-preview PRIVATE blue_wallet_render zcl_address)
target_compile_options(zcl-blue-wallet-preview PRIVATE -Wall -Wextra -Werror -pedantic)

add_library(blue_host_gui STATIC src/blue_host_gui.c)
target_include_directories(blue_host_gui PUBLIC include PRIVATE
    ../../contexts/commons/packages/zripemd/include)
target_link_libraries(blue_host_gui PUBLIC blue_payment_simulate
    blue_payment_fixture zcl_tx_prevout zcl_zip243_host_hash zcl_address
    zcl_sha256 blue_wallet_protocol blue_install_params blue_bagl_canvas
    zcl_host_crypto)
target_compile_options(blue_host_gui PRIVATE -Wall -Wextra -Werror -pedantic)

find_package(PkgConfig REQUIRED)
pkg_check_modules(GTK3 REQUIRED gtk+-3.0)
add_executable(zcl-blue-host-gui src/blue_host_gui_cli.c src/blue_host_gui_window.c)
target_include_directories(zcl-blue-host-gui PRIVATE ${GTK3_INCLUDE_DIRS})
target_link_libraries(zcl-blue-host-gui PRIVATE blue_host_gui ${GTK3_LIBRARIES})
target_compile_options(zcl-blue-host-gui PRIVATE -Wall -Wextra -Werror -pedantic
    ${GTK3_CFLAGS_OTHER})
set_source_files_properties(src/blue_host_gui_window.c PROPERTIES
    COMPILE_OPTIONS "-Wno-pedantic;-Wno-deprecated-declarations")

add_library(blue_review_render STATIC src/blue_review_render.c)
target_include_directories(blue_review_render PUBLIC include)
target_link_libraries(blue_review_render PUBLIC blue_review_app blue_bagl_canvas)
target_compile_options(blue_review_render PRIVATE -Wall -Wextra -Werror -pedantic)

add_executable(zcl-blue-screen-sim src/blue_screen_sim_cli.c)
target_link_libraries(zcl-blue-screen-sim PRIVATE blue_review_render blue_review_simulate)
target_compile_options(zcl-blue-screen-sim PRIVATE -Wall -Wextra -Werror -pedantic)

add_executable(zcl-ledger src/main.c)
target_link_libraries(zcl-ledger PRIVATE ledger_hid zcl_address blue_wallet_protocol)
target_compile_options(zcl-ledger PRIVATE -Wall -Wextra -Werror -pedantic)

add_library(blue_secure STATIC src/blue_secure.c)
target_include_directories(blue_secure PUBLIC include)
target_link_libraries(blue_secure PUBLIC OpenSSL::Crypto)
target_compile_options(blue_secure PRIVATE -Wall -Wextra -Werror -pedantic)

add_library(blue_app_catalog STATIC src/blue_app_catalog.c)
target_include_directories(blue_app_catalog PUBLIC include)
target_compile_options(blue_app_catalog PRIVATE -Wall -Wextra -Werror -pedantic)

add_library(blue_install_params STATIC src/blue_install_params.c)
target_include_directories(blue_install_params PUBLIC include)
target_compile_options(blue_install_params PRIVATE -Wall -Wextra -Werror -pedantic)

add_library(blue_ca STATIC src/blue_ca.c)
target_include_directories(blue_ca PUBLIC include)
target_link_libraries(blue_ca PUBLIC blue_secure)
target_compile_options(blue_ca PRIVATE -Wall -Wextra -Werror -pedantic)

add_executable(zcl-blue-ca src/blue_ca_cli.c)
target_link_libraries(zcl-blue-ca PRIVATE blue_ca)
target_compile_options(zcl-blue-ca PRIVATE -Wall -Wextra -Werror -pedantic)

add_executable(zcl-blue-install src/blue_install.c)
target_link_libraries(zcl-blue-install PRIVATE ledger_hid blue_secure blue_ca blue_install_params blue_app_catalog)
target_compile_options(zcl-blue-install PRIVATE -Wall -Wextra -Werror -pedantic)

if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    foreach(target ledger_hid zcl_base58 zcl_address zcl_sign_test zcl-blue-sign-test zcl_tx_review zcl_tx_previous_stream zcl_tx_script_facts zcl_zip243 zcl_zip243_host_hash zcl_tx_prevout zcl_tx_stream zcl_tx_stream_zip243 zcl_tx_replay_zip243 blue_payment_review blue_payment_screen blue_payment_apdu blue_payment_render blue_payment_simulate blue_payment_live blue_chain_tip blue_utxo zcl-blue-payment-sim zcl-blue-wallet-review blue_review_protocol blue_review_screen blue_review_app blue_review_simulate blue_bagl_canvas blue_wallet_receive blue_wallet_protocol blue_wallet_render zcl-blue-wallet-preview blue_host_gui zcl-blue-host-gui blue_review_render zcl-blue-screen-sim zcl-tx-review zcl-ledger blue_secure blue_app_catalog blue_install_params blue_ca zcl-blue-ca zcl-blue-install)
        target_compile_options(${target} PRIVATE -fsanitize=address,undefined -fno-omit-frame-pointer)
        target_link_options(${target} PUBLIC -fsanitize=address,undefined)
    endforeach()
endif()

enable_testing()
add_executable(test-zcl-tx-previous-stream
    tests/test_zcl_tx_previous_stream.c)
target_link_libraries(test-zcl-tx-previous-stream PRIVATE
    zcl_tx_previous_stream zcl_tx_review OpenSSL::Crypto)
target_compile_options(test-zcl-tx-previous-stream PRIVATE
    -Wall -Wextra -Werror -pedantic)
if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    target_compile_options(test-zcl-tx-previous-stream PRIVATE
        -fsanitize=address,undefined -fno-omit-frame-pointer)
    target_link_options(test-zcl-tx-previous-stream PRIVATE
        -fsanitize=address,undefined)
endif()
add_test(NAME zcl-tx-previous-stream COMMAND test-zcl-tx-previous-stream)
add_executable(test-blue-bagl-canvas tests/test_blue_bagl_canvas.c)
target_link_libraries(test-blue-bagl-canvas PRIVATE blue_bagl_canvas)
target_compile_options(test-blue-bagl-canvas PRIVATE -Wall -Wextra -Werror -pedantic)
if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    target_compile_options(test-blue-bagl-canvas PRIVATE -fsanitize=address,undefined -fno-omit-frame-pointer)
    target_link_options(test-blue-bagl-canvas PRIVATE -fsanitize=address,undefined)
endif()
add_test(NAME blue-bagl-canvas COMMAND test-blue-bagl-canvas)

add_executable(test-blue-wallet-receive tests/test_blue_wallet_receive.c)
target_link_libraries(test-blue-wallet-receive PRIVATE blue_wallet_receive)
target_compile_options(test-blue-wallet-receive PRIVATE -Wall -Wextra -Werror -pedantic)
if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    target_compile_options(test-blue-wallet-receive PRIVATE -fsanitize=address,undefined -fno-omit-frame-pointer)
    target_link_options(test-blue-wallet-receive PRIVATE -fsanitize=address,undefined)
endif()
add_test(NAME blue-wallet-receive COMMAND test-blue-wallet-receive)

add_executable(test-blue-wallet-protocol tests/test_blue_wallet_protocol.c)
target_link_libraries(test-blue-wallet-protocol PRIVATE blue_wallet_protocol)
target_compile_options(test-blue-wallet-protocol PRIVATE -Wall -Wextra -Werror -pedantic)
if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    target_compile_options(test-blue-wallet-protocol PRIVATE -fsanitize=address,undefined -fno-omit-frame-pointer)
    target_link_options(test-blue-wallet-protocol PRIVATE -fsanitize=address,undefined)
endif()
add_test(NAME blue-wallet-protocol COMMAND test-blue-wallet-protocol)

add_executable(test-ledger-hid tests/test_ledger_hid.c)
target_link_libraries(test-ledger-hid PRIVATE ledger_hid)
target_compile_options(test-ledger-hid PRIVATE -Wall -Wextra -Werror -pedantic)
if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    target_compile_options(test-ledger-hid PRIVATE -fsanitize=address,undefined -fno-omit-frame-pointer)
    target_link_options(test-ledger-hid PRIVATE -fsanitize=address,undefined)
endif()
add_test(NAME ledger-hid COMMAND test-ledger-hid)

add_executable(test-ledger-hid-io tests/test_ledger_hid_io.c)
target_link_libraries(test-ledger-hid-io PRIVATE ledger_hid)
target_compile_options(test-ledger-hid-io PRIVATE -Wall -Wextra -Werror -pedantic)
if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    target_compile_options(test-ledger-hid-io PRIVATE -fsanitize=address,undefined -fno-omit-frame-pointer)
    target_link_options(test-ledger-hid-io PRIVATE -fsanitize=address,undefined)
endif()
add_test(NAME ledger-hid-io COMMAND test-ledger-hid-io)

add_executable(test-blue-secure tests/test_blue_secure.c)
target_link_libraries(test-blue-secure PRIVATE blue_secure)
target_compile_options(test-blue-secure PRIVATE -Wall -Wextra -Werror -pedantic)
if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    target_compile_options(test-blue-secure PRIVATE -fsanitize=address,undefined -fno-omit-frame-pointer)
    target_link_options(test-blue-secure PRIVATE -fsanitize=address,undefined)
endif()
add_test(NAME blue-secure COMMAND test-blue-secure)

add_executable(test-blue-app-catalog tests/test_blue_app_catalog.c)
target_link_libraries(test-blue-app-catalog PRIVATE blue_app_catalog)
target_compile_options(test-blue-app-catalog PRIVATE -Wall -Wextra -Werror -pedantic)
if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    target_compile_options(test-blue-app-catalog PRIVATE -fsanitize=address,undefined -fno-omit-frame-pointer)
    target_link_options(test-blue-app-catalog PRIVATE -fsanitize=address,undefined)
endif()
add_test(NAME blue-app-catalog COMMAND test-blue-app-catalog)

add_executable(test-blue-ca tests/test_blue_ca.c)
target_link_libraries(test-blue-ca PRIVATE blue_ca)
target_compile_options(test-blue-ca PRIVATE -Wall -Wextra -Werror -pedantic)
if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    target_compile_options(test-blue-ca PRIVATE -fsanitize=address,undefined -fno-omit-frame-pointer)
    target_link_options(test-blue-ca PRIVATE -fsanitize=address,undefined)
endif()
add_test(NAME blue-ca COMMAND test-blue-ca)

add_executable(test-blue-install-params tests/test_blue_install_params.c)
target_link_libraries(test-blue-install-params PRIVATE blue_install_params)
target_compile_options(test-blue-install-params PRIVATE -Wall -Wextra -Werror -pedantic)
if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    target_compile_options(test-blue-install-params PRIVATE -fsanitize=address,undefined -fno-omit-frame-pointer)
    target_link_options(test-blue-install-params PRIVATE -fsanitize=address,undefined)
endif()
add_test(NAME blue-install-params COMMAND test-blue-install-params)

add_executable(test-blue-install-image-cli tests/test_blue_install_image_cli.c)
target_compile_options(test-blue-install-image-cli PRIVATE
    -Wall -Wextra -Werror -pedantic)
if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    target_compile_options(test-blue-install-image-cli PRIVATE
        -fsanitize=address,undefined -fno-omit-frame-pointer)
    target_link_options(test-blue-install-image-cli PRIVATE
        -fsanitize=address,undefined)
endif()
add_test(NAME blue-install-image-cli COMMAND test-blue-install-image-cli
    $<TARGET_FILE:zcl-blue-install>)

add_executable(test-blue-install-wallet-0346 tests/test_blue_install_wallet_0346.c)
target_link_libraries(test-blue-install-wallet-0346 PRIVATE zcl_sha256)
target_compile_options(test-blue-install-wallet-0346 PRIVATE
    -Wall -Wextra -Werror -pedantic)
if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    target_compile_options(test-blue-install-wallet-0346 PRIVATE
        -fsanitize=address,undefined -fno-omit-frame-pointer)
    target_link_options(test-blue-install-wallet-0346 PRIVATE
        -fsanitize=address,undefined)
endif()
add_test(NAME blue-install-wallet-0346 COMMAND test-blue-install-wallet-0346
    $<TARGET_FILE:zcl-blue-install>
    ${CMAKE_CURRENT_SOURCE_DIR}/tests/fixtures/zcl-wallet-0.3.46.text)

add_executable(test-blue-host-gui tests/test_blue_host_gui.c)
target_link_libraries(test-blue-host-gui PRIVATE blue_host_gui
    blue_install_params)
target_compile_options(test-blue-host-gui PRIVATE -Wall -Wextra -Werror -pedantic)
if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    target_compile_options(test-blue-host-gui PRIVATE
        -fsanitize=address,undefined -fno-omit-frame-pointer)
    target_link_options(test-blue-host-gui PRIVATE -fsanitize=address,undefined)
endif()
add_test(NAME blue-host-gui COMMAND test-blue-host-gui)

add_executable(test-zcl-address tests/test_zcl_address.c)
target_link_libraries(test-zcl-address PRIVATE zcl_address)
target_compile_options(test-zcl-address PRIVATE -Wall -Wextra -Werror -pedantic)
if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    target_compile_options(test-zcl-address PRIVATE -fsanitize=address,undefined -fno-omit-frame-pointer)
    target_link_options(test-zcl-address PRIVATE -fsanitize=address,undefined)
endif()
add_test(NAME zcl-address COMMAND test-zcl-address)

add_executable(test-zcl-sign-test tests/test_zcl_sign_test.c)
target_link_libraries(test-zcl-sign-test PRIVATE zcl_sign_test)
target_compile_options(test-zcl-sign-test PRIVATE -Wall -Wextra -Werror -pedantic)
if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    target_compile_options(test-zcl-sign-test PRIVATE -fsanitize=address,undefined -fno-omit-frame-pointer)
    target_link_options(test-zcl-sign-test PRIVATE -fsanitize=address,undefined)
endif()
add_test(NAME zcl-sign-test COMMAND test-zcl-sign-test)

add_executable(test-zcl-tx-review tests/test_zcl_tx_review.c)
target_link_libraries(test-zcl-tx-review PRIVATE zcl_tx_review)
target_compile_options(test-zcl-tx-review PRIVATE -Wall -Wextra -Werror -pedantic)
if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    target_compile_options(test-zcl-tx-review PRIVATE -fsanitize=address,undefined -fno-omit-frame-pointer)
    target_link_options(test-zcl-tx-review PRIVATE -fsanitize=address,undefined)
endif()
add_test(NAME zcl-tx-review COMMAND test-zcl-tx-review)

add_executable(test-zcl-tx-script-facts tests/test_zcl_tx_script_facts.c)
target_link_libraries(test-zcl-tx-script-facts PRIVATE zcl_tx_script_facts)
target_compile_options(test-zcl-tx-script-facts PRIVATE -Wall -Wextra -Werror -pedantic)
if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    target_compile_options(test-zcl-tx-script-facts PRIVATE -fsanitize=address,undefined -fno-omit-frame-pointer)
    target_link_options(test-zcl-tx-script-facts PRIVATE -fsanitize=address,undefined)
endif()
add_test(NAME zcl-tx-script-facts COMMAND test-zcl-tx-script-facts)

add_executable(test-zcl-tx-prevout tests/test_zcl_tx_prevout.c)
target_link_libraries(test-zcl-tx-prevout PRIVATE zcl_tx_prevout
    zcl_zip243_host_hash OpenSSL::Crypto)
target_compile_options(test-zcl-tx-prevout PRIVATE -Wall -Wextra -Werror -pedantic)
if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    target_compile_options(test-zcl-tx-prevout PRIVATE -fsanitize=address,undefined -fno-omit-frame-pointer)
    target_link_options(test-zcl-tx-prevout PRIVATE -fsanitize=address,undefined)
endif()
add_test(NAME zcl-tx-prevout COMMAND test-zcl-tx-prevout
    ${CMAKE_CURRENT_SOURCE_DIR}/tests/fixtures/zip243-transparent-vector3.hex)

add_executable(test-zcl-tx-stream tests/test_zcl_tx_stream.c)
target_link_libraries(test-zcl-tx-stream PRIVATE zcl_tx_stream zcl_tx_review)
target_compile_options(test-zcl-tx-stream PRIVATE -Wall -Wextra -Werror -pedantic)
if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    target_compile_options(test-zcl-tx-stream PRIVATE -fsanitize=address,undefined -fno-omit-frame-pointer)
    target_link_options(test-zcl-tx-stream PRIVATE -fsanitize=address,undefined)
endif()
add_test(NAME zcl-tx-stream COMMAND test-zcl-tx-stream)

add_executable(test-blue-payment-review tests/test_blue_payment_review.c)
target_link_libraries(test-blue-payment-review PRIVATE blue_payment_review
    blue_payment_screen blue_payment_apdu blue_payment_simulate
    blue_payment_live blue_payment_sign blue_payment_host_sign
    blue_payment_host_assemble blue_payment_host_ownership
    blue_payment_fixture
    zcl_zip243 zcl_tx_prevout
    zcl_zip243_host_hash OpenSSL::Crypto)
target_compile_options(test-blue-payment-review PRIVATE -Wall -Wextra -Werror -pedantic)
if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    target_compile_options(test-blue-payment-review PRIVATE -fsanitize=address,undefined -fno-omit-frame-pointer)
    target_link_options(test-blue-payment-review PRIVATE -fsanitize=address,undefined)
endif()
add_test(NAME blue-payment-review COMMAND test-blue-payment-review)

add_executable(test-blue-payment-fixture tests/test_blue_payment_fixture.c)
target_link_libraries(test-blue-payment-fixture PRIVATE
    blue_payment_fixture blue_payment_live zcl_tx_prevout
    zcl_zip243_host_hash zcl_sha256)
target_compile_options(test-blue-payment-fixture PRIVATE
    -Wall -Wextra -Werror -pedantic)
if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    target_compile_options(test-blue-payment-fixture PRIVATE
        -fsanitize=address,undefined -fno-omit-frame-pointer)
    target_link_options(test-blue-payment-fixture PRIVATE
        -fsanitize=address,undefined)
endif()
add_test(NAME blue-payment-fixture COMMAND test-blue-payment-fixture)

add_library(blue_ecdsa_der STATIC src/blue_ecdsa_der.c)
target_include_directories(blue_ecdsa_der PUBLIC include)
target_compile_options(blue_ecdsa_der PRIVATE -Wall -Wextra -Werror -pedantic)

add_library(blue_payment_sign STATIC src/blue_payment_sign.c)
target_include_directories(blue_payment_sign PUBLIC include)
target_link_libraries(blue_payment_sign PUBLIC
    blue_payment_apdu blue_ecdsa_der)
target_compile_options(blue_payment_sign PRIVATE
    -Wall -Wextra -Werror -pedantic)
if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    foreach(target blue_ecdsa_der blue_payment_sign)
        target_compile_options(${target} PRIVATE
            -fsanitize=address,undefined -fno-omit-frame-pointer)
    endforeach()
endif()

add_library(blue_payment_host_verify STATIC src/blue_payment_host_verify.c)
target_include_directories(blue_payment_host_verify PUBLIC include)
target_link_libraries(blue_payment_host_verify PUBLIC blue_ecdsa_der)
target_compile_options(blue_payment_host_verify PRIVATE
    -Wall -Wextra -Werror -pedantic)
if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    target_compile_options(blue_payment_host_verify PRIVATE
        -fsanitize=address,undefined -fno-omit-frame-pointer)
endif()

add_library(blue_payment_host_sign STATIC src/blue_payment_host_sign.c)
target_include_directories(blue_payment_host_sign PUBLIC include)
target_link_libraries(blue_payment_host_sign PUBLIC
    blue_payment_live blue_payment_host_verify)
target_compile_options(blue_payment_host_sign PRIVATE
    -Wall -Wextra -Werror -pedantic)
if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    target_compile_options(blue_payment_host_sign PRIVATE
        -fsanitize=address,undefined -fno-omit-frame-pointer)
endif()

add_library(blue_payment_host_assemble STATIC src/blue_payment_host_assemble.c)
target_include_directories(blue_payment_host_assemble PUBLIC include)
target_link_libraries(blue_payment_host_assemble PUBLIC
    blue_payment_host_verify zcl_tx_script_facts zcl_tx_review zcl_sha256)
target_compile_options(blue_payment_host_assemble PRIVATE
    -Wall -Wextra -Werror -pedantic)
if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    target_compile_options(blue_payment_host_assemble PRIVATE
        -fsanitize=address,undefined -fno-omit-frame-pointer)
endif()

add_library(blue_payment_host_ownership STATIC
    src/blue_payment_host_ownership.c)
target_include_directories(blue_payment_host_ownership PUBLIC include)
target_link_libraries(blue_payment_host_ownership PUBLIC zcl_tx_prevout)
target_compile_options(blue_payment_host_ownership PRIVATE
    -Wall -Wextra -Werror -pedantic)
if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    target_compile_options(blue_payment_host_ownership PRIVATE
        -fsanitize=address,undefined -fno-omit-frame-pointer)
endif()

add_library(blue_signed_output STATIC src/blue_signed_output.c)
target_include_directories(blue_signed_output PUBLIC include)
target_compile_options(blue_signed_output PRIVATE
    -Wall -Wextra -Werror -pedantic)
if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    target_compile_options(blue_signed_output PRIVATE
        -fsanitize=address,undefined -fno-omit-frame-pointer)
endif()

add_executable(zcl-blue-wallet-sign src/blue_wallet_review_cli.c
    src/blue_mainnet_branch.c)
target_include_directories(zcl-blue-wallet-sign PRIVATE include)
target_compile_definitions(zcl-blue-wallet-sign PRIVATE BLUE_WALLET_SIGN_CLI=1)
target_link_libraries(zcl-blue-wallet-sign PRIVATE blue_payment_live blue_utxo
    blue_payment_host_ownership blue_payment_host_sign
    blue_payment_host_assemble blue_signed_output zcl_address
    zcl_host_crypto ledger_hid zcl_sha256)
target_compile_options(zcl-blue-wallet-sign PRIVATE
    -Wall -Wextra -Werror -pedantic)
if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    target_compile_options(zcl-blue-wallet-sign PRIVATE
        -fsanitize=address,undefined -fno-omit-frame-pointer)
    target_link_options(zcl-blue-wallet-sign PRIVATE
        -fsanitize=address,undefined)
endif()

add_executable(test-blue-payment-host-ownership
    tests/test_blue_payment_host_ownership.c)
target_link_libraries(test-blue-payment-host-ownership PRIVATE
    blue_payment_host_ownership blue_payment_fixture zcl_sha256)
target_compile_options(test-blue-payment-host-ownership PRIVATE
    -Wall -Wextra -Werror -pedantic)
if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    target_compile_options(test-blue-payment-host-ownership PRIVATE
        -fsanitize=address,undefined -fno-omit-frame-pointer)
    target_link_options(test-blue-payment-host-ownership PRIVATE
        -fsanitize=address,undefined)
endif()
add_test(NAME blue-payment-host-ownership
    COMMAND test-blue-payment-host-ownership)

add_executable(test-blue-jubjub-lowmem
    src/blue_jubjub_lowmem.c src/blue_jubjub_arithmetic.c src/blue_fr_ct.c
    src/blue_fr_sqrt.c src/blue_jubjub_encode.c
    src/blue_jubjub_decode.c src/blue_mod256.c
    tests/test_blue_jubjub_lowmem.c
    ../../core/modules/sapling/src/fr.c
    ../../core/modules/sapling/src/fr_avx512.c
    ../../core/modules/crypto/src/simd_dispatch.c)
target_include_directories(test-blue-jubjub-lowmem PRIVATE
    include ../../core/modules/sapling/include
    ../../core/modules/crypto/include)
target_compile_options(test-blue-jubjub-lowmem PRIVATE
    -Wall -Wextra -Werror -pedantic)
if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    target_compile_options(test-blue-jubjub-lowmem PRIVATE
        -O2 -fsanitize=address,undefined -fno-omit-frame-pointer)
    target_link_options(test-blue-jubjub-lowmem PRIVATE
        -fsanitize=address,undefined)
endif()
add_test(NAME blue-jubjub-lowmem COMMAND test-blue-jubjub-lowmem)

add_executable(test-blue-fr-ct
    src/blue_fr_ct.c src/blue_fr_sqrt.c src/blue_mod256.c
    tests/test_blue_fr_ct.c
    ../../core/modules/sapling/src/fr.c
    ../../core/modules/sapling/src/fr_avx512.c
    ../../core/modules/crypto/src/simd_dispatch.c)
target_include_directories(test-blue-fr-ct PRIVATE
    include ../../core/modules/sapling/include
    ../../core/modules/crypto/include)
target_compile_options(test-blue-fr-ct PRIVATE
    -Wall -Wextra -Werror -pedantic)
if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    target_compile_options(test-blue-fr-ct PRIVATE
        -O2 -fsanitize=address,undefined -fno-omit-frame-pointer)
    target_link_options(test-blue-fr-ct PRIVATE
        -fsanitize=address,undefined)
endif()
add_test(NAME blue-fr-ct COMMAND test-blue-fr-ct)

add_executable(test-blue-fs-ct
    src/blue_fs_ct.c src/blue_mod256.c tests/test_blue_fs_ct.c
    ../../core/modules/sapling/src/fr.c
    ../../core/modules/sapling/src/fr_avx512.c
    ../../core/modules/crypto/src/simd_dispatch.c)
target_include_directories(test-blue-fs-ct PRIVATE
    include ../../core/modules/sapling/include
    ../../core/modules/crypto/include)
target_compile_options(test-blue-fs-ct PRIVATE
    -Wall -Wextra -Werror -pedantic)
if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    target_compile_options(test-blue-fs-ct PRIVATE
        -O2 -fsanitize=address,undefined -fno-omit-frame-pointer)
    target_link_options(test-blue-fs-ct PRIVATE
        -fsanitize=address,undefined)
endif()
add_test(NAME blue-fs-ct COMMAND test-blue-fs-ct)

add_executable(test-blue-redjubjub-equation
    src/blue_fs_ct.c src/blue_fr_ct.c src/blue_mod256.c
    src/blue_jubjub_arithmetic.c src/blue_jubjub_lowmem.c
    src/blue_jubjub_encode.c src/blue_redjubjub_challenge.c
    src/blue_redjubjub_response.c
    src/blue_redjubjub_sign_isolated.c src/blue_redjubjub_nonce.c
    src/blue_sapling_spend_auth.c
    src/blue_sapling_generators.c src/blue_zip32_master.c
    src/blue_zip32_fvk.c src/blue_zip32_child.c
    src/blue_zip32_seed_bridge.c
    tests/test_blue_redjubjub_equation.c
    ../../core/modules/sapling/src/jubjub.c
    ../../core/modules/sapling/src/fr.c
    ../../core/modules/sapling/src/fr_avx512.c
    ../../core/modules/crypto/src/simd_dispatch.c)
target_include_directories(test-blue-redjubjub-equation PRIVATE
    include tests ../../core/modules/sapling/include
    ../../core/modules/crypto/include)
target_link_libraries(test-blue-redjubjub-equation PRIVATE
    zcl_zip243 zcl_zip243_host_hash zcl_tx_shielded_replay)
target_compile_options(test-blue-redjubjub-equation PRIVATE
    -Wall -Wextra -Werror -pedantic)
if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    target_compile_options(test-blue-redjubjub-equation PRIVATE
        -O2 -fsanitize=address,undefined -fno-omit-frame-pointer)
    target_link_options(test-blue-redjubjub-equation PRIVATE
        -fsanitize=address,undefined)
endif()
add_test(NAME blue-redjubjub-equation COMMAND test-blue-redjubjub-equation
    ${CMAKE_CURRENT_SOURCE_DIR}/tests/fixtures/simnet-sapling-spend.hex)

add_executable(test-blue-zip32-master
    tests/test_blue_zip32_master.c src/blue_zip32_master.c
    src/blue_zip32_seed_bridge.c
    device-blue-wallet/candidate/blue_zip32_seed_device.c
    src/blue_mod256.c ../../core/modules/sapling/src/jubjub.c)
target_include_directories(test-blue-zip32-master PRIVATE
    tests/blue_wallet_signer_stub device-blue-wallet/candidate
    include ../../core/modules/sapling/include
    ../../core/modules/crypto/include)
target_link_libraries(test-blue-zip32-master PRIVATE zcl_zip243_host_hash)
target_compile_options(test-blue-zip32-master PRIVATE
    -Wall -Wextra -Werror -pedantic)
if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    target_compile_options(test-blue-zip32-master PRIVATE
        -O2 -fsanitize=address,undefined -fno-omit-frame-pointer)
    target_link_options(test-blue-zip32-master PRIVATE
        -fsanitize=address,undefined)
endif()
add_test(NAME blue-zip32-master COMMAND test-blue-zip32-master)

add_executable(test-blue-sapling-entropy-device
    tests/test_blue_sapling_entropy_device.c
    device-blue-wallet/candidate/blue_sapling_entropy_device.c
    src/blue_mod256.c)
target_include_directories(test-blue-sapling-entropy-device PRIVATE
    tests/blue_sapling_device_stub device-blue-wallet/candidate include)
target_compile_options(test-blue-sapling-entropy-device PRIVATE
    -Wall -Wextra -Werror -pedantic)
if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    target_compile_options(test-blue-sapling-entropy-device PRIVATE
        -O2 -fsanitize=address,undefined -fno-omit-frame-pointer)
    target_link_options(test-blue-sapling-entropy-device PRIVATE
        -fsanitize=address,undefined)
endif()
add_test(NAME blue-sapling-entropy-device
    COMMAND test-blue-sapling-entropy-device)

add_executable(test-blue-sapling-spend-device
    tests/test_blue_sapling_spend_device.c
    device-blue-wallet/candidate/blue_sapling_spend_device.c
    src/blue_mod256.c)
target_include_directories(test-blue-sapling-spend-device PRIVATE
    tests/blue_sapling_device_stub device-blue-wallet/candidate
    include ../../core/modules/sapling/include)
target_compile_options(test-blue-sapling-spend-device PRIVATE
    -Wall -Wextra -Werror -pedantic
    -DZCL_BLUE_SYNTHETIC_SEED_FIXTURE=1)
if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    target_compile_options(test-blue-sapling-spend-device PRIVATE
        -O2 -fsanitize=address,undefined -fno-omit-frame-pointer)
    target_link_options(test-blue-sapling-spend-device PRIVATE
        -fsanitize=address,undefined)
endif()
add_test(NAME blue-sapling-spend-device
    COMMAND test-blue-sapling-spend-device)

add_executable(test-blue-scalar-reducer
    tests/test_blue_scalar_reducer.c
    ../../core/modules/sapling/src/jubjub.c
    ../../core/modules/sapling/src/fr.c
    ../../core/modules/sapling/src/fr_avx512.c
    ../../core/modules/crypto/src/simd_dispatch.c)
target_include_directories(test-blue-scalar-reducer PRIVATE
    ../../core/modules/sapling/include ../../core/modules/crypto/include)
target_compile_options(test-blue-scalar-reducer PRIVATE
    -Wall -Wextra -Werror -pedantic)
if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    target_compile_options(test-blue-scalar-reducer PRIVATE
        -O2 -fsanitize=address,undefined -fno-omit-frame-pointer)
    target_link_options(test-blue-scalar-reducer PRIVATE
        -fsanitize=address,undefined)
endif()
add_test(NAME blue-scalar-reducer COMMAND test-blue-scalar-reducer)

add_executable(test-blue-redjubjub-challenge
    tests/test_blue_redjubjub_challenge.c
    src/blue_redjubjub_challenge.c
    ../../core/modules/sapling/src/jubjub.c)
target_include_directories(test-blue-redjubjub-challenge PRIVATE
    include ../../core/modules/sapling/include
    ../../core/modules/crypto/include)
target_link_libraries(test-blue-redjubjub-challenge PRIVATE
    zcl_zip243_host_hash)
target_compile_options(test-blue-redjubjub-challenge PRIVATE
    -Wall -Wextra -Werror -pedantic)
if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    target_compile_options(test-blue-redjubjub-challenge PRIVATE
        -O2 -fsanitize=address,undefined -fno-omit-frame-pointer)
    target_link_options(test-blue-redjubjub-challenge PRIVATE
        -fsanitize=address,undefined)
endif()
add_test(NAME blue-redjubjub-challenge COMMAND test-blue-redjubjub-challenge)

add_executable(test-blue-redjubjub-nonce
    tests/test_blue_redjubjub_nonce.c
    src/blue_redjubjub_nonce.c
    ../../core/modules/sapling/src/jubjub.c)
target_include_directories(test-blue-redjubjub-nonce PRIVATE
    include ../../core/modules/sapling/include
    ../../core/modules/crypto/include)
target_link_libraries(test-blue-redjubjub-nonce PRIVATE
    zcl_zip243_host_hash)
target_compile_options(test-blue-redjubjub-nonce PRIVATE
    -Wall -Wextra -Werror -pedantic)
if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    target_compile_options(test-blue-redjubjub-nonce PRIVATE
        -O2 -fsanitize=address,undefined -fno-omit-frame-pointer)
    target_link_options(test-blue-redjubjub-nonce PRIVATE
        -fsanitize=address,undefined)
endif()
add_test(NAME blue-redjubjub-nonce COMMAND test-blue-redjubjub-nonce)

find_program(BLUE_ARM_GCC NAMES arm-none-eabi-gcc)
find_program(BLUE_QEMU NAMES qemu-system-arm)
if(BLUE_ARM_GCC AND BLUE_QEMU)
    execute_process(COMMAND ${BLUE_ARM_GCC} -print-file-name=rdimon.specs
        OUTPUT_VARIABLE BLUE_RDIMON_SPECS OUTPUT_STRIP_TRAILING_WHITESPACE)
    if(EXISTS "${BLUE_RDIMON_SPECS}")
        set(BLUE_M3_IMAGE "${CMAKE_CURRENT_BINARY_DIR}/blue-m3-qemu.elf")
        set(BLUE_SAPLING_ARM_SOURCES
            "${CMAKE_CURRENT_SOURCE_DIR}/tests/blue_m3_qemu.c"
            "${CMAKE_CURRENT_SOURCE_DIR}/src/blue_redjubjub_challenge.c"
            "${CMAKE_CURRENT_SOURCE_DIR}/src/blue_redjubjub_nonce.c"
            "${CMAKE_CURRENT_SOURCE_DIR}/src/blue_redjubjub_response.c"
            "${CMAKE_CURRENT_SOURCE_DIR}/src/blue_redjubjub_sign_isolated.c"
            "${CMAKE_CURRENT_SOURCE_DIR}/src/blue_sapling_spend_auth.c"
            "${CMAKE_CURRENT_SOURCE_DIR}/src/blue_sapling_aead.c"
            "${CMAKE_CURRENT_SOURCE_DIR}/src/blue_sapling_memo.c"
            "${CMAKE_CURRENT_SOURCE_DIR}/src/blue_sapling_epk.c"
            "${CMAKE_CURRENT_SOURCE_DIR}/src/blue_sapling_group_hash.c"
            "${CMAKE_CURRENT_SOURCE_DIR}/src/blue_zip32_master.c"
            "${CMAKE_CURRENT_SOURCE_DIR}/src/blue_zip32_fvk.c"
            "${CMAKE_CURRENT_SOURCE_DIR}/src/blue_zip32_child.c"
            "${CMAKE_CURRENT_SOURCE_DIR}/src/blue_zip32_seed_bridge.c"
            "${CMAKE_CURRENT_SOURCE_DIR}/device-blue-wallet/candidate/blue_zip32_seed_device.c"
            "${CMAKE_CURRENT_SOURCE_DIR}/device-blue-wallet/candidate/blue_sapling_entropy_device.c"
            "${CMAKE_CURRENT_SOURCE_DIR}/device-blue-wallet/candidate/blue_sapling_spend_device.c"
            "${CMAKE_CURRENT_SOURCE_DIR}/src/blue_sapling_generators.c"
            "${CMAKE_CURRENT_SOURCE_DIR}/src/blue_mod256.c"
            "${CMAKE_CURRENT_SOURCE_DIR}/src/blue_fr_ct.c"
            "${CMAKE_CURRENT_SOURCE_DIR}/src/blue_fr_sqrt.c"
            "${CMAKE_CURRENT_SOURCE_DIR}/src/blue_fs_ct.c"
            "${CMAKE_CURRENT_SOURCE_DIR}/src/blue_jubjub_arithmetic.c"
            "${CMAKE_CURRENT_SOURCE_DIR}/src/blue_jubjub_lowmem.c"
            "${CMAKE_CURRENT_SOURCE_DIR}/src/blue_jubjub_encode.c"
            "${CMAKE_CURRENT_SOURCE_DIR}/src/blue_jubjub_decode.c"
            "${CMAKE_CURRENT_SOURCE_DIR}/../../core/modules/sapling/src/jubjub.c"
            "${CMAKE_CURRENT_SOURCE_DIR}/../../core/modules/crypto/src/blake2b.c")
        list(APPEND BLUE_SAPLING_ARM_SOURCES
            "${CMAKE_CURRENT_SOURCE_DIR}/../../core/modules/crypto/src/blake2s.c")
        list(APPEND BLUE_SAPLING_ARM_SOURCES
            "${CMAKE_CURRENT_SOURCE_DIR}/../../contexts/commons/packages/zsha256/src/zsha256.c")
        set(BLUE_SAPLING_ARM_DEPENDS
            ${BLUE_SAPLING_ARM_SOURCES}
            tests/blue_m3_qemu.ld tests/blue_consensus_spend_fixture.h
            include/blue_mod256.h include/blue_fr_ct.h
            include/blue_fr_sqrt.h include/blue_fs_ct.h
            include/blue_jubjub_arithmetic.h include/blue_jubjub_lowmem.h
            include/blue_jubjub_encode.h
            include/blue_jubjub_decode.h
            include/blue_redjubjub_challenge.h
            include/blue_redjubjub_nonce.h
            include/blue_redjubjub_response.h
            include/blue_redjubjub_sign_isolated.h
            include/blue_sapling_spend_auth.h
            include/blue_sapling_aead.h
            include/blue_sapling_memo.h
            include/blue_sapling_epk.h
            include/blue_sapling_group_hash.h
            include/blue_zip32_master.h
            include/blue_zip32_fvk.h
            include/blue_zip32_child.h
            include/blue_zip32_seed_bridge.h
            device-blue-wallet/candidate/blue_sapling_entropy_device.h
            device-blue-wallet/candidate/blue_sapling_spend_device.h
            device-blue-wallet/candidate/blue_zip32_seed_device.h
            tests/blue_sapling_device_stub/os.h
            include/blue_sapling_generators.h)
        add_custom_command(OUTPUT "${BLUE_M3_IMAGE}"
            COMMAND ${BLUE_ARM_GCC} -std=c23 -mcpu=cortex-m3 -mthumb
                -O2 -ffunction-sections -fdata-sections
                -Wall -Wextra -Werror -pedantic
                -DZCL_FUZZ_QUIET_LOG_MACROS=1
                -DZCL_BLUE_SYNTHETIC_SEED_FIXTURE=1
                -I "${CMAKE_CURRENT_SOURCE_DIR}/include"
                -I "${CMAKE_CURRENT_SOURCE_DIR}/device-blue-wallet/candidate"
                -I "${CMAKE_CURRENT_SOURCE_DIR}/tests/blue_sapling_device_stub"
                -I "${CMAKE_CURRENT_SOURCE_DIR}/../../core/modules/sapling/include"
                -I "${CMAKE_CURRENT_SOURCE_DIR}/../../core/modules/crypto/include"
                -I "${CMAKE_CURRENT_SOURCE_DIR}/../../contexts/commons/packages/zsha256/include"
                -I "${CMAKE_CURRENT_SOURCE_DIR}/../../platform/modules/util/include"
                -I "${CMAKE_CURRENT_SOURCE_DIR}/../../platform/modules/base/include"
                -I "${CMAKE_CURRENT_SOURCE_DIR}/../../platform/modules/support/include"
                -nostartfiles -specs=rdimon.specs
                -Wl,-T,${CMAKE_CURRENT_SOURCE_DIR}/tests/blue_m3_qemu.ld
                -Wl,--gc-sections
                ${BLUE_SAPLING_ARM_SOURCES}
                -o "${BLUE_M3_IMAGE}"
            DEPENDS ${BLUE_SAPLING_ARM_DEPENDS}
            VERBATIM)
        add_custom_target(blue-m3-qemu-image ALL DEPENDS "${BLUE_M3_IMAGE}")
        add_test(NAME blue-m3-qemu COMMAND ${BLUE_QEMU}
            -M mps2-an385 -cpu cortex-m3 -nographic
            -semihosting-config enable=on,target=native
            -kernel "${BLUE_M3_IMAGE}")
        set_tests_properties(blue-m3-qemu PROPERTIES
            PASS_REGULAR_EXPRESSION "M3 PASS"
            FAIL_REGULAR_EXPRESSION "M3 FAIL|M3 STACK SETUP FAIL"
            TIMEOUT 15)

        set(BLUE_M0_SAPLING_IMAGE
            "${CMAKE_CURRENT_BINARY_DIR}/blue-m0-sapling-qemu.elf")
        set(BLUE_M0_SAPLING_BINARY
            "${CMAKE_CURRENT_BINARY_DIR}/blue-m0-sapling-qemu.bin")
        get_filename_component(BLUE_ARM_GCC_DIR "${BLUE_ARM_GCC}" DIRECTORY)
        set(BLUE_ARM_OBJCOPY "${BLUE_ARM_GCC_DIR}/arm-none-eabi-objcopy")
        add_custom_command(OUTPUT "${BLUE_M0_SAPLING_IMAGE}"
                "${BLUE_M0_SAPLING_BINARY}"
            COMMAND ${BLUE_ARM_GCC} -std=c23 -mcpu=cortex-m0 -mthumb
                -O2 -ffunction-sections -fdata-sections -fstack-usage
                -Wall -Wextra -Werror -pedantic
                -DBLUE_QEMU_M0 -DZCL_FUZZ_QUIET_LOG_MACROS=1
                -DZCL_BLUE_SYNTHETIC_SEED_FIXTURE=1
                -I "${CMAKE_CURRENT_SOURCE_DIR}/include"
                -I "${CMAKE_CURRENT_SOURCE_DIR}/device-blue-wallet/candidate"
                -I "${CMAKE_CURRENT_SOURCE_DIR}/tests/blue_sapling_device_stub"
                -I "${CMAKE_CURRENT_SOURCE_DIR}/../../core/modules/sapling/include"
                -I "${CMAKE_CURRENT_SOURCE_DIR}/../../core/modules/crypto/include"
                -I "${CMAKE_CURRENT_SOURCE_DIR}/../../contexts/commons/packages/zsha256/include"
                -I "${CMAKE_CURRENT_SOURCE_DIR}/../../platform/modules/util/include"
                -I "${CMAKE_CURRENT_SOURCE_DIR}/../../platform/modules/base/include"
                -I "${CMAKE_CURRENT_SOURCE_DIR}/../../platform/modules/support/include"
                -nostartfiles -specs=rdimon.specs
                -Wl,-T,${CMAKE_CURRENT_SOURCE_DIR}/tests/blue_m3_qemu.ld
                -Wl,--gc-sections
                ${BLUE_SAPLING_ARM_SOURCES}
                -o "${BLUE_M0_SAPLING_IMAGE}"
            COMMAND ${BLUE_ARM_OBJCOPY} -O binary
                "${BLUE_M0_SAPLING_IMAGE}" "${BLUE_M0_SAPLING_BINARY}"
            DEPENDS ${BLUE_SAPLING_ARM_DEPENDS}
            VERBATIM)
        add_custom_target(blue-m0-sapling-qemu-image ALL
            DEPENDS "${BLUE_M0_SAPLING_BINARY}")
        add_test(NAME blue-m0-sapling-qemu COMMAND ${BLUE_QEMU}
            -M microbit -cpu cortex-m0 -nographic
            -semihosting-config enable=on,target=native
            -kernel "${BLUE_M0_SAPLING_BINARY}")
        set_tests_properties(blue-m0-sapling-qemu PROPERTIES
            PASS_REGULAR_EXPRESSION "M0 PASS"
            FAIL_REGULAR_EXPRESSION "M0 FAIL|M0 STACK SETUP FAIL"
            TIMEOUT 30)

        set(BLUE_CM_ARM_SOURCES
            "${CMAKE_CURRENT_SOURCE_DIR}/tests/blue_cm_qemu.c"
            "${CMAKE_CURRENT_SOURCE_DIR}/src/blue_sapling_cm.c"
            "${CMAKE_CURRENT_SOURCE_DIR}/src/blue_sapling_group_hash.c"
            "${CMAKE_CURRENT_SOURCE_DIR}/src/blue_jubjub_arithmetic.c"
            "${CMAKE_CURRENT_SOURCE_DIR}/src/blue_jubjub_lowmem.c"
            "${CMAKE_CURRENT_SOURCE_DIR}/src/blue_jubjub_encode.c"
            "${CMAKE_CURRENT_SOURCE_DIR}/src/blue_jubjub_decode.c"
            "${CMAKE_CURRENT_SOURCE_DIR}/src/blue_fr_ct.c"
            "${CMAKE_CURRENT_SOURCE_DIR}/src/blue_fr_sqrt.c"
            "${CMAKE_CURRENT_SOURCE_DIR}/src/blue_fs_ct.c"
            "${CMAKE_CURRENT_SOURCE_DIR}/src/blue_mod256.c"
            "${CMAKE_CURRENT_SOURCE_DIR}/../../core/modules/crypto/src/blake2s.c")
        set(BLUE_CM_ARM_INCLUDES
            -I "${CMAKE_CURRENT_SOURCE_DIR}/include"
            -I "${CMAKE_CURRENT_SOURCE_DIR}/../../core/modules/sapling/include"
            -I "${CMAKE_CURRENT_SOURCE_DIR}/../../core/modules/crypto/include"
            -I "${CMAKE_CURRENT_SOURCE_DIR}/../../platform/modules/util/include"
            -I "${CMAKE_CURRENT_SOURCE_DIR}/../../platform/modules/base/include"
            -I "${CMAKE_CURRENT_SOURCE_DIR}/../../platform/modules/support/include")
        set(BLUE_CM_M3_IMAGE
            "${CMAKE_CURRENT_BINARY_DIR}/blue-cm-m3-qemu.elf")
        add_custom_command(OUTPUT "${BLUE_CM_M3_IMAGE}"
            COMMAND ${BLUE_ARM_GCC} -std=c23 -mcpu=cortex-m3 -mthumb
                -O2 -ffunction-sections -fdata-sections
                -Wall -Wextra -Werror -pedantic
                -DZCL_FUZZ_QUIET_LOG_MACROS=1
                ${BLUE_CM_ARM_INCLUDES}
                -nostartfiles -specs=rdimon.specs
                -Wl,-T,${CMAKE_CURRENT_SOURCE_DIR}/tests/blue_m3_qemu.ld
                -Wl,--gc-sections
                ${BLUE_CM_ARM_SOURCES} -o "${BLUE_CM_M3_IMAGE}"
            DEPENDS ${BLUE_CM_ARM_SOURCES}
                tests/blue_m3_qemu.ld include/blue_sapling_cm.h
                include/blue_sapling_group_hash.h
            VERBATIM)
        add_custom_target(blue-cm-m3-qemu-image ALL
            DEPENDS "${BLUE_CM_M3_IMAGE}")
        add_test(NAME blue-cm-m3-qemu COMMAND ${BLUE_QEMU}
            -M mps2-an385 -cpu cortex-m3 -nographic
            -semihosting-config enable=on,target=native
            -kernel "${BLUE_CM_M3_IMAGE}")
        set_tests_properties(blue-cm-m3-qemu PROPERTIES
            PASS_REGULAR_EXPRESSION "CM-M3 PASS"
            FAIL_REGULAR_EXPRESSION "CM-M3 FAIL" TIMEOUT 30)

        set(BLUE_CM_M0_IMAGE
            "${CMAKE_CURRENT_BINARY_DIR}/blue-cm-m0-qemu.elf")
        set(BLUE_CM_M0_BINARY
            "${CMAKE_CURRENT_BINARY_DIR}/blue-cm-m0-qemu.bin")
        add_custom_command(OUTPUT "${BLUE_CM_M0_IMAGE}"
                "${BLUE_CM_M0_BINARY}"
            COMMAND ${BLUE_ARM_GCC} -std=c23 -mcpu=cortex-m0 -mthumb
                -O2 -ffunction-sections -fdata-sections
                -Wall -Wextra -Werror -pedantic
                -DBLUE_QEMU_M0 -DZCL_FUZZ_QUIET_LOG_MACROS=1
                ${BLUE_CM_ARM_INCLUDES}
                -nostartfiles -specs=rdimon.specs
                -Wl,-T,${CMAKE_CURRENT_SOURCE_DIR}/tests/blue_m3_qemu.ld
                -Wl,--gc-sections
                ${BLUE_CM_ARM_SOURCES} -o "${BLUE_CM_M0_IMAGE}"
            COMMAND ${BLUE_ARM_OBJCOPY} -O binary
                "${BLUE_CM_M0_IMAGE}" "${BLUE_CM_M0_BINARY}"
            DEPENDS ${BLUE_CM_ARM_SOURCES}
                tests/blue_m3_qemu.ld include/blue_sapling_cm.h
                include/blue_sapling_group_hash.h
            VERBATIM)
        add_custom_target(blue-cm-m0-qemu-image ALL
            DEPENDS "${BLUE_CM_M0_BINARY}")
        add_test(NAME blue-cm-m0-qemu COMMAND ${BLUE_QEMU}
            -M microbit -cpu cortex-m0 -nographic
            -semihosting-config enable=on,target=native
            -kernel "${BLUE_CM_M0_BINARY}")
        set_tests_properties(blue-cm-m0-qemu PROPERTIES
            PASS_REGULAR_EXPRESSION "CM-M0 PASS"
            FAIL_REGULAR_EXPRESSION "CM-M0 FAIL" TIMEOUT 60)

        set(BLUE_M0_WALLET_IMAGE
            "${CMAKE_CURRENT_BINARY_DIR}/blue-wallet-m0-qemu.elf")
        add_custom_command(OUTPUT "${BLUE_M0_WALLET_IMAGE}"
            COMMAND ${BLUE_ARM_GCC} -std=c23 -mcpu=cortex-m0 -mthumb
                -O2 -ffunction-sections -fdata-sections
                -Wall -Wextra -Werror -pedantic
                -DHAVE_BOLOS_APP_STACK_CANARY
                -I "${CMAKE_CURRENT_SOURCE_DIR}/tests/blue_wallet_startup_stub"
                -I "${CMAKE_CURRENT_SOURCE_DIR}/include"
                -I "${CMAKE_CURRENT_SOURCE_DIR}/device-blue-wallet/src"
                -I "${CMAKE_CURRENT_SOURCE_DIR}/../../contexts/commons/packages/zsha256/include"
                -I "${CMAKE_CURRENT_SOURCE_DIR}/../../contexts/commons/packages/zripemd/include"
                -nostartfiles -specs=rdimon.specs
                -Wl,-T,${CMAKE_CURRENT_SOURCE_DIR}/tests/blue_wallet_m0_qemu.ld
                -Wl,--gc-sections
                "${CMAKE_CURRENT_SOURCE_DIR}/tests/blue_wallet_m0_qemu.c"
                "${CMAKE_CURRENT_SOURCE_DIR}/src/blue_wallet_protocol.c"
                "${CMAKE_CURRENT_SOURCE_DIR}/src/blue_wallet_receive.c"
                "${CMAKE_CURRENT_SOURCE_DIR}/src/zcl_base58.c"
                "${CMAKE_CURRENT_SOURCE_DIR}/../../contexts/commons/packages/zsha256/src/zsha256.c"
                "${CMAKE_CURRENT_SOURCE_DIR}/../../contexts/commons/packages/zripemd/src/zripemd.c"
                -o "${BLUE_M0_WALLET_IMAGE}"
            DEPENDS tests/blue_wallet_m0_qemu.c tests/blue_wallet_m0_qemu.ld
                device-blue-wallet/src/main.c
                tests/blue_wallet_startup_stub/os.h
                tests/blue_wallet_startup_stub/os_io_seproxyhal.h
                tests/blue_wallet_startup_stub/core_cmFunc.h
                src/blue_wallet_protocol.c src/blue_wallet_receive.c
                src/zcl_base58.c
                ../../contexts/commons/packages/zsha256/src/zsha256.c
                ../../contexts/commons/packages/zripemd/src/zripemd.c
            VERBATIM)
        add_custom_target(blue-wallet-m0-qemu-image ALL
            DEPENDS "${BLUE_M0_WALLET_IMAGE}")
        add_test(NAME blue-wallet-m0-qemu COMMAND ${BLUE_QEMU}
            -M microbit -cpu cortex-m0 -nographic
            -semihosting-config enable=on,target=native
            -kernel "${BLUE_M0_WALLET_IMAGE}")
        set_tests_properties(blue-wallet-m0-qemu PROPERTIES
            PASS_REGULAR_EXPRESSION "M0 WALLET PASS"
            FAIL_REGULAR_EXPRESSION "M0 WALLET FAIL|M0 WALLET STACK SETUP FAIL"
            TIMEOUT 15)
    endif()
endif()

add_executable(zcl-blue-wallet-fixture src/blue_wallet_fixture_cli.c)
target_link_libraries(zcl-blue-wallet-fixture PRIVATE
    blue_payment_fixture blue_payment_live blue_payment_host_sign
    blue_payment_host_assemble zcl_tx_prevout zcl_zip243_host_hash
    zcl_address ledger_hid zcl_host_crypto)
target_compile_options(zcl-blue-wallet-fixture PRIVATE
    -Wall -Wextra -Werror -pedantic)
if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    target_compile_options(zcl-blue-wallet-fixture PRIVATE
        -fsanitize=address,undefined -fno-omit-frame-pointer)
    target_link_options(zcl-blue-wallet-fixture PRIVATE
        -fsanitize=address,undefined)
endif()
add_test(NAME blue-wallet-fixture-cli COMMAND zcl-blue-wallet-fixture
    --prepare 0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798)
set_tests_properties(blue-wallet-fixture-cli PROPERTIES
    PASS_REGULAR_EXPRESSION "SYNTHETIC TEST ONLY")

add_executable(test-blue-wallet-fixture-cleanup
    tests/test_blue_wallet_fixture_cleanup.c)
target_link_libraries(test-blue-wallet-fixture-cleanup PRIVATE
    blue_payment_fixture blue_payment_live blue_payment_host_sign
    blue_payment_host_assemble zcl_tx_prevout zcl_zip243_host_hash
    zcl_address zcl_host_crypto)
target_compile_options(test-blue-wallet-fixture-cleanup PRIVATE
    -Wall -Wextra -Werror -pedantic)
if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    target_compile_options(test-blue-wallet-fixture-cleanup PRIVATE
        -fsanitize=address,undefined -fno-omit-frame-pointer)
    target_link_options(test-blue-wallet-fixture-cleanup PRIVATE
        -fsanitize=address,undefined)
endif()
add_test(NAME blue-wallet-fixture-cleanup
    COMMAND test-blue-wallet-fixture-cleanup)

add_executable(test-blue-ecdsa-der tests/test_blue_ecdsa_der.c)
target_link_libraries(test-blue-ecdsa-der PRIVATE
    blue_ecdsa_der OpenSSL::Crypto)
target_compile_options(test-blue-ecdsa-der PRIVATE
    -Wall -Wextra -Werror -pedantic)
if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    target_compile_options(test-blue-ecdsa-der PRIVATE
        -fsanitize=address,undefined -fno-omit-frame-pointer)
    target_link_options(test-blue-ecdsa-der PRIVATE
        -fsanitize=address,undefined)
endif()
add_test(NAME blue-ecdsa-der COMMAND test-blue-ecdsa-der)

add_executable(test-blue-payment-sign tests/test_blue_payment_sign.c)
target_link_libraries(test-blue-payment-sign PRIVATE
    blue_payment_sign blue_payment_host_assemble zcl_host_crypto
    OpenSSL::Crypto)
target_compile_options(test-blue-payment-sign PRIVATE
    -Wall -Wextra -Werror -pedantic)
if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    target_compile_options(test-blue-payment-sign PRIVATE
        -fsanitize=address,undefined -fno-omit-frame-pointer)
    target_link_options(test-blue-payment-sign PRIVATE
        -fsanitize=address,undefined)
endif()
add_test(NAME blue-payment-sign COMMAND test-blue-payment-sign)

add_executable(test-blue-wallet-signer-device
    tests/test_blue_wallet_signer_device.c)
target_include_directories(test-blue-wallet-signer-device PRIVATE
    tests/blue_wallet_signer_stub include device-blue-wallet/src)
target_compile_options(test-blue-wallet-signer-device PRIVATE
    -Wall -Wextra -Werror -pedantic)
if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    target_compile_options(test-blue-wallet-signer-device PRIVATE
        -fsanitize=address,undefined -fno-omit-frame-pointer)
    target_link_options(test-blue-wallet-signer-device PRIVATE
        -fsanitize=address,undefined)
endif()
add_test(NAME blue-wallet-signer-device COMMAND test-blue-wallet-signer-device)

add_executable(test-blue-wallet-device-ui tests/test_blue_wallet_device_ui.c)
target_include_directories(test-blue-wallet-device-ui PRIVATE
    tests/blue_wallet_sdk_stub include device-blue-wallet/src)
target_link_libraries(test-blue-wallet-device-ui PRIVATE
    blue_payment_sign blue_payment_apdu blue_payment_screen blue_payment_review zcl_zip243
    zcl_tx_prevout zcl_base58 blue_payment_render blue_bagl_canvas zcl_sha256)
target_compile_options(test-blue-wallet-device-ui PRIVATE
    -Wall -Wextra -Werror -pedantic)
if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    target_compile_options(test-blue-wallet-device-ui PRIVATE
        -fsanitize=address,undefined -fno-omit-frame-pointer)
    target_link_options(test-blue-wallet-device-ui PRIVATE
        -fsanitize=address,undefined)
endif()
add_test(NAME blue-wallet-device-ui COMMAND test-blue-wallet-device-ui)

add_executable(test-blue-wallet-startup tests/test_blue_wallet_startup.c)
target_include_directories(test-blue-wallet-startup PRIVATE
    tests/blue_wallet_startup_stub include device-blue-wallet/src
    ../../contexts/commons/packages/zripemd/include)
target_link_libraries(test-blue-wallet-startup PRIVATE
    blue_wallet_protocol blue_wallet_receive zcl_address zcl_sha256)
target_compile_options(test-blue-wallet-startup PRIVATE
    -Wall -Wextra -Werror -pedantic -DHAVE_BOLOS_APP_STACK_CANARY)
if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    target_compile_options(test-blue-wallet-startup PRIVATE
        -fsanitize=address,undefined -fno-omit-frame-pointer)
    target_link_options(test-blue-wallet-startup PRIVATE
        -fsanitize=address,undefined)
endif()
add_test(NAME blue-wallet-startup COMMAND test-blue-wallet-startup)

add_executable(test-blue-wallet-integrated-loop
    tests/test_blue_wallet_integrated_loop.c)
target_include_directories(test-blue-wallet-integrated-loop PRIVATE
    tests/blue_wallet_startup_stub include device-blue-wallet/src
    ../../contexts/commons/packages/zripemd/include)
target_link_libraries(test-blue-wallet-integrated-loop PRIVATE
    blue_wallet_protocol blue_wallet_receive blue_payment_sign
    blue_payment_apdu blue_payment_screen blue_payment_review zcl_zip243
    zcl_tx_prevout zcl_base58 zcl_address zcl_sha256
    blue_payment_fixture blue_payment_live zcl_zip243_host_hash
    blue_host_gui blue_install_params)
target_compile_options(test-blue-wallet-integrated-loop PRIVATE
    -Wall -Wextra -Werror -pedantic -DHAVE_BOLOS_APP_STACK_CANARY
    -DBLUE_WALLET_TEST_REAL_HASH)
if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    target_compile_options(test-blue-wallet-integrated-loop PRIVATE
        -fsanitize=address,undefined -fno-omit-frame-pointer)
    target_link_options(test-blue-wallet-integrated-loop PRIVATE
        -fsanitize=address,undefined)
endif()
add_test(NAME blue-wallet-integrated-loop COMMAND test-blue-wallet-integrated-loop)

add_executable(test-blue-wallet-review-cli tests/test_blue_wallet_review_cli.c)
target_link_libraries(test-blue-wallet-review-cli PRIVATE zcl_sha256 blue_utxo)
target_compile_options(test-blue-wallet-review-cli PRIVATE
    -Wall -Wextra -Werror -pedantic)
if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    target_compile_options(test-blue-wallet-review-cli PRIVATE
        -fsanitize=address,undefined -fno-omit-frame-pointer)
    target_link_options(test-blue-wallet-review-cli PRIVATE
        -fsanitize=address,undefined)
endif()
add_test(NAME blue-wallet-review-cli COMMAND test-blue-wallet-review-cli
    $<TARGET_FILE:test-blue-payment-review>
    $<TARGET_FILE:zcl-blue-wallet-review>
    $<TARGET_FILE:zcl-blue-wallet-sign>
    $<TARGET_FILE:test-blue-chain-tip>)

add_executable(test-blue-signed-output tests/test_blue_signed_output.c)
target_link_libraries(test-blue-signed-output PRIVATE blue_signed_output)
target_compile_options(test-blue-signed-output PRIVATE
    -Wall -Wextra -Werror -pedantic)
target_link_options(test-blue-signed-output PRIVATE
    -Wl,--wrap=fsync -Wl,--wrap=unlinkat)
if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    target_compile_options(test-blue-signed-output PRIVATE
        -fsanitize=address,undefined -fno-omit-frame-pointer)
    target_link_options(test-blue-signed-output PRIVATE
        -fsanitize=address,undefined)
endif()
add_test(NAME blue-signed-output COMMAND test-blue-signed-output)

add_executable(test-blue-mainnet-branch tests/test_blue_mainnet_branch.c
    src/blue_mainnet_branch.c)
target_include_directories(test-blue-mainnet-branch PRIVATE include)
target_compile_options(test-blue-mainnet-branch PRIVATE
    -Wall -Wextra -Werror -pedantic)
if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    target_compile_options(test-blue-mainnet-branch PRIVATE
        -fsanitize=address,undefined -fno-omit-frame-pointer)
    target_link_options(test-blue-mainnet-branch PRIVATE
        -fsanitize=address,undefined)
endif()
add_test(NAME blue-mainnet-branch COMMAND test-blue-mainnet-branch)

add_executable(test-blue-chain-tip tests/test_blue_chain_tip.c)
target_link_libraries(test-blue-chain-tip PRIVATE blue_utxo)
target_compile_options(test-blue-chain-tip PRIVATE
    -Wall -Wextra -Werror -pedantic)
if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    target_compile_options(test-blue-chain-tip PRIVATE
        -fsanitize=address,undefined -fno-omit-frame-pointer)
    target_link_options(test-blue-chain-tip PRIVATE
        -fsanitize=address,undefined)
endif()
add_test(NAME blue-chain-tip COMMAND test-blue-chain-tip)

add_executable(test-blue-payment-screen tests/test_blue_payment_screen.c)
target_link_libraries(test-blue-payment-screen PRIVATE blue_payment_render
    zcl_address OpenSSL::Crypto)
target_compile_options(test-blue-payment-screen PRIVATE -Wall -Wextra -Werror -pedantic)
if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    target_compile_options(test-blue-payment-screen PRIVATE -fsanitize=address,undefined -fno-omit-frame-pointer)
    target_link_options(test-blue-payment-screen PRIVATE -fsanitize=address,undefined)
endif()
add_test(NAME blue-payment-screen COMMAND test-blue-payment-screen)

option(ZCL_LEDGER_FUZZ "Build the local Clang parser fuzzers" OFF)
if(ZCL_LEDGER_FUZZ)
    if(NOT CMAKE_C_COMPILER_ID STREQUAL "Clang" OR
       NOT CMAKE_BUILD_TYPE STREQUAL "Debug")
        message(FATAL_ERROR "ZCL_LEDGER_FUZZ requires Clang Debug")
    endif()
    foreach(target blue_app_catalog blue_payment_apdu blue_payment_review
                   blue_payment_sign blue_ecdsa_der
                   blue_payment_screen zcl_tx_review zcl_tx_previous_stream zcl_tx_script_facts
                   zcl_zip243 zcl_tx_stream
                   zcl_tx_stream_zip243 zcl_tx_replay_zip243
                   zcl_zip243_host_hash)
        target_compile_options(${target} PRIVATE -fsanitize=fuzzer-no-link)
    endforeach()
    add_executable(fuzz-zcl-tx tests/fuzz_zcl_tx.c)
    add_executable(fuzz-blue-app-catalog tests/fuzz_blue_app_catalog.c)
    target_link_libraries(fuzz-blue-app-catalog PRIVATE blue_app_catalog)
    target_compile_options(fuzz-blue-app-catalog PRIVATE -Wall -Wextra
        -Werror -pedantic -fsanitize=fuzzer,address,undefined)
    target_link_options(fuzz-blue-app-catalog PRIVATE
        -fsanitize=fuzzer,address,undefined)
    add_executable(fuzz-blue-payment-apdu tests/fuzz_blue_payment_apdu.c)
    target_link_libraries(fuzz-blue-payment-apdu PRIVATE blue_payment_apdu
        zcl_zip243_host_hash zcl_sha256)
    target_compile_options(fuzz-blue-payment-apdu PRIVATE -Wall -Wextra
        -Werror -pedantic -fsanitize=fuzzer,address,undefined)
    target_link_options(fuzz-blue-payment-apdu PRIVATE
        -fsanitize=fuzzer,address,undefined)
    add_executable(fuzz-blue-payment-sign tests/fuzz_blue_payment_sign.c)
    target_link_libraries(fuzz-blue-payment-sign PRIVATE blue_payment_sign)
    target_compile_options(fuzz-blue-payment-sign PRIVATE -Wall -Wextra
        -Werror -pedantic -fsanitize=fuzzer,address,undefined)
    target_link_options(fuzz-blue-payment-sign PRIVATE
        -fsanitize=fuzzer,address,undefined)
    target_link_libraries(fuzz-zcl-tx PRIVATE zcl_tx_script_facts
        zcl_zip243 zcl_zip243_host_hash)
    target_compile_options(fuzz-zcl-tx PRIVATE -Wall -Wextra -Werror -pedantic
        -fsanitize=fuzzer,address,undefined)
    target_link_options(fuzz-zcl-tx PRIVATE -fsanitize=fuzzer,address,undefined)
    add_executable(fuzz-zcl-previous-output tests/fuzz_zcl_previous_output.c)
    target_link_libraries(fuzz-zcl-previous-output PRIVATE zcl_tx_review)
    target_compile_options(fuzz-zcl-previous-output PRIVATE -Wall -Wextra
        -Werror -pedantic -fsanitize=fuzzer,address,undefined)
    target_link_options(fuzz-zcl-previous-output PRIVATE
        -fsanitize=fuzzer,address,undefined)
    add_executable(fuzz-zcl-previous-stream
        tests/fuzz_zcl_previous_stream.c)
    target_link_libraries(fuzz-zcl-previous-stream PRIVATE
        zcl_tx_previous_stream zcl_tx_review OpenSSL::Crypto)
    target_compile_options(fuzz-zcl-previous-stream PRIVATE -Wall -Wextra
        -Werror -pedantic -fsanitize=fuzzer,address,undefined)
    target_link_options(fuzz-zcl-previous-stream PRIVATE
        -fsanitize=fuzzer,address,undefined)
    add_executable(fuzz-zcl-tx-stream tests/fuzz_zcl_tx_stream.c)
    target_link_libraries(fuzz-zcl-tx-stream PRIVATE zcl_tx_stream
        zcl_tx_stream_zip243 zcl_tx_replay_zip243 zcl_tx_script_facts
        zcl_tx_review zcl_zip243 zcl_zip243_host_hash OpenSSL::Crypto)
    target_compile_options(fuzz-zcl-tx-stream PRIVATE -Wall -Wextra -Werror
        -pedantic -fsanitize=fuzzer,address,undefined)
    target_link_options(fuzz-zcl-tx-stream PRIVATE -fsanitize=fuzzer,address,undefined)
endif()

add_executable(test-zcl-zip243 tests/test_zcl_zip243.c)
target_link_libraries(test-zcl-zip243 PRIVATE zcl_zip243 zcl_tx_stream_zip243 zcl_tx_replay_zip243 zcl_zip243_host_hash OpenSSL::Crypto)
target_compile_options(test-zcl-zip243 PRIVATE -Wall -Wextra -Werror -pedantic)
if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    target_compile_options(test-zcl-zip243 PRIVATE -fsanitize=address,undefined -fno-omit-frame-pointer)
    target_link_options(test-zcl-zip243 PRIVATE -fsanitize=address,undefined)
endif()
add_test(NAME zcl-zip243 COMMAND test-zcl-zip243
    ${CMAKE_CURRENT_SOURCE_DIR}/tests/fixtures/zip243-vector1.hex
    ${CMAKE_CURRENT_SOURCE_DIR}/tests/fixtures/zip243-transparent-vector3.hex)

add_library(zcl_tx_shielded_stream STATIC src/zcl_tx_shielded_stream.c)
target_include_directories(zcl_tx_shielded_stream PUBLIC include)
target_compile_options(zcl_tx_shielded_stream PRIVATE
    -Wall -Wextra -Werror -pedantic)
if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    target_compile_options(zcl_tx_shielded_stream PRIVATE
        -fsanitize=address,undefined -fno-omit-frame-pointer)
endif()

add_library(zcl_tx_shielded_replay STATIC src/zcl_tx_shielded_replay.c)
target_include_directories(zcl_tx_shielded_replay PUBLIC include)
target_link_libraries(zcl_tx_shielded_replay PUBLIC
    zcl_tx_shielded_stream zcl_sha256)
target_link_libraries(test-blue-sapling-ock PRIVATE zcl_tx_shielded_replay)
target_compile_options(zcl_tx_shielded_replay PRIVATE
    -Wall -Wextra -Werror -pedantic)
if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    target_compile_options(zcl_tx_shielded_replay PRIVATE
        -fsanitize=address,undefined -fno-omit-frame-pointer)
endif()

add_library(blue_shielded_review_apdu STATIC
    src/blue_shielded_review_apdu.c)
target_include_directories(blue_shielded_review_apdu PUBLIC include)
target_link_libraries(blue_shielded_review_apdu PUBLIC
    zcl_tx_shielded_replay blue_mainnet_branch)
target_compile_options(blue_shielded_review_apdu PRIVATE
    -Wall -Wextra -Werror -pedantic)
if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    target_compile_options(blue_shielded_review_apdu PRIVATE
        -fsanitize=address,undefined -fno-omit-frame-pointer)
endif()

add_library(blue_shielded_review_app STATIC
    src/blue_shielded_review_app.c)
target_include_directories(blue_shielded_review_app PUBLIC include)
target_link_libraries(blue_shielded_review_app PUBLIC
    blue_shielded_review_apdu blue_review_screen)
target_compile_options(blue_shielded_review_app PRIVATE
    -Wall -Wextra -Werror -pedantic)
if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    target_compile_options(blue_shielded_review_app PRIVATE
        -fsanitize=address,undefined -fno-omit-frame-pointer)
endif()

if(ZCL_LEDGER_FUZZ)
    foreach(target blue_shielded_review_app blue_shielded_review_apdu
                   zcl_tx_shielded_replay zcl_tx_shielded_stream
                   blue_review_screen blue_mainnet_branch zcl_sha256)
        target_compile_options(${target} PRIVATE -fsanitize=fuzzer-no-link)
    endforeach()
    add_executable(fuzz-blue-shielded-review-apdu
        tests/fuzz_blue_shielded_review_apdu.c)
    target_link_libraries(fuzz-blue-shielded-review-apdu PRIVATE
        blue_shielded_review_app zcl_zip243_host_hash)
    target_compile_options(fuzz-blue-shielded-review-apdu PRIVATE
        -Wall -Wextra -Werror -pedantic -fsanitize=fuzzer,address,undefined)
    target_link_options(fuzz-blue-shielded-review-apdu PRIVATE
        -fsanitize=fuzzer,address,undefined)
endif()

add_executable(test-blue-shielded-review-app
    tests/test_blue_shielded_review_app.c)
target_link_libraries(test-blue-shielded-review-app PRIVATE
    blue_shielded_review_app zcl_zip243_host_hash)
target_compile_options(test-blue-shielded-review-app PRIVATE
    -Wall -Wextra -Werror -pedantic)
if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    target_compile_options(test-blue-shielded-review-app PRIVATE
        -fsanitize=address,undefined -fno-omit-frame-pointer)
    target_link_options(test-blue-shielded-review-app PRIVATE
        -fsanitize=address,undefined)
endif()
add_test(NAME blue-shielded-review-app COMMAND
    test-blue-shielded-review-app)

add_executable(test-blue-shielded-review-device
    tests/test_blue_review_device.c
    src/blue_review_accessible.c)
target_include_directories(test-blue-shielded-review-device PRIVATE
    tests/blue_wallet_startup_stub include)
target_compile_definitions(test-blue-shielded-review-device PRIVATE
    ZCL_BLUE_SHIELDED_REVIEW BLUE_WALLET_TEST_REAL_HASH
    ZCL_BLUE_REVIEW_HOST_TEST)
target_link_libraries(test-blue-shielded-review-device PRIVATE
    blue_shielded_review_app zcl_zip243 zcl_zip243_host_hash)
target_compile_options(test-blue-shielded-review-device PRIVATE
    -Wall -Wextra -Werror -pedantic)
if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    target_compile_options(test-blue-shielded-review-device PRIVATE
        -fsanitize=address,undefined -fno-omit-frame-pointer)
    target_link_options(test-blue-shielded-review-device PRIVATE
        -fsanitize=address,undefined)
endif()
add_test(NAME blue-shielded-review-device
    COMMAND test-blue-shielded-review-device)

add_executable(test-blue-review-device
    tests/test_blue_review_device.c)
target_include_directories(test-blue-review-device PRIVATE
    tests/blue_wallet_startup_stub include)
target_compile_definitions(test-blue-review-device PRIVATE
    BLUE_REVIEW_TEST_CONTEXT ZCL_BLUE_REVIEW_HOST_TEST)
target_link_libraries(test-blue-review-device PRIVATE blue_review_app)
target_compile_options(test-blue-review-device PRIVATE
    -Wall -Wextra -Werror -pedantic)
if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    target_compile_options(test-blue-review-device PRIVATE
        -fsanitize=address,undefined -fno-omit-frame-pointer)
    target_link_options(test-blue-review-device PRIVATE
        -fsanitize=address,undefined)
endif()
add_test(NAME blue-review-device COMMAND test-blue-review-device)

add_library(blue_shielded_review_client STATIC
    src/blue_shielded_review_client.c)
target_include_directories(blue_shielded_review_client PUBLIC include)
target_link_libraries(blue_shielded_review_client PUBLIC
    blue_mainnet_branch zcl_tx_review zcl_zip243 zcl_zip243_host_hash
    zcl_sha256)
target_compile_options(blue_shielded_review_client PRIVATE
    -Wall -Wextra -Werror -pedantic)
if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    target_compile_options(blue_shielded_review_client PRIVATE
        -fsanitize=address,undefined -fno-omit-frame-pointer)
endif()

add_executable(test-blue-shielded-review-client
    tests/test_blue_shielded_review_client.c)
target_link_libraries(test-blue-shielded-review-client PRIVATE
    blue_shielded_review_client blue_shielded_review_app)
target_compile_options(test-blue-shielded-review-client PRIVATE
    -Wall -Wextra -Werror -pedantic)
if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    target_compile_options(test-blue-shielded-review-client PRIVATE
        -fsanitize=address,undefined -fno-omit-frame-pointer)
    target_link_options(test-blue-shielded-review-client PRIVATE
        -fsanitize=address,undefined)
endif()
add_test(NAME blue-shielded-review-client COMMAND
    test-blue-shielded-review-client
    ${CMAKE_CURRENT_SOURCE_DIR}/tests/fixtures/zip243-vector1.hex
    ${CMAKE_CURRENT_SOURCE_DIR}/tests/fixtures/simnet-sapling-spend.hex)

add_executable(zcl-blue-shielded-review
    src/blue_shielded_review_cli.c)
target_link_libraries(zcl-blue-shielded-review PRIVATE
    blue_shielded_review_client blue_shielded_review_app ledger_hid)
target_compile_options(zcl-blue-shielded-review PRIVATE
    -Wall -Wextra -Werror -pedantic)
if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    target_compile_options(zcl-blue-shielded-review PRIVATE
        -fsanitize=address,undefined -fno-omit-frame-pointer)
    target_link_options(zcl-blue-shielded-review PRIVATE
        -fsanitize=address,undefined)
endif()

add_executable(zcl-blue-shielded-screen-sim
    src/blue_shielded_screen_sim_cli.c)
target_link_libraries(zcl-blue-shielded-screen-sim PRIVATE
    blue_shielded_review_client blue_shielded_review_app
    blue_review_render)
target_compile_options(zcl-blue-shielded-screen-sim PRIVATE
    -Wall -Wextra -Werror -pedantic)
if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    target_compile_options(zcl-blue-shielded-screen-sim PRIVATE
        -fsanitize=address,undefined -fno-omit-frame-pointer)
    target_link_options(zcl-blue-shielded-screen-sim PRIVATE
        -fsanitize=address,undefined)
endif()

add_executable(test-blue-shielded-screen-cli
    tests/test_blue_shielded_screen_cli.c)
target_link_libraries(test-blue-shielded-screen-cli PRIVATE
    zcl_sha256 PNG::PNG)
target_compile_options(test-blue-shielded-screen-cli PRIVATE
    -Wall -Wextra -Werror -pedantic)
if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    target_compile_options(test-blue-shielded-screen-cli PRIVATE
        -fsanitize=address,undefined -fno-omit-frame-pointer)
    target_link_options(test-blue-shielded-screen-cli PRIVATE
        -fsanitize=address,undefined)
endif()
add_test(NAME blue-shielded-screen-cli COMMAND
    test-blue-shielded-screen-cli
    ${CMAKE_CURRENT_SOURCE_DIR}/tests/fixtures/zip243-vector1.hex
    $<TARGET_FILE:zcl-blue-shielded-screen-sim>
    ${CMAKE_CURRENT_SOURCE_DIR}/tests/fixtures/simnet-sapling-spend.hex)

add_executable(test-blue-shielded-review-apdu
    tests/test_blue_shielded_review_apdu.c)
target_link_libraries(test-blue-shielded-review-apdu PRIVATE
    blue_shielded_review_apdu blue_review_screen zcl_zip243
    zcl_zip243_host_hash)
target_compile_options(test-blue-shielded-review-apdu PRIVATE
    -Wall -Wextra -Werror -pedantic)
if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    target_compile_options(test-blue-shielded-review-apdu PRIVATE
        -fsanitize=address,undefined -fno-omit-frame-pointer)
    target_link_options(test-blue-shielded-review-apdu PRIVATE
        -fsanitize=address,undefined)
endif()
add_test(NAME blue-shielded-review-apdu COMMAND
    test-blue-shielded-review-apdu
    ${CMAKE_CURRENT_SOURCE_DIR}/tests/fixtures/zip243-vector1.hex)

add_executable(test-zcl-tx-shielded-stream
    tests/test_zcl_tx_shielded_stream.c)
target_link_libraries(test-zcl-tx-shielded-stream PRIVATE
    zcl_tx_shielded_replay zcl_tx_review zcl_zip243
    zcl_zip243_host_hash)
target_compile_options(test-zcl-tx-shielded-stream PRIVATE
    -Wall -Wextra -Werror -pedantic)
if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    target_compile_options(test-zcl-tx-shielded-stream PRIVATE
        -fsanitize=address,undefined -fno-omit-frame-pointer)
    target_link_options(test-zcl-tx-shielded-stream PRIVATE
        -fsanitize=address,undefined)
endif()
add_test(NAME zcl-tx-shielded-stream COMMAND test-zcl-tx-shielded-stream
    ${CMAKE_CURRENT_SOURCE_DIR}/tests/fixtures/zip243-vector1.hex
    ${CMAKE_CURRENT_SOURCE_DIR}/tests/fixtures/zip243-transparent-vector3.hex
    ${CMAKE_CURRENT_SOURCE_DIR}/tests/fixtures/simnet-sapling-spend.hex)

add_executable(test-blue-review-protocol tests/test_blue_review_protocol.c)
target_link_libraries(test-blue-review-protocol PRIVATE blue_review_protocol blue_review_screen zcl_zip243_host_hash OpenSSL::Crypto)
target_compile_options(test-blue-review-protocol PRIVATE -Wall -Wextra -Werror -pedantic)
if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    target_compile_options(test-blue-review-protocol PRIVATE -fsanitize=address,undefined -fno-omit-frame-pointer)
    target_link_options(test-blue-review-protocol PRIVATE -fsanitize=address,undefined)
endif()
add_test(NAME blue-review-protocol COMMAND test-blue-review-protocol
    ${CMAKE_CURRENT_SOURCE_DIR}/tests/fixtures/zip243-transparent-vector3.hex)

add_executable(test-blue-review-screen tests/test_blue_review_screen.c)
target_link_libraries(test-blue-review-screen PRIVATE blue_review_screen blue_review_protocol zcl_zip243_host_hash zcl_address OpenSSL::Crypto)
target_compile_options(test-blue-review-screen PRIVATE -Wall -Wextra -Werror -pedantic)
if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    target_compile_options(test-blue-review-screen PRIVATE -fsanitize=address,undefined -fno-omit-frame-pointer)
    target_link_options(test-blue-review-screen PRIVATE -fsanitize=address,undefined)
endif()
add_test(NAME blue-review-screen COMMAND test-blue-review-screen)

add_executable(test-blue-review-simulator tests/test_blue_review_simulator.c)
target_link_libraries(test-blue-review-simulator PRIVATE blue_review_simulate blue_review_render OpenSSL::Crypto)
target_compile_options(test-blue-review-simulator PRIVATE -Wall -Wextra -Werror -pedantic)
if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    target_compile_options(test-blue-review-simulator PRIVATE -fsanitize=address,undefined -fno-omit-frame-pointer)
    target_link_options(test-blue-review-simulator PRIVATE -fsanitize=address,undefined)
endif()
add_test(NAME blue-review-simulator COMMAND test-blue-review-simulator
    ${CMAKE_CURRENT_SOURCE_DIR}/tests/fixtures/zip243-transparent-vector3.hex)

add_executable(test-zcl-tx-review-cli tests/test_zcl_tx_review_cli.c)
target_compile_options(test-zcl-tx-review-cli PRIVATE -Wall -Wextra -Werror -pedantic)
if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    target_compile_options(test-zcl-tx-review-cli PRIVATE -fsanitize=address,undefined -fno-omit-frame-pointer)
    target_link_options(test-zcl-tx-review-cli PRIVATE -fsanitize=address,undefined)
endif()
add_test(NAME zcl-tx-review-cli COMMAND test-zcl-tx-review-cli
    $<TARGET_FILE:zcl-tx-review>
    ${CMAKE_CURRENT_SOURCE_DIR}/tests/fixtures/zip243-transparent-vector3.hex
    $<TARGET_FILE:zcl-blue-screen-sim>)
