/* Copyright 2026 Rhett Creighton - Apache License 2.0 */

#include "encoding/qr.h"
#include "base/safe_alloc.h"
#include "command/native_command.h"
#include "json/json.h"
#include "presentation/canvas.h"
#include "presentation/model.h"
#include "presentation/model_render.h"
#include "presentation/model_text.h"
#include "presentation/presentation.h"
#include "presentation/zclassic_brand.h"
#include "views/qr_popup.h"
#include "views/ui_present.h"
#include "views/ui_present_document.h"
#include "views/ui_present_host_transport.h"
#include "vcs/zcode_work_node.h"

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "test/test_qr_priv.h"

/* The shared failure counter, handed out only through a pointer. */
int *qr_failures_ptr(void)
{
    static int failures;
    return &failures;
}
/* Allocation failure used to crash both QR paths: zcl_malloc's NULL went
 * straight into the module-copy loop / the render memset. Both must refuse
 * with the function's false-and-error contract instead. */
static void qr_case_alloc_failure_refuses(void)
{
    char err[128] = "stale error";
    uint8_t sentinel = 0;
    struct qr_matrix m = { .modules = &sentinel, .width = 1 };

    zcl_alloc_fault_fail_next("qr.matrix.modules");
    bool refused = !qr_matrix_encode("hello", &m, err, sizeof err);
    zcl_alloc_fault_clear();
    QR_CHECK("QR encode refuses allocation failure",
             refused && m.modules == NULL && m.width == 0);
    QR_CHECK("QR encode allocation diagnostic gives stage, bytes and recovery",
             strcmp(err, "QR matrix allocation failed during encode (441 bytes); "
                         "retry after freeing memory") == 0);
    qr_matrix_free(&m);

    if (!qr_matrix_encode("hello", &m, err, sizeof err)) {
        QR_CHECK("QR render refuses allocation failure (matrix setup)", false);
        return;
    }
    uint8_t *pixels = &sentinel;
    uint32_t side = 99;
    zcl_alloc_fault_fail_next("qr.render.rgb");
    refused = !qr_matrix_render_rgb(&m, 2, 2, &pixels, &side, err,
                                    sizeof err);
    zcl_alloc_fault_clear();
    QR_CHECK("QR render refuses allocation failure",
             refused && pixels == NULL && side == 0 &&
             strcmp(err, "QR render allocation failed: 7500 bytes, side=50; "
                         "retry after freeing memory") == 0);
    qr_matrix_free(&m);
}

static void qr_case_render_alloc_optional_error(void)
{
    uint8_t sentinel = 0;
    struct qr_matrix m;
    char err[2] = { 'x', 'y' };
    char full[128] = "stale error";
    if (!qr_matrix_encode("hello", &m, NULL, 0)) {
        QR_CHECK("QR optional allocation diagnostic (matrix setup)", false);
        return;
    }
    char *errors[] = { err, NULL, full };
    const size_t capacities[] = { 1, 1, sizeof full };
    bool cleared = true;
    for (size_t i = 0; i < 3; i++) {
        uint8_t *pixels = &sentinel;
        uint32_t side = 99;
        zcl_alloc_fault_fail_next("qr.render.rgb");
        bool refused = !qr_matrix_render_rgb(&m, 2, 2, &pixels, &side,
                                             errors[i], capacities[i]);
        zcl_alloc_fault_clear();
        cleared = cleared && refused && pixels == NULL && side == 0;
    }
    QR_CHECK("QR allocation diagnostic supports full, tiny and omitted buffers",
             cleared && err[0] == '\0' && err[1] == 'y' &&
             strcmp(full, "QR render allocation failed: 7500 bytes, side=50; "
                          "retry after freeing memory") == 0);
    qr_matrix_free(&m);
}

static void qr_case_popup_alloc_failure_refuses(void)
{
    char err[128];
    struct zcl_present_model_v1 model;
    if (!zcl_present_model_qr_from_payload_v1(
            "hello", "QR", &model, err, sizeof err)) {
        QR_CHECK("QR popup allocation failure (model setup)", false);
        return;
    }
    const char *labels[] = { "qr.matrix.modules", "qr.render.rgb" };
    const char *errors[] = { "QR matrix allocation failed during encode (441 bytes); "
                             "retry after freeing memory",
        "QR render allocation failed: 252300 bytes, side=290; "
        "retry after freeing memory" };
    for (size_t i = 0; i < 2; i++) {
        struct qr_popup_card card = { .width = 99, .height = 99 };
        zcl_alloc_fault_fail_next(labels[i]);
        bool refused = !qr_popup_card_render(&model, &card, err, sizeof err);
        zcl_alloc_fault_clear();
        QR_CHECK(labels[i], refused && card.pixels == NULL &&
                 card.width == 0 && card.height == 0 &&
                 strcmp(err, errors[i]) == 0);
        qr_popup_card_free(&card);
    }
}

static void qr_case_encode_alloc_optional_diagnostic(void)
{
    uint8_t sentinel = 0;
    char tiny[2] = { 'x', 'y' };
    char *errors[] = { tiny, NULL };
    for (size_t i = 0; i < 2; i++) {
        struct qr_matrix m = { .modules = &sentinel, .width = 1 };
        zcl_alloc_fault_fail_next("qr.matrix.modules");
        bool refused = !qr_matrix_encode("hello", &m, errors[i], 1);
        zcl_alloc_fault_clear();
        QR_CHECK("QR encode allocation refusal with optional diagnostic",
                 refused && m.modules == NULL && m.width == 0);
        qr_matrix_free(&m);
    }
    QR_CHECK("QR encode allocation diagnostic respects one-byte capacity",
             tiny[0] == '\0' && tiny[1] == 'y');
}

static void qr_case_render_refusal_outputs(void)
{
    uint8_t sentinel = 0;
    struct qr_matrix matrix = { .modules = &sentinel, .width = 1 };
    struct qr_matrix no_modules = { .width = 1 };
    struct qr_matrix no_width = { .modules = &sentinel };
    const struct {
        const struct qr_matrix *matrix;
        uint32_t scale, quiet;
        bool missing_pixels, missing_side;
        const char *error;
    } cases[] = {
        { &matrix, 0, 4, false, false, "QR scale: use 1..64" },
        { &matrix, 65, 4, false, false, "QR scale: use 1..64" },
        { &matrix, 1, 33, false, false, "QR quiet_modules: use 0..32" },
        { NULL, 2, 2, false, false, "QR matrix: supply a matrix" },
        { &no_modules, 2, 2, false, false,
          "QR matrix.modules: supply module data" },
        { &no_width, 2, 2, false, false,
          "QR matrix.width: use a nonzero width" },
        { &matrix, 2, 2, true, false, "QR pixels: supply an output pointer" },
        { &matrix, 2, 2, false, true, "QR side: supply an output pointer" },
    };
    for (size_t i = 0; i < sizeof cases / sizeof cases[0]; i++) {
        for (size_t mode = 0; mode < 4; mode++) {
            uint8_t *pixels = &sentinel;
            uint32_t side = 99;
            char err[128] = "stale error";
            char *error = mode == 2 ? NULL : err;
            size_t cap = mode == 1 ? 1u : mode == 3 ? 0u : sizeof err;
            bool refused = !qr_matrix_render_rgb(cases[i].matrix,
                cases[i].scale, cases[i].quiet,
                cases[i].missing_pixels ? NULL : &pixels,
                cases[i].missing_side ? NULL : &side, error, cap);
            QR_CHECK(cases[i].error, refused &&
                (cases[i].missing_pixels || pixels == NULL) &&
                (cases[i].missing_side || side == 0));
            QR_CHECK("QR argument diagnostic respects optional buffer",
                mode == 0 ? strcmp(err, cases[i].error) == 0 :
                mode == 1 ? err[0] == '\0' : strcmp(err, "stale error") == 0);
        }
    }
}

static void qr_case_render_argument_boundaries(void)
{
    uint8_t module = 0;
    struct qr_matrix matrix = { .modules = &module, .width = 1 };
    const uint32_t scales[] = { 1, 64 }, quiets[] = { 0, 32 };
    for (size_t i = 0; i < 2; i++) {
        uint8_t *pixels = NULL;
        uint32_t side = 0;
        char err[128] = "stale error";
        bool rendered = qr_matrix_render_rgb(&matrix, scales[i], quiets[i],
                                             &pixels, &side, err, sizeof err);
        QR_CHECK("QR render accepts argument boundaries", rendered && pixels &&
            side == (1u + 2u * quiets[i]) * scales[i] && err[0] == '\0');
        struct qr_popup_card card = { .pixels = pixels };
        qr_popup_card_free(&card);
    }
}

static void qr_case_overflow_optional_diagnostic(const struct qr_matrix *matrix)
{
    uint8_t sentinel = 0;
    uint8_t *pixels = &sentinel;
    uint32_t side = 99;
    char bounded[] = { 'x', 'y', 'z', '!' };
    bool refused = !qr_matrix_render_rgb(matrix, 2, 2, &pixels, &side,
                                         bounded, 3);
    QR_CHECK("QR overflow diagnostic respects short capacity",
             refused && pixels == NULL && side == 0 &&
             memcmp(bounded, "QR\0!", sizeof bounded) == 0);
    bounded[0] = 'x';
    pixels = &sentinel;
    side = 99;
    refused = !qr_matrix_render_rgb(matrix, 2, 2, &pixels, &side,
                                    bounded, 1);
    QR_CHECK("QR overflow diagnostic respects one-byte capacity",
             refused && pixels == NULL && side == 0 &&
             memcmp(bounded, "\0R\0!", sizeof bounded) == 0);
    pixels = &sentinel;
    side = 99;
    refused = !qr_matrix_render_rgb(matrix, 2, 2, &pixels, &side, NULL, 128);
    QR_CHECK("QR overflow refuses without diagnostic buffer",
             refused && pixels == NULL && side == 0);
}

static void qr_case_render_size_refuses(void)
{
    uint8_t sentinel = 0;
    const uint32_t widths[] = { UINT32_MAX, UINT32_MAX / 2u - 4u };
    for (size_t i = 0; i < 2; i++) {
        struct qr_matrix matrix = { .modules = &sentinel,
                                     .width = widths[i] };
        uint8_t *pixels = &sentinel;
        uint32_t side = 99;
        char err[128];
        bool refused = !qr_matrix_render_rgb(&matrix, 2, 2, &pixels, &side,
                                             err, sizeof err);
        QR_CHECK("overflowing QR dimensions clear outputs",
                 refused && pixels == NULL && side == 0);
        char expected[128];
        snprintf(expected, sizeof expected,
                 "QR render dimensions overflow: width=%" PRIu32
                 " scale=2 quiet=2; reduce width or scale", widths[i]);
        QR_CHECK("QR overflow reports dimensions and correction",
                 strcmp(err, expected) == 0);

        qr_case_overflow_optional_diagnostic(&matrix);
    }
}

int test_qr(void)
{
    printf("\n=== qr ===\n");
    (*qr_failures_ptr()) = 0;
    QR_CHECK("native QR backend is compiled", qr_matrix_backend_available());
    if (!qr_matrix_backend_available()) return (*qr_failures_ptr());

    if (!qr_case_payment_uri_encode_and_finders()) return (*qr_failures_ptr());
    qr_case_alloc_failure_refuses();
    qr_case_render_alloc_optional_error();
    qr_case_encode_alloc_optional_diagnostic();
    qr_case_popup_alloc_failure_refuses();
    qr_case_render_refusal_outputs();
    qr_case_render_argument_boundaries();
    qr_case_render_size_refuses();
    qr_case_zclassic_window_icon();
    qr_case_canvas_primitives();
    qr_case_chart_scale_maximum();
    qr_case_canvas_text_metrics();
    qr_case_deposit_card();
    qr_case_generic_qr_compositor();
    qr_case_presentation_clipboard_bmp();
    qr_case_confirmation_action_clicks();
    qr_case_chart_hover();
    qr_case_image_copy_control();
    qr_case_chart_keys();
    qr_case_chart_axis_cadence();
    qr_case_chart_rendering_page_bound();
    qr_case_shared_qr_model_rejects();
    qr_case_maximum_qr_chunks();
    qr_case_qr_text_companion_pages();
    qr_case_qr_text_export_and_backend();
    qr_case_progress_model();
    qr_case_chart_model();
    qr_case_timeline_model();
    qr_case_evidence_graph();
    qr_case_choice_model();
    qr_case_form_model_render();
    qr_case_form_bridge_and_typing();
    qr_case_form_focus();
    qr_case_form_submission_mutants();
    qr_case_canvas_model_render();
    qr_case_canvas_reducer_and_submit();
    qr_case_host_reply();
    qr_case_visual_model_wire();
    qr_case_confirmation_model();
    qr_case_status_facts();
    qr_case_corpus_instrument();
    qr_case_corpus_text_export();
    qr_case_corpus_command();
    qr_case_code_change_model();
    qr_case_development_reflex_red();
    qr_case_development_pending_and_compile();
    qr_case_unchanged_candidate_bytes();
    qr_case_publication_confirm();
    qr_case_publication_confirm_chrome();
    qr_case_publication_evidence_boundaries();
    qr_case_release_confirm();
    qr_case_publication_local_commit();
    qr_case_publication_pointer_and_self();
    qr_case_publication_peer_fetch();
    qr_case_reproduction_progress();
    qr_case_package_worker_diagnostic();
    qr_case_progress_native_pixels();
    qr_case_bounded_table_pages();
    qr_case_bounded_table_text();
    qr_case_bounded_table_pixels();
    qr_case_bounded_table_keys();
    qr_case_typed_visual_json();
    qr_case_typed_chart_command();
    qr_case_typed_timeline_command();
    qr_case_typed_evidence_graph_command();
    qr_case_typed_choice_command();
    qr_case_typed_form_command();
    qr_case_typed_canvas_command();
    qr_case_shared_presentation_response();
    qr_case_shared_text_paging_fallback();
    qr_case_visual_command_smuggling();
    printf("=== qr: %d failure(s) ===\n", (*qr_failures_ptr()));
    return (*qr_failures_ptr());
}
