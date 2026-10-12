/* ztemplate — minimal {{variable}} template engine (C23).
 *
 * Templates are parsed once into a segment list (literals and
 * variables), then rendered any number of times against a caller
 * lookup callback. Syntax is deliberately tiny:
 *
 *   Hello {{name}}, you have {{count}} messages.
 *
 * - `{{ name }}` — variable; inner whitespace is trimmed
 * - `{{! ... }}` — comment, dropped at parse time
 * - `{{` in literal text is an error; there is no escaping by design
 *   (write the braces as a variable value if you need them)
 *
 * Rendering is allocation-free into a caller buffer; the exact
 * required length is reported when representable so a two-pass size-then-fill
 * pattern works. Unknown variables are a render error (fail-closed),
 * never silently empty.
 *
 * Apache-2.0 licensed. No dependencies beyond libc.
 */
#ifndef ZTEMPLATE_H
#define ZTEMPLATE_H

#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct ztemplate ztemplate;

typedef enum {
    ZTEMPLATE_OK = 0,
    ZTEMPLATE_PARSE_ERROR,   /* malformed template syntax */
    ZTEMPLATE_OVERFLOW,      /* output buffer too small or length overflow */
    ZTEMPLATE_UNKNOWN_VAR,   /* lookup returned false */
    ZTEMPLATE_NO_MEMORY      /* segment allocation failed */
} ztemplate_status;

/* Parse text[0..text_len); text may be NULL only with text_len == 0.
 * Returns NULL on parse error or allocation failure, including an
 * unrepresentable allocation size. On parse error, non-NULL err_pos
 * receives the byte offset of the offending construct. */
ztemplate *ztemplate_parse(const char *text, size_t text_len,
                           size_t *err_pos);
void ztemplate_free(ztemplate *tp);

/* Lookup callback: return true and set *value and *value_len for
 * name, false when the variable is unknown. Values are borrowed, not
 * copied. */
typedef bool (*ztemplate_lookup)(const char *name, size_t name_len,
                                 const char **value, size_t *value_len,
                                 void *ctx);

/* Render into out[0..out_cap). On success or buffer overflow, *out_len
 * receives the rendered length. If that length cannot fit in size_t,
 * rendering stops before the overflowing segment, *out_len is SIZE_MAX,
 * and ZTEMPLATE_OVERFLOW is returned. Returns ZTEMPLATE_OVERFLOW when
 * out is NULL or too small, including space for the NUL terminator.
 * Any supplied nonempty output buffer is NUL-terminated on overflow.
 * Invalid arguments or unknown variables return an error; their output
 * buffer and length are unspecified. */
ztemplate_status ztemplate_render(const ztemplate *tp,
                                  ztemplate_lookup lookup, void *ctx,
                                  char *out, size_t out_cap,
                                  size_t *out_len);

/* Number of distinct variable names in the template. */
size_t ztemplate_var_count(const ztemplate *tp);

/* Visit each distinct variable name (parse order, deduplicated).
 * Return false from fn to stop early. */
bool ztemplate_foreach_var(const ztemplate *tp,
                           bool (*fn)(const char *name, size_t name_len,
                                      void *ctx),
                           void *ctx);

#ifdef __cplusplus
}
#endif

#endif /* ZTEMPLATE_H */
