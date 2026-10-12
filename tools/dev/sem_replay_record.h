/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Bounded record reading and complete field parsing for semantic replay. */
#ifndef ZCL_SEM_REPLAY_RECORD_H
#define ZCL_SEM_REPLAY_RECORD_H

#include "sem_replay.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Count bytes before string parsing: 1 record, 0 EOF, -1 refusal.
 * A final record without LF is complete; NUL and buffer fragments are not. */
static inline int sr_record(FILE *fp, char *line, size_t cap)
{
    size_t n = 0;
    int c;
    if (cap < 2)
        return -1;
    while ((c = fgetc(fp)) != EOF) {
        if (c == 0 || n >= cap - 1)
            return -1;
        line[n++] = (char)c;
        if (c == '\n')
            break;
    }
    if (ferror(fp))
        return -1;
    line[n] = '\0';
    return n != 0;
}

/* Split the existing tab-separated format, consuming the entire record. */
static inline size_t sr_record_fields(char *line, char **fields, size_t cap)
{
    size_t len = strlen(line), n = 0;
    if (len && line[len - 1] == '\n')
        line[--len] = '\0';
    char *next = line;
    do {
        if (n == cap || *next == '\0' || *next == '\t')
            return 0;
        fields[n++] = next;
        next = strchr(next, '\t');
        if (next)
            *next++ = '\0';
    } while (next);
    return n;
}

static inline bool sr_record_double(const char *text, double *out)
{
    char *end;
    errno = 0;
    double value = strtod(text, &end);
    if (end == text || *end != '\0' || errno == ERANGE)
        return false;
    *out = value;
    return true;
}

/* Both cost writers emit TU, CPU, wall, match. Retain the two-field
 * input accepted by the replay, but refuse incomplete or extra fields. */
static inline bool sr_record_cost(char *line, char **tu, double *cpu)
{
    char *fields[4];
    size_t n = sr_record_fields(line, fields, 4);
    double wall;
    if (n != 2 && n != 4)
        return false;
    if (strlen(fields[0]) >= SR_PATH || !sr_record_double(fields[1], cpu))
        return false;
    if (n == 4 && (!sr_record_double(fields[2], &wall) ||
                  (strcmp(fields[3], "0") && strcmp(fields[3], "1"))))
        return false;
    *tu = fields[0];
    return true;
}
#endif
