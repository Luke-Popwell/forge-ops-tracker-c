#ifndef FORGEOPS_TRACKER_INTERNAL_STRBUF_H
#define FORGEOPS_TRACKER_INTERNAL_STRBUF_H

/* A tiny growable-buffer helper shared across this SDK's .c files (never installed -- an
 * implementation detail, not part of the public API). Header-only/static so there's no separate
 * translation unit or build-system entry needed for something this small. */

#include <stdlib.h>
#include <string.h>

typedef struct {
  char *data;
  size_t length;
  size_t capacity;
} forgeops_strbuf_t;

static inline int forgeops_strbuf_init(forgeops_strbuf_t *buf, size_t initial_capacity) {
  if (initial_capacity < 1) initial_capacity = 1;
  buf->data = malloc(initial_capacity);
  if (buf->data == NULL) return -1;
  buf->data[0] = '\0';
  buf->length = 0;
  buf->capacity = initial_capacity;
  return 0;
}

static inline int forgeops_strbuf_append(forgeops_strbuf_t *buf, const char *text, size_t text_len) {
  if (buf->length + text_len + 1 > buf->capacity) {
    size_t new_capacity = buf->capacity * 2;
    while (new_capacity < buf->length + text_len + 1) new_capacity *= 2;
    char *grown = realloc(buf->data, new_capacity);
    if (grown == NULL) return -1;
    buf->data = grown;
    buf->capacity = new_capacity;
  }
  memcpy(buf->data + buf->length, text, text_len);
  buf->length += text_len;
  buf->data[buf->length] = '\0';
  return 0;
}

static inline int forgeops_strbuf_append_str(forgeops_strbuf_t *buf, const char *text) {
  return forgeops_strbuf_append(buf, text, strlen(text));
}

#endif
