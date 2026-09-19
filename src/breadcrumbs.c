#include "forgeops_tracker/breadcrumbs.h"

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "forgeops_tracker/pii_scrubber.h"
#include "strbuf.h"

#define MAX_MESSAGE_BYTES 300
#define MAX_TAG_BYTES 64 /* category and level */

typedef struct {
  size_t capacity;
  size_t start; /* index of the oldest entry */
  size_t count;
  char (*slots)[FORGEOPS_BREADCRUMB_SLOT_SIZE];
} ring_t;

/* The signal handler reads this pointer (and the ring it points to) directly: plain loads only. */
static _Thread_local ring_t *thread_ring = NULL;

static pthread_key_t ring_key;
static pthread_once_t ring_key_once = PTHREAD_ONCE_INIT;

static void free_ring(ring_t *ring) {
  if (ring == NULL) return;
  free(ring->slots);
  free(ring);
}

/* Runs on the exiting thread itself, so it may clear that thread's own _Thread_local. */
static void ring_key_destructor(void *value) {
  thread_ring = NULL;
  free_ring((ring_t *)value);
}

static void create_ring_key(void) {
  pthread_key_create(&ring_key, ring_key_destructor);
}

static ring_t *ring_for_this_thread(size_t wanted_capacity) {
  if (thread_ring != NULL) return thread_ring;

  pthread_once(&ring_key_once, create_ring_key);
  ring_t *ring = calloc(1, sizeof(ring_t));
  if (ring == NULL) return NULL;
  ring->slots = calloc(wanted_capacity, sizeof(*ring->slots));
  if (ring->slots == NULL) {
    free(ring);
    return NULL;
  }
  ring->capacity = wanted_capacity;
  pthread_setspecific(ring_key, ring);
  thread_ring = ring;
  return ring;
}

static void json_append_escaped(forgeops_strbuf_t *out, const char *value, size_t max_bytes) {
  /* Never cuts a multi-byte UTF-8 sequence in half: a truncated sequence would make the whole
   * payload invalid UTF-8. Continuation bytes are 10xxxxxx. */
  size_t length = strlen(value);
  if (length > max_bytes) {
    length = max_bytes;
    while (length > 0 && ((unsigned char)value[length] & 0xC0) == 0x80) length--;
  }

  forgeops_strbuf_append(out, "\"", 1);
  for (size_t i = 0; i < length; i++) {
    unsigned char c = (unsigned char)value[i];
    switch (c) {
      case '"': forgeops_strbuf_append(out, "\\\"", 2); break;
      case '\\': forgeops_strbuf_append(out, "\\\\", 2); break;
      case '\n': forgeops_strbuf_append(out, "\\n", 2); break;
      case '\r': forgeops_strbuf_append(out, "\\r", 2); break;
      case '\t': forgeops_strbuf_append(out, "\\t", 2); break;
      default:
        if (c < 0x20) {
          char escaped[8];
          snprintf(escaped, sizeof(escaped), "\\u%04x", c);
          forgeops_strbuf_append_str(out, escaped);
        } else {
          forgeops_strbuf_append(out, (const char *)&c, 1);
        }
    }
  }
  forgeops_strbuf_append(out, "\"", 1);
}

/* Encodes one entry; returns a malloc'd string, or NULL on allocation failure. `data_count` pairs
 * are included, message truncated to `message_bytes`. */
static char *encode_entry(const char *message, size_t message_bytes, const char *category, const char *level, const char *timestamp, char **data_keys, char **data_values, size_t data_count) {
  forgeops_strbuf_t out;
  if (forgeops_strbuf_init(&out, 256) != 0) return NULL;

  forgeops_strbuf_append_str(&out, "{\"category\":");
  json_append_escaped(&out, category, MAX_TAG_BYTES);
  forgeops_strbuf_append_str(&out, ",\"message\":");
  json_append_escaped(&out, message, message_bytes);
  forgeops_strbuf_append_str(&out, ",\"level\":");
  json_append_escaped(&out, level, MAX_TAG_BYTES);
  forgeops_strbuf_append_str(&out, ",\"timestamp\":");
  json_append_escaped(&out, timestamp, 32);
  forgeops_strbuf_append_str(&out, ",\"data\":{");
  for (size_t i = 0; i < data_count; i++) {
    if (i > 0) forgeops_strbuf_append(&out, ",", 1);
    json_append_escaped(&out, data_keys[i], MAX_TAG_BYTES);
    forgeops_strbuf_append(&out, ":", 1);
    json_append_escaped(&out, data_values[i], MAX_MESSAGE_BYTES);
  }
  forgeops_strbuf_append_str(&out, "}}");
  return out.data;
}

void forgeops_breadcrumb_add(const forgeops_configuration_t *config, const char *message, const char *category, const char *level, const char **data_keys, const char **data_values, size_t data_count) {
  if (config == NULL || !config->track_breadcrumbs || message == NULL) return;
  if (category == NULL) category = "custom";
  if (level == NULL) level = "info";

  size_t max_entries = config->max_breadcrumbs > 0 ? (size_t)config->max_breadcrumbs : 0;
  if (max_entries > FORGEOPS_BREADCRUMB_RING_LIMIT) max_entries = FORGEOPS_BREADCRUMB_RING_LIMIT;
  if (max_entries == 0) return;

  ring_t *ring = ring_for_this_thread(max_entries);
  if (ring == NULL) return;
  if (max_entries > ring->capacity) max_entries = ring->capacity; /* raised after this thread's ring was sized */

  time_t now = time(NULL);
  struct tm utc;
  gmtime_r(&now, &utc);
  char timestamp[32];
  strftime(timestamp, sizeof(timestamp), "%Y-%m-%dT%H:%M:%SZ", &utc);

  /* Scrubbed here, at add time: see breadcrumbs.h's own comment for why. Values that turn out not
   * to need a copy (scrubbing off, or nothing to scrub) fall back to the caller's own string. */
  char *scrubbed_message = config->scrub_pii ? forgeops_scrub_string(message) : NULL;
  const char *message_to_encode = scrubbed_message != NULL ? scrubbed_message : message;

  char **keys = NULL;
  char **values = NULL;
  size_t pair_count = 0;
  if (data_count > 0 && data_keys != NULL && data_values != NULL) {
    keys = calloc(data_count, sizeof(char *));
    values = calloc(data_count, sizeof(char *));
    if (keys != NULL && values != NULL) {
      for (size_t i = 0; i < data_count; i++) {
        keys[i] = strdup(data_keys[i]);
        if (config->scrub_pii && forgeops_is_sensitive_key(data_keys[i])) {
          values[i] = strdup(FORGEOPS_REDACTED);
        } else {
          char *scrubbed = config->scrub_pii ? forgeops_scrub_string(data_values[i]) : NULL;
          values[i] = scrubbed != NULL ? scrubbed : strdup(data_values[i]);
        }
        if (keys[i] == NULL || values[i] == NULL) break;
        pair_count++;
      }
    }
  }

  /* Fit the entry to its slot: drop data pairs from the end first, then shorten the message. */
  size_t message_bytes = MAX_MESSAGE_BYTES;
  char *encoded = NULL;
  for (;;) {
    free(encoded);
    encoded = encode_entry(message_to_encode, message_bytes, category, level, timestamp, keys, values, pair_count);
    if (encoded == NULL || strlen(encoded) < FORGEOPS_BREADCRUMB_SLOT_SIZE) break;
    if (pair_count > 0) {
      pair_count--;
    } else if (message_bytes > 16) {
      message_bytes /= 2;
    } else {
      free(encoded);
      encoded = NULL;
      break;
    }
  }

  if (encoded != NULL) {
    /* Trim to the current max first (it may have been lowered), then write the new entry into the
     * slot just past the newest, and only then publish it by bumping count: a crash in the middle
     * of this function leaves the ring exactly as it was, never a half-written entry the signal
     * handler would dump. */
    while (ring->count >= max_entries) {
      ring->start = (ring->start + 1) % ring->capacity;
      ring->count--;
    }
    size_t slot = (ring->start + ring->count) % ring->capacity;
    memcpy(ring->slots[slot], encoded, strlen(encoded) + 1);
    __atomic_signal_fence(__ATOMIC_SEQ_CST);
    ring->count++;
  }

  free(encoded);
  free(scrubbed_message);
  for (size_t i = 0; i < data_count && keys != NULL && values != NULL; i++) {
    free(keys[i]);
    free(values[i]);
  }
  free(keys);
  free(values);
}

void forgeops_breadcrumbs_clear(void) {
  if (thread_ring == NULL) return;
  thread_ring->start = 0;
  thread_ring->count = 0;
}

char **forgeops_breadcrumbs_snapshot(size_t *out_count) {
  *out_count = 0;
  ring_t *ring = thread_ring;
  if (ring == NULL || ring->count == 0) return NULL;

  char **copy = calloc(ring->count, sizeof(char *));
  if (copy == NULL) return NULL;
  for (size_t i = 0; i < ring->count; i++) {
    copy[i] = strdup(ring->slots[(ring->start + i) % ring->capacity]);
    if (copy[i] == NULL) {
      forgeops_breadcrumbs_free_snapshot(copy, i);
      return NULL;
    }
  }
  *out_count = ring->count;
  return copy;
}

void forgeops_breadcrumbs_free_snapshot(char **json_objects, size_t count) {
  if (json_objects == NULL) return;
  for (size_t i = 0; i < count; i++) free(json_objects[i]);
  free(json_objects);
}

void forgeops_breadcrumbs_write_raw_to_fd(int fd) {
  ring_t *ring = thread_ring;
  if (ring == NULL) return;

  size_t count = ring->count;
  for (size_t i = 0; i < count; i++) {
    const char *json = ring->slots[(ring->start + i) % ring->capacity];
    (void)!write(fd, "#breadcrumb ", 12);
    (void)!write(fd, json, strlen(json));
    (void)!write(fd, "\n", 1);
  }
}

void forgeops_breadcrumbs_reset_for_testing(void) {
  ring_t *ring = thread_ring;
  if (ring == NULL) return;
  thread_ring = NULL;
  pthread_setspecific(ring_key, NULL);
  free_ring(ring);
}
