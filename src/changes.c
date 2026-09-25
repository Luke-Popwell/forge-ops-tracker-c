#include "forgeops_tracker/changes.h"

#include <ctype.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <time.h>

#include "forgeops_tracker/client.h"
#include "strbuf.h"

/* The delivery queue and its thread: see spans.c, whose queue this one copies. */
static pthread_mutex_t queue_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t queue_wake = PTHREAD_COND_INITIALIZER;
static char *queue[FORGEOPS_CHANGES_QUEUE_LIMIT];
static size_t queue_count = 0;
static int worker_running = 0;
static int worker_stop = 0;
static pthread_t worker;
static const forgeops_configuration_t *worker_config = NULL;
static int atexit_registered = 0;

static const char *const KINDS[] = {"feature_flag", "config", "migration", "dependency", "infrastructure", "other"};

static const char *normalize_kind(const char *kind) {
  if (kind != NULL) {
    for (size_t i = 0; i < sizeof(KINDS) / sizeof(KINDS[0]); i++) {
      if (strcmp(kind, KINDS[i]) == 0) return KINDS[i];
    }
  }
  return "other";
}

static void append_json_string_n(forgeops_strbuf_t *out, const char *value, size_t length) {
  forgeops_strbuf_append(out, "\"", 1);
  const unsigned char *p = (const unsigned char *)value;
  for (size_t i = 0; i < length; i++) {
    switch (p[i]) {
      case '"': forgeops_strbuf_append(out, "\\\"", 2); break;
      case '\\': forgeops_strbuf_append(out, "\\\\", 2); break;
      case '\n': forgeops_strbuf_append(out, "\\n", 2); break;
      case '\r': forgeops_strbuf_append(out, "\\r", 2); break;
      case '\t': forgeops_strbuf_append(out, "\\t", 2); break;
      default:
        if (p[i] < 0x20) {
          char escaped[8];
          snprintf(escaped, sizeof(escaped), "\\u%04x", p[i]);
          forgeops_strbuf_append_str(out, escaped);
        } else {
          forgeops_strbuf_append(out, (const char *)p + i, 1);
        }
    }
  }
  forgeops_strbuf_append(out, "\"", 1);
}

static void append_json_string(forgeops_strbuf_t *out, const char *value) {
  const char *text = value != NULL ? value : "";
  append_json_string_n(out, text, strlen(text));
}

static void append_optional_field(forgeops_strbuf_t *out, const char *key, const char *value) {
  if (value == NULL) return;
  forgeops_strbuf_append_str(out, ",\"");
  forgeops_strbuf_append_str(out, key);
  forgeops_strbuf_append_str(out, "\":");
  append_json_string(out, value);
}

static long long now_unix_ms(void) {
  struct timeval tv;
  gettimeofday(&tv, NULL);
  return (long long)tv.tv_sec * 1000 + tv.tv_usec / 1000;
}

static void append_timestamp(forgeops_strbuf_t *out, long long unix_ms) {
  time_t seconds = (time_t)(unix_ms / 1000);
  long millis = (long)(unix_ms % 1000);
  if (millis < 0) millis = 0;
  struct tm utc;
  gmtime_r(&seconds, &utc);
  char formatted[40];
  size_t n = strftime(formatted, sizeof(formatted), "%Y-%m-%dT%H:%M:%S", &utc);
  snprintf(formatted + n, sizeof(formatted) - n, ".%03ldZ", millis);
  append_json_string(out, formatted);
}

/* How many bytes of text make up its first max_chars UTF-8 characters: counting lead bytes only,
 * so the cut never lands inside a multibyte character. */
static size_t utf8_prefix_length(const char *text, size_t length, size_t max_chars) {
  size_t chars = 0;
  for (size_t i = 0; i < length; i++) {
    if ((((unsigned char)text[i]) & 0xC0) != 0x80) {
      if (chars == max_chars) return i;
      chars++;
    }
  }
  return length;
}

char *forgeops_changes_build(const forgeops_configuration_t *config, const char *kind, const char *title, const char **details_keys, const char **details_values, size_t details_count, const forgeops_change_options_t *options) {
  if (config == NULL || title == NULL) return NULL;

  const char *start = title;
  while (*start != '\0' && isspace((unsigned char)*start)) start++;
  size_t length = strlen(start);
  while (length > 0 && isspace((unsigned char)start[length - 1])) length--;
  if (length == 0) return NULL;
  length = utf8_prefix_length(start, length, FORGEOPS_CHANGES_MAX_TITLE_CHARS);

  forgeops_change_options_t none = {0};
  if (options == NULL) options = &none;

  forgeops_strbuf_t out;
  if (forgeops_strbuf_init(&out, 512) != 0) return NULL;
  forgeops_strbuf_append_str(&out, "{\"kind\":");
  append_json_string(&out, normalize_kind(kind));
  forgeops_strbuf_append_str(&out, ",\"title\":");
  append_json_string_n(&out, start, length);
  forgeops_strbuf_append_str(&out, ",\"environment\":");
  append_json_string(&out, options->environment != NULL ? options->environment : (config->environment != NULL ? config->environment : ""));
  forgeops_strbuf_append_str(&out, ",\"occurred_at\":");
  append_timestamp(&out, options->occurred_at_unix_ms != 0 ? options->occurred_at_unix_ms : now_unix_ms());
  if (details_keys != NULL && details_values != NULL && details_count > 0) {
    forgeops_strbuf_append_str(&out, ",\"details\":{");
    for (size_t i = 0; i < details_count; i++) {
      if (i > 0) forgeops_strbuf_append(&out, ",", 1);
      append_json_string(&out, details_keys[i]);
      forgeops_strbuf_append(&out, ":", 1);
      append_json_string(&out, details_values[i]);
    }
    forgeops_strbuf_append(&out, "}", 1);
  }
  append_optional_field(&out, "service", options->service);
  append_optional_field(&out, "actor", options->actor);
  append_optional_field(&out, "url", options->url);
  append_optional_field(&out, "id", options->id);
  forgeops_strbuf_append(&out, "}", 1);
  return out.data;
}

static void *worker_main(void *unused) {
  (void)unused;
  pthread_mutex_lock(&queue_lock);
  for (;;) {
    while (queue_count == 0 && !worker_stop) pthread_cond_wait(&queue_wake, &queue_lock);
    if (queue_count == 0) break; /* stopping, and drained */

    char *body = queue[0];
    memmove(queue, queue + 1, (queue_count - 1) * sizeof(char *));
    queue_count--;
    const forgeops_configuration_t *config = worker_config;
    pthread_mutex_unlock(&queue_lock);
    if (config != NULL) forgeops_client_deliver_changes(config, body);
    free(body);
    pthread_mutex_lock(&queue_lock);
  }
  pthread_mutex_unlock(&queue_lock);
  return NULL;
}

static void drain_at_exit(void) {
  pthread_mutex_lock(&queue_lock);
  int was_running = worker_running;
  worker_stop = 1;
  pthread_cond_broadcast(&queue_wake);
  pthread_mutex_unlock(&queue_lock);
  if (was_running) pthread_join(worker, NULL);
}

int forgeops_changes_enqueue(const forgeops_configuration_t *config, char *body) {
  if (body == NULL) return 0;
  pthread_mutex_lock(&queue_lock);
  if (queue_count >= FORGEOPS_CHANGES_QUEUE_LIMIT) {
    pthread_mutex_unlock(&queue_lock);
    free(body);
    return 0;
  }
  queue[queue_count++] = body;
  worker_config = config;
  if (!atexit_registered) {
    atexit_registered = 1;
    atexit(drain_at_exit);
  }
  if (!worker_running) {
    worker_stop = 0;
    if (pthread_create(&worker, NULL, worker_main, NULL) == 0) worker_running = 1;
  }
  pthread_cond_signal(&queue_wake);
  pthread_mutex_unlock(&queue_lock);
  return 1;
}

void forgeops_changes_reset_for_testing(void) {
  pthread_mutex_lock(&queue_lock);
  int was_running = worker_running;
  for (size_t i = 0; i < queue_count; i++) free(queue[i]);
  queue_count = 0;
  worker_stop = 1;
  worker_config = NULL;
  pthread_cond_broadcast(&queue_wake);
  pthread_mutex_unlock(&queue_lock);
  if (was_running) pthread_join(worker, NULL);

  pthread_mutex_lock(&queue_lock);
  worker_running = 0;
  worker_stop = 0;
  pthread_mutex_unlock(&queue_lock);
}
