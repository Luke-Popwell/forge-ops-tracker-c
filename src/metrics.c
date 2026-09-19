#include "forgeops_tracker/metrics.h"

#include <math.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "forgeops_tracker/client.h"
#include "strbuf.h"

typedef struct {
  char *entries[FORGEOPS_METRICS_MAX_ENTRIES];
  size_t count;
  int worker_running;
  pthread_t worker;
} buffer_t;

static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t wake = PTHREAD_COND_INITIALIZER;
static buffer_t buffers[2];
static int worker_stop = 0;
static const forgeops_configuration_t *worker_config = NULL;
static int atexit_registered = 0;
static void (*before_delivery_hook)(void) = NULL;

typedef struct {
  forgeops_metric_kind_t kind;
} worker_arg_t;
static worker_arg_t worker_args[2] = {{FORGEOPS_METRIC_CUSTOM}, {FORGEOPS_METRIC_INFRASTRUCTURE}};

static long interval_seconds(const forgeops_configuration_t *config, forgeops_metric_kind_t kind) {
  long value = kind == FORGEOPS_METRIC_CUSTOM ? config->metric_flush_interval_seconds : config->infrastructure_metric_flush_interval_seconds;
  return value > 0 ? value : 60;
}

static void *worker_main(void *arg) {
  forgeops_metric_kind_t kind = ((worker_arg_t *)arg)->kind;
  pthread_mutex_lock(&lock);
  while (!worker_stop) {
    const forgeops_configuration_t *config = worker_config;
    struct timespec deadline;
    clock_gettime(CLOCK_REALTIME, &deadline);
    deadline.tv_sec += config != NULL ? interval_seconds(config, kind) : 60;
    pthread_cond_timedwait(&wake, &lock, &deadline);
    if (worker_stop) break;

    config = worker_config;
    pthread_mutex_unlock(&lock);
    if (config != NULL) forgeops_metrics_flush(config, kind);
    pthread_mutex_lock(&lock);
  }
  pthread_mutex_unlock(&lock);
  return NULL;
}

static void flush_at_exit(void) {
  pthread_mutex_lock(&lock);
  const forgeops_configuration_t *config = worker_config;
  pthread_mutex_unlock(&lock);
  if (config == NULL) return;
  forgeops_metrics_flush(config, FORGEOPS_METRIC_CUSTOM);
  forgeops_metrics_flush(config, FORGEOPS_METRIC_INFRASTRUCTURE);
}

/* Called with the lock held. */
static void ensure_worker_started(const forgeops_configuration_t *config, forgeops_metric_kind_t kind) {
  worker_config = config;
  if (!atexit_registered) {
    atexit_registered = 1;
    atexit(flush_at_exit);
  }
  if (buffers[kind].worker_running) return;
  worker_stop = 0;
  if (pthread_create(&buffers[kind].worker, NULL, worker_main, &worker_args[kind]) == 0) buffers[kind].worker_running = 1;
}

static void append_json_string(forgeops_strbuf_t *out, const char *value) {
  forgeops_strbuf_append(out, "\"", 1);
  for (const unsigned char *p = (const unsigned char *)value; *p != '\0'; p++) {
    switch (*p) {
      case '"': forgeops_strbuf_append(out, "\\\"", 2); break;
      case '\\': forgeops_strbuf_append(out, "\\\\", 2); break;
      case '\n': forgeops_strbuf_append(out, "\\n", 2); break;
      case '\r': forgeops_strbuf_append(out, "\\r", 2); break;
      case '\t': forgeops_strbuf_append(out, "\\t", 2); break;
      default:
        if (*p < 0x20) {
          char escaped[8];
          snprintf(escaped, sizeof(escaped), "\\u%04x", *p);
          forgeops_strbuf_append_str(out, escaped);
        } else {
          forgeops_strbuf_append(out, (const char *)p, 1);
        }
    }
  }
  forgeops_strbuf_append(out, "\"", 1);
}

int forgeops_metrics_record(const forgeops_configuration_t *config, forgeops_metric_kind_t kind, double value, const char *fields_json) {
  if (config == NULL || fields_json == NULL || !isfinite(value)) return 0;

  time_t now = time(NULL);
  struct tm utc;
  gmtime_r(&now, &utc);
  char stamp[32];
  strftime(stamp, sizeof(stamp), "%Y-%m-%dT%H:%M:%SZ", &utc);

  forgeops_strbuf_t entry;
  if (forgeops_strbuf_init(&entry, strlen(fields_json) + 64) != 0) return 0;
  forgeops_strbuf_append(&entry, "{", 1);
  forgeops_strbuf_append_str(&entry, fields_json);
  forgeops_strbuf_append_str(&entry, ",\"recorded_at\":");
  append_json_string(&entry, stamp);
  forgeops_strbuf_append(&entry, "}", 1);

  pthread_mutex_lock(&lock);
  buffer_t *buffer = &buffers[kind];
  if (buffer->count >= FORGEOPS_METRICS_MAX_ENTRIES) {
    pthread_mutex_unlock(&lock);
    free(entry.data);
    return 0;
  }
  ensure_worker_started(config, kind);
  buffer->entries[buffer->count++] = entry.data;
  pthread_mutex_unlock(&lock);
  return 1;
}

void forgeops_metrics_flush(const forgeops_configuration_t *config, forgeops_metric_kind_t kind) {
  pthread_mutex_lock(&lock);
  buffer_t *buffer = &buffers[kind];
  size_t count = buffer->count;
  if (count == 0) {
    pthread_mutex_unlock(&lock);
    return;
  }

  forgeops_strbuf_t body;
  if (forgeops_strbuf_init(&body, 256 + count * 128) != 0) {
    pthread_mutex_unlock(&lock);
    return;
  }
  forgeops_strbuf_append_str(&body, "{\"metrics\":[");
  for (size_t i = 0; i < count; i++) {
    if (i > 0) forgeops_strbuf_append(&body, ",", 1);
    forgeops_strbuf_append_str(&body, buffer->entries[i]);
  }
  forgeops_strbuf_append_str(&body, "]}");
  pthread_mutex_unlock(&lock);

  if (before_delivery_hook != NULL) before_delivery_hook();

  int delivered = kind == FORGEOPS_METRIC_CUSTOM ? forgeops_client_deliver_metrics(config, body.data) : forgeops_client_deliver_infrastructure_metrics(config, body.data);
  free(body.data);
  if (!delivered) return;

  pthread_mutex_lock(&lock);
  /* Exactly the entries just delivered: anything recorded while the request was in flight sits after
   * them and stays for the next flush. */
  for (size_t i = 0; i < count; i++) free(buffer->entries[i]);
  memmove(buffer->entries, buffer->entries + count, (buffer->count - count) * sizeof(char *));
  buffer->count -= count;
  pthread_mutex_unlock(&lock);
}

void forgeops_metrics_set_before_delivery_hook_for_testing(void (*hook)(void)) {
  before_delivery_hook = hook;
}

size_t forgeops_metrics_count_for_testing(forgeops_metric_kind_t kind) {
  pthread_mutex_lock(&lock);
  size_t count = buffers[kind].count;
  pthread_mutex_unlock(&lock);
  return count;
}

void forgeops_metrics_reset_for_testing(void) {
  pthread_mutex_lock(&lock);
  int was_running[2] = {buffers[0].worker_running, buffers[1].worker_running};
  worker_stop = 1;
  worker_config = NULL;
  pthread_cond_broadcast(&wake);
  pthread_mutex_unlock(&lock);
  for (int k = 0; k < 2; k++) {
    if (was_running[k]) pthread_join(buffers[k].worker, NULL);
  }

  pthread_mutex_lock(&lock);
  worker_stop = 0;
  for (int k = 0; k < 2; k++) {
    buffers[k].worker_running = 0;
    for (size_t i = 0; i < buffers[k].count; i++) free(buffers[k].entries[i]);
    buffers[k].count = 0;
  }
  before_delivery_hook = NULL;
  pthread_mutex_unlock(&lock);
}
