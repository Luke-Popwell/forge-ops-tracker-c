#include "forgeops_tracker/performance.h"

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "forgeops_tracker/client.h"
#include "strbuf.h"

typedef struct {
  char *name;
  unsigned long count;
  double duration_sum_ms;
  double max_duration_ms;
} bucket_t;

static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t wake = PTHREAD_COND_INITIALIZER;
static bucket_t *buckets = NULL;
static size_t bucket_count = 0;
static size_t bucket_capacity = 0;
static time_t period_started_at = 0;

static int worker_running = 0;
static int worker_stop = 0;
static pthread_t worker;
static const forgeops_configuration_t *worker_config = NULL;
static int atexit_registered = 0;
static void (*before_delivery_hook)(void) = NULL;

static bucket_t *find_bucket(const char *name) {
  for (size_t i = 0; i < bucket_count; i++) {
    if (strcmp(buckets[i].name, name) == 0) return &buckets[i];
  }
  return NULL;
}

static void free_snapshot(bucket_t *snapshot, size_t count) {
  if (snapshot == NULL) return;
  for (size_t i = 0; i < count; i++) free(snapshot[i].name);
  free(snapshot);
}

static void *worker_main(void *unused) {
  (void)unused;
  pthread_mutex_lock(&lock);
  while (!worker_stop) {
    long interval = worker_config != NULL && worker_config->performance_flush_interval_seconds > 0 ? worker_config->performance_flush_interval_seconds : 60;
    struct timespec deadline;
    clock_gettime(CLOCK_REALTIME, &deadline);
    deadline.tv_sec += interval;
    pthread_cond_timedwait(&wake, &lock, &deadline);
    if (worker_stop) break;

    const forgeops_configuration_t *config = worker_config;
    pthread_mutex_unlock(&lock);
    if (config != NULL) forgeops_performance_flush(config);
    pthread_mutex_lock(&lock);
  }
  pthread_mutex_unlock(&lock);
  return NULL;
}

static void flush_at_exit(void) {
  pthread_mutex_lock(&lock);
  const forgeops_configuration_t *config = worker_config;
  pthread_mutex_unlock(&lock);
  if (config != NULL) forgeops_performance_flush(config);
}

/* Called with the lock held. */
static void ensure_worker_started(const forgeops_configuration_t *config) {
  worker_config = config;
  if (!atexit_registered) {
    atexit_registered = 1;
    atexit(flush_at_exit);
  }
  if (worker_running) return;
  worker_stop = 0;
  if (pthread_create(&worker, NULL, worker_main, NULL) == 0) worker_running = 1;
}

void forgeops_performance_record(const forgeops_configuration_t *config, const char *transaction_name, double duration_ms) {
  if (config == NULL || transaction_name == NULL || !config->track_performance || !forgeops_configuration_is_enabled(config)) return;

  pthread_mutex_lock(&lock);
  ensure_worker_started(config);

  bucket_t *bucket = find_bucket(transaction_name);
  if (bucket == NULL && bucket_count < FORGEOPS_PERFORMANCE_MAX_TRANSACTIONS) {
    if (bucket_count == bucket_capacity) {
      size_t new_capacity = bucket_capacity == 0 ? 16 : bucket_capacity * 2;
      bucket_t *grown = realloc(buckets, new_capacity * sizeof(bucket_t));
      if (grown != NULL) {
        buckets = grown;
        bucket_capacity = new_capacity;
      }
    }
    char *name = strdup(transaction_name);
    if (name != NULL && bucket_count < bucket_capacity) {
      if (bucket_count == 0) period_started_at = time(NULL);
      bucket = &buckets[bucket_count++];
      bucket->name = name;
      bucket->count = 0;
      bucket->duration_sum_ms = 0;
      bucket->max_duration_ms = 0;
    } else {
      free(name);
    }
  }
  if (bucket != NULL) {
    bucket->count++;
    bucket->duration_sum_ms += duration_ms;
    if (duration_ms > bucket->max_duration_ms) bucket->max_duration_ms = duration_ms;
  }
  pthread_mutex_unlock(&lock);
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

static void append_timestamp(forgeops_strbuf_t *out, time_t when) {
  struct tm utc;
  gmtime_r(&when, &utc);
  char formatted[32];
  strftime(formatted, sizeof(formatted), "%Y-%m-%dT%H:%M:%SZ", &utc);
  append_json_string(out, formatted);
}

static char *build_samples_json(const forgeops_configuration_t *config, const bucket_t *snapshot, size_t count, time_t period_start, time_t period_end) {
  forgeops_strbuf_t out;
  if (forgeops_strbuf_init(&out, 512) != 0) return NULL;

  forgeops_strbuf_append_str(&out, "{\"samples\":[");
  for (size_t i = 0; i < count; i++) {
    if (i > 0) forgeops_strbuf_append(&out, ",", 1);
    char numbers[128];
    forgeops_strbuf_append_str(&out, "{\"transaction_name\":");
    append_json_string(&out, snapshot[i].name);
    forgeops_strbuf_append_str(&out, ",\"environment\":");
    append_json_string(&out, config->environment != NULL ? config->environment : "");
    forgeops_strbuf_append_str(&out, ",\"release\":");
    if (config->release != NULL) {
      append_json_string(&out, config->release);
    } else {
      forgeops_strbuf_append_str(&out, "null");
    }
    forgeops_strbuf_append_str(&out, ",\"period_started_at\":");
    append_timestamp(&out, period_start);
    forgeops_strbuf_append_str(&out, ",\"period_ended_at\":");
    append_timestamp(&out, period_end);
    snprintf(numbers, sizeof(numbers), ",\"request_count\":%lu,\"duration_sum_ms\":%.3f,\"max_duration_ms\":%.3f}", snapshot[i].count, snapshot[i].duration_sum_ms, snapshot[i].max_duration_ms);
    forgeops_strbuf_append_str(&out, numbers);
  }
  forgeops_strbuf_append_str(&out, "]}");
  return out.data;
}

void forgeops_performance_flush(const forgeops_configuration_t *config) {
  pthread_mutex_lock(&lock);
  if (bucket_count == 0) {
    pthread_mutex_unlock(&lock);
    return;
  }

  size_t count = bucket_count;
  bucket_t *snapshot = calloc(count, sizeof(bucket_t));
  if (snapshot == NULL) {
    pthread_mutex_unlock(&lock);
    return;
  }
  for (size_t i = 0; i < count; i++) {
    snapshot[i] = buckets[i];
    snapshot[i].name = strdup(buckets[i].name);
    if (snapshot[i].name == NULL) {
      free_snapshot(snapshot, i);
      pthread_mutex_unlock(&lock);
      return;
    }
  }
  time_t period_start = period_started_at;
  time_t period_end = time(NULL);
  pthread_mutex_unlock(&lock);

  if (before_delivery_hook != NULL) before_delivery_hook();

  char *body = build_samples_json(config, snapshot, count, period_start, period_end);
  int delivered = body != NULL && forgeops_client_deliver_performance_samples(config, body);
  free(body);
  if (!delivered) {
    free_snapshot(snapshot, count);
    return;
  }

  pthread_mutex_lock(&lock);
  for (size_t i = 0; i < count; i++) {
    bucket_t *current = find_bucket(snapshot[i].name);
    if (current == NULL) continue;

    current->count = current->count > snapshot[i].count ? current->count - snapshot[i].count : 0;
    current->duration_sum_ms -= snapshot[i].duration_sum_ms;
    if (current->duration_sum_ms < 0) current->duration_sum_ms = 0;
    /* max_duration_ms is deliberately left as whatever is currently on the bucket, sent or not:
     * unlike count/duration_sum_ms, a max can't be correctly "subtracted" back out (the true max of
     * what's left is anything at or below it, not knowable from the two numbers alone), and leaving
     * it never overstates the next period's own max, only potentially understates how far back it
     * was actually set. */
    if (current->count == 0) {
      free(current->name);
      *current = buckets[--bucket_count];
    }
  }
  period_started_at = period_end;
  pthread_mutex_unlock(&lock);
  free_snapshot(snapshot, count);
}

void forgeops_performance_set_before_delivery_hook_for_testing(void (*hook)(void)) {
  before_delivery_hook = hook;
}

int forgeops_performance_tally_for_testing(const char *transaction_name, unsigned long *count, double *duration_sum_ms, double *max_duration_ms) {
  pthread_mutex_lock(&lock);
  bucket_t *bucket = find_bucket(transaction_name);
  if (bucket != NULL) {
    *count = bucket->count;
    *duration_sum_ms = bucket->duration_sum_ms;
    *max_duration_ms = bucket->max_duration_ms;
  }
  pthread_mutex_unlock(&lock);
  return bucket != NULL;
}

void forgeops_performance_reset_for_testing(void) {
  pthread_mutex_lock(&lock);
  int was_running = worker_running;
  worker_stop = 1;
  worker_config = NULL;
  pthread_cond_broadcast(&wake);
  pthread_mutex_unlock(&lock);
  if (was_running) pthread_join(worker, NULL);

  pthread_mutex_lock(&lock);
  worker_running = 0;
  worker_stop = 0;
  for (size_t i = 0; i < bucket_count; i++) free(buckets[i].name);
  free(buckets);
  buckets = NULL;
  bucket_count = 0;
  bucket_capacity = 0;
  before_delivery_hook = NULL;
  pthread_mutex_unlock(&lock);
}
