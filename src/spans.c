#include "forgeops_tracker/spans.h"

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "forgeops_tracker/client.h"
#include "strbuf.h"

typedef struct {
  char trace_id[FORGEOPS_TRACE_ID_LENGTH + 1];
  char root_span_id[FORGEOPS_SPAN_ID_LENGTH + 1];
  char remote_parent_span_id[FORGEOPS_SPAN_ID_LENGTH + 1]; /* "" unless continuing another service's trace */
  int send; /* track_tracing as it was when the trace began: whether trace_end sends the spans at all */
  forgeops_strbuf_t spans; /* finished spans, each one JSON object, comma-separated */
  int span_count;
  char open[FORGEOPS_SPANS_MAX_DEPTH][FORGEOPS_SPAN_ID_LENGTH + 1];
  int open_count;
} trace_t;

static _Thread_local trace_t *current_trace = NULL;

/* The delivery queue and its thread. */
static pthread_mutex_t queue_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t queue_wake = PTHREAD_COND_INITIALIZER;
static char *queue[FORGEOPS_SPANS_QUEUE_LIMIT];
static size_t queue_count = 0;
static int worker_running = 0;
static int worker_stop = 0;
static pthread_t worker;
static const forgeops_configuration_t *worker_config = NULL;
static int atexit_registered = 0;

static const char *const KINDS[] = {"controller", "service", "database", "redis", "http", "job", "other"};

static const char *normalize_kind(const char *kind) {
  if (kind != NULL) {
    for (size_t i = 0; i < sizeof(KINDS) / sizeof(KINDS[0]); i++) {
      if (strcmp(kind, KINDS[i]) == 0) return KINDS[i];
    }
  }
  return "other";
}

static void append_json_string(forgeops_strbuf_t *out, const char *value) {
  forgeops_strbuf_append(out, "\"", 1);
  for (const unsigned char *p = (const unsigned char *)(value != NULL ? value : ""); *p != '\0'; p++) {
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

/* One span as a JSON object; parent NULL encodes null (the root). */
static void append_span(forgeops_strbuf_t *out, const forgeops_configuration_t *config, const char *id, const char *parent, const char *name, const char *kind, long long started_at_unix_ms, double duration_ms, const char **data_keys, const char **data_values, size_t data_count) {
  forgeops_strbuf_append_str(out, "{\"span_id\":");
  append_json_string(out, id);
  forgeops_strbuf_append_str(out, ",\"parent_span_id\":");
  if (parent != NULL) {
    append_json_string(out, parent);
  } else {
    forgeops_strbuf_append_str(out, "null");
  }
  forgeops_strbuf_append_str(out, ",\"name\":");
  append_json_string(out, name);
  forgeops_strbuf_append_str(out, ",\"kind\":");
  append_json_string(out, normalize_kind(kind));
  forgeops_strbuf_append_str(out, ",\"started_at\":");
  append_timestamp(out, started_at_unix_ms);
  char number[64];
  snprintf(number, sizeof(number), ",\"duration_ms\":%.2f,\"environment\":", duration_ms);
  forgeops_strbuf_append_str(out, number);
  append_json_string(out, config->environment != NULL ? config->environment : "");
  forgeops_strbuf_append_str(out, ",\"release\":");
  if (config->release != NULL) {
    append_json_string(out, config->release);
  } else {
    forgeops_strbuf_append_str(out, "null");
  }
  forgeops_strbuf_append_str(out, ",\"data\":{");
  for (size_t i = 0; i < data_count; i++) {
    if (i > 0) forgeops_strbuf_append(out, ",", 1);
    append_json_string(out, data_keys[i]);
    forgeops_strbuf_append(out, ":", 1);
    append_json_string(out, data_values[i]);
  }
  forgeops_strbuf_append_str(out, "}}");
}

static const char *current_parent(const trace_t *trace) {
  return trace->open_count > 0 ? trace->open[trace->open_count - 1] : trace->root_span_id;
}

static void record(trace_t *trace, const forgeops_configuration_t *config, const char *id, const char *parent, const char *name, const char *kind, long long started_at_unix_ms, double duration_ms, const char **data_keys, const char **data_values, size_t data_count) {
  if (trace->span_count >= FORGEOPS_SPANS_MAX_SPANS - 1) return; /* leave room for the root */
  if (trace->span_count > 0) forgeops_strbuf_append(&trace->spans, ",", 1);
  append_span(&trace->spans, config, id, parent, name, kind, started_at_unix_ms, duration_ms, data_keys, data_values, data_count);
  trace->span_count++;
}

static void free_trace(trace_t *trace) {
  if (trace == NULL) return;
  free(trace->spans.data);
  free(trace);
}

int forgeops_spans_trace_begin(const forgeops_configuration_t *config, const char *traceparent) {
  if (config == NULL || current_trace != NULL) return 0;
  if (!forgeops_configuration_is_enabled(config)) return 0;

  trace_t *trace = calloc(1, sizeof(trace_t));
  if (trace == NULL) return 0;
  if (forgeops_strbuf_init(&trace->spans, 1024) != 0) {
    free(trace);
    return 0;
  }
  if (!forgeops_traceparent_parse(traceparent, trace->trace_id, trace->remote_parent_span_id)) {
    forgeops_trace_random_id(trace->trace_id, FORGEOPS_TRACE_ID_LENGTH);
    trace->remote_parent_span_id[0] = '\0';
  }
  forgeops_trace_random_id(trace->root_span_id, FORGEOPS_SPAN_ID_LENGTH);
  trace->send = config->track_tracing;
  current_trace = trace;
  return 1;
}

const char *forgeops_spans_current_trace_id(void) {
  return current_trace != NULL ? current_trace->trace_id : NULL;
}

void forgeops_spans_write_raw_trace_id_to_fd(int fd) {
  const trace_t *trace = current_trace;
  if (trace == NULL) return;
  (void)!write(fd, "#trace_id ", 10);
  (void)!write(fd, trace->trace_id, FORGEOPS_TRACE_ID_LENGTH);
  (void)!write(fd, "\n", 1);
}

static void worker_deliver_loop(void) {
  pthread_mutex_lock(&queue_lock);
  for (;;) {
    while (queue_count == 0 && !worker_stop) pthread_cond_wait(&queue_wake, &queue_lock);
    if (queue_count == 0) break; /* stopping, and drained */

    char *body = queue[0];
    memmove(queue, queue + 1, (queue_count - 1) * sizeof(char *));
    queue_count--;
    const forgeops_configuration_t *config = worker_config;
    pthread_mutex_unlock(&queue_lock);
    if (config != NULL) forgeops_client_deliver_spans(config, body);
    free(body);
    pthread_mutex_lock(&queue_lock);
  }
  pthread_mutex_unlock(&queue_lock);
}

static void *worker_main(void *unused) {
  (void)unused;
  worker_deliver_loop();
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

/* Takes ownership of body. Drops it when the queue is full: a request slow enough to be traced must
 * not be made slower still by waiting on the tracker. */
static void enqueue(const forgeops_configuration_t *config, char *body) {
  pthread_mutex_lock(&queue_lock);
  if (queue_count >= FORGEOPS_SPANS_QUEUE_LIMIT) {
    pthread_mutex_unlock(&queue_lock);
    free(body);
    return;
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
}

void forgeops_spans_trace_end(const forgeops_configuration_t *config, const char *root_name, long long started_at_unix_ms, double duration_ms) {
  trace_t *trace = current_trace;
  current_trace = NULL;
  if (trace == NULL || config == NULL) {
    free_trace(trace);
    return;
  }

  if (trace->send && duration_ms >= (double)config->trace_capture_threshold_ms) {
    forgeops_strbuf_t body;
    if (forgeops_strbuf_init(&body, trace->spans.length + 512) == 0) {
      forgeops_strbuf_append_str(&body, "{\"trace_id\":\"");
      forgeops_strbuf_append_str(&body, trace->trace_id);
      forgeops_strbuf_append_str(&body, "\",\"spans\":[");
      append_span(&body, config, trace->root_span_id, trace->remote_parent_span_id[0] != '\0' ? trace->remote_parent_span_id : NULL, root_name != NULL ? root_name : "trace", "controller", started_at_unix_ms, duration_ms, NULL, NULL, 0);
      if (trace->span_count > 0) {
        forgeops_strbuf_append(&body, ",", 1);
        forgeops_strbuf_append(&body, trace->spans.data, trace->spans.length);
      }
      forgeops_strbuf_append_str(&body, "]}");
      enqueue(config, body.data);
    }
  }
  free_trace(trace);
}

void forgeops_spans_start(forgeops_span_state_t *state) {
  state->active = 0;
  trace_t *trace = current_trace;
  if (trace == NULL) return;

  forgeops_trace_random_id(state->id, FORGEOPS_SPAN_ID_LENGTH);
  snprintf(state->parent, sizeof(state->parent), "%s", current_parent(trace));
  if (trace->open_count < FORGEOPS_SPANS_MAX_DEPTH) {
    memcpy(trace->open[trace->open_count++], state->id, sizeof(state->id));
  }
  state->active = 1;
}

void forgeops_spans_stop(const forgeops_configuration_t *config, forgeops_span_state_t *state, const char *name, const char *kind, double duration_ms, const char **data_keys, const char **data_values, size_t data_count) {
  if (state == NULL || !state->active) return;
  state->active = 0;

  trace_t *trace = current_trace;
  if (trace == NULL || config == NULL) return;

  for (int i = trace->open_count - 1; i >= 0; i--) {
    if (strcmp(trace->open[i], state->id) == 0) {
      memmove(trace->open[i], trace->open[i + 1], (size_t)(trace->open_count - 1 - i) * sizeof(trace->open[0]));
      trace->open_count--;
      break;
    }
  }
  record(trace, config, state->id, state->parent, name, kind, state->started_at_unix_ms, duration_ms, data_keys, data_values, data_count);
}

void forgeops_spans_record(const forgeops_configuration_t *config, const char *name, const char *kind, long long started_at_unix_ms, double duration_ms, const char **data_keys, const char **data_values, size_t data_count) {
  trace_t *trace = current_trace;
  if (trace == NULL || config == NULL) return;

  char id[FORGEOPS_SPAN_ID_LENGTH + 1];
  forgeops_trace_random_id(id, FORGEOPS_SPAN_ID_LENGTH);
  record(trace, config, id, current_parent(trace), name, kind, started_at_unix_ms, duration_ms, data_keys, data_values, data_count);
}

int forgeops_spans_active_for_testing(void) {
  return current_trace != NULL;
}

int forgeops_spans_count_for_testing(void) {
  return current_trace != NULL ? current_trace->span_count : -1;
}

int forgeops_spans_worker_started_for_testing(void) {
  pthread_mutex_lock(&queue_lock);
  int started = worker_running;
  pthread_mutex_unlock(&queue_lock);
  return started;
}

void forgeops_spans_reset_for_testing(void) {
  free_trace(current_trace);
  current_trace = NULL;

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
