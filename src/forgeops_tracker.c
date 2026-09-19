#include "forgeops_tracker/forgeops_tracker.h"

#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>

#include "forgeops_tracker/breadcrumbs.h"
#include "forgeops_tracker/metrics.h"
#include "forgeops_tracker/performance.h"
#include "forgeops_tracker/reporter.h"
#include "forgeops_tracker/spans.h"
#include "forgeops_tracker/signal_handler.h"
#include "strbuf.h"

static forgeops_configuration_t *shared_configuration = NULL;
static int handlers_installed = 0;

typedef struct {
  char **keys;
  char **values;
  size_t count;
} forgeops_user_t;

/* See forgeops_tracker_set_user's own header comment for why this is thread-local rather than a
 * plain global. */
static _Thread_local forgeops_user_t current_user = {0};

static void free_current_user(void) {
  for (size_t i = 0; i < current_user.count; i++) {
    free(current_user.keys[i]);
    free(current_user.values[i]);
  }
  free(current_user.keys);
  free(current_user.values);
  current_user.keys = NULL;
  current_user.values = NULL;
  current_user.count = 0;
}

forgeops_configuration_t *forgeops_tracker_configuration(void) {
  if (shared_configuration == NULL) {
    shared_configuration = forgeops_configuration_create();
  }
  return shared_configuration;
}

void forgeops_tracker_install_handlers(void) {
  if (handlers_installed) return;
  handlers_installed = 1;

  forgeops_configuration_t *config = forgeops_tracker_configuration();
  forgeops_signal_handler_install(config->crash_reports_directory);
  forgeops_tracker_upload_pending_reports();
}

void forgeops_tracker_capture_error(const char *exception_class, const char *message, const char **context_keys, const char **context_values, size_t context_count, const char **user_keys, const char **user_values, size_t user_count) {
  if (user_count == 0) {
    forgeops_tracker_current_user(&user_keys, &user_values, &user_count);
  }
  size_t breadcrumb_count = 0;
  char **breadcrumbs = forgeops_breadcrumbs_snapshot(&breadcrumb_count);
  forgeops_report_error(forgeops_tracker_configuration(), exception_class, message, context_keys, context_values, context_count, user_keys, user_values, user_count, (const char **)breadcrumbs, breadcrumb_count);
  forgeops_breadcrumbs_free_snapshot(breadcrumbs, breadcrumb_count);
}

void forgeops_tracker_add_breadcrumb(const char *message, const char *category, const char *level, const char **data_keys, const char **data_values, size_t data_count) {
  forgeops_breadcrumb_add(forgeops_tracker_configuration(), message, category, level, data_keys, data_values, data_count);
}

void forgeops_tracker_clear_breadcrumbs(void) {
  forgeops_breadcrumbs_clear();
}

void forgeops_tracker_set_user(const char **user_keys, const char **user_values, size_t user_count) {
  free_current_user();
  if (user_count == 0) return;

  current_user.keys = calloc(user_count, sizeof(char *));
  current_user.values = calloc(user_count, sizeof(char *));
  if (current_user.keys == NULL || current_user.values == NULL) {
    free_current_user();
    return;
  }
  for (size_t i = 0; i < user_count; i++) {
    current_user.keys[i] = strdup(user_keys[i]);
    current_user.values[i] = strdup(user_values[i]);
  }
  current_user.count = user_count;
}

void forgeops_tracker_current_user(const char ***out_keys, const char ***out_values, size_t *out_count) {
  *out_keys = (const char **)current_user.keys;
  *out_values = (const char **)current_user.values;
  *out_count = current_user.count;
}

void forgeops_tracker_record_performance(const char *transaction_name, double duration_ms) {
  forgeops_performance_record(forgeops_tracker_configuration(), transaction_name, duration_ms);
}

static long long monotonic_now_ns(void) {
  struct timespec now;
  clock_gettime(CLOCK_MONOTONIC, &now);
  return (long long)now.tv_sec * 1000000000LL + now.tv_nsec;
}

forgeops_performance_timer_t forgeops_tracker_performance_start(const char *transaction_name) {
  forgeops_performance_timer_t timer = {transaction_name, monotonic_now_ns()};
  return timer;
}

void forgeops_tracker_performance_stop(forgeops_performance_timer_t *timer) {
  if (timer == NULL || timer->name == NULL) return;
  forgeops_tracker_record_performance(timer->name, (double)(monotonic_now_ns() - timer->started_at_ns) / 1e6);
  timer->name = NULL; /* a second stop on the same timer records nothing */
}

void forgeops_tracker_flush_performance(void) {
  forgeops_performance_flush(forgeops_tracker_configuration());
}

static long long wall_clock_ms(void) {
  struct timespec now;
  clock_gettime(CLOCK_REALTIME, &now);
  return (long long)now.tv_sec * 1000LL + now.tv_nsec / 1000000;
}

forgeops_trace_t forgeops_tracker_trace_start(void) {
  forgeops_trace_t trace = {wall_clock_ms(), monotonic_now_ns(), 0};
  trace.owns = forgeops_spans_trace_begin(forgeops_tracker_configuration());
  return trace;
}

void forgeops_tracker_trace_stop(forgeops_trace_t *trace, const char *root_name) {
  if (trace == NULL || !trace->owns) return;
  trace->owns = 0; /* a second stop on the same trace does nothing */
  forgeops_spans_trace_end(forgeops_tracker_configuration(), root_name, trace->started_at_unix_ms, (double)(monotonic_now_ns() - trace->started_at_ns) / 1e6);
}

forgeops_span_t forgeops_tracker_span_start(const char *name, const char *kind) {
  forgeops_span_t span;
  memset(&span, 0, sizeof(span));
  span.name = name;
  span.kind = kind;
  forgeops_spans_start(&span.state);
  span.state.started_at_unix_ms = wall_clock_ms();
  span.state.started_at_ns = monotonic_now_ns();
  return span;
}

void forgeops_tracker_span_stop_with_data(forgeops_span_t *span, const char **data_keys, const char **data_values, size_t data_count) {
  if (span == NULL || !span->state.active) return;
  double duration_ms = (double)(monotonic_now_ns() - span->state.started_at_ns) / 1e6;
  forgeops_spans_stop(forgeops_tracker_configuration(), &span->state, span->name != NULL ? span->name : "span", span->kind, duration_ms, data_keys, data_values, data_count);
}

void forgeops_tracker_span_stop(forgeops_span_t *span) {
  forgeops_tracker_span_stop_with_data(span, NULL, NULL, 0);
}

void forgeops_tracker_record_span(const char *name, const char *kind, long long started_at_unix_ms, double duration_ms, const char **data_keys, const char **data_values, size_t data_count) {
  forgeops_spans_record(forgeops_tracker_configuration(), name != NULL ? name : "span", kind, started_at_unix_ms, duration_ms, data_keys, data_values, data_count);
}

/* Appends `value` as a JSON string literal (quotes, backslashes and control characters escaped). */
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

void forgeops_tracker_capture_metric(const char *name, double value) {
  forgeops_configuration_t *config = forgeops_tracker_configuration();
  if (name == NULL || !forgeops_configuration_is_enabled(config) || !isfinite(value)) return;

  forgeops_strbuf_t fields;
  if (forgeops_strbuf_init(&fields, 256) != 0) return;
  char number[64];
  snprintf(number, sizeof(number), "%.17g", value);
  forgeops_strbuf_append_str(&fields, "\"metric_name\":");
  append_json_string(&fields, name);
  forgeops_strbuf_append_str(&fields, ",\"value\":");
  forgeops_strbuf_append_str(&fields, number);
  forgeops_strbuf_append_str(&fields, ",\"environment\":");
  append_json_string(&fields, config->environment != NULL ? config->environment : "");
  forgeops_strbuf_append_str(&fields, ",\"release\":");
  if (config->release != NULL) {
    append_json_string(&fields, config->release);
  } else {
    forgeops_strbuf_append_str(&fields, "null");
  }
  forgeops_metrics_record(config, FORGEOPS_METRIC_CUSTOM, value, fields.data);
  free(fields.data);
}

void forgeops_tracker_capture_infrastructure_metric(const char *name, double value, const char *hostname) {
  forgeops_configuration_t *config = forgeops_tracker_configuration();
  if (name == NULL || !forgeops_configuration_is_enabled(config) || !isfinite(value)) return;

  forgeops_strbuf_t fields;
  if (forgeops_strbuf_init(&fields, 256) != 0) return;
  char number[64];
  snprintf(number, sizeof(number), "%.17g", value);
  forgeops_strbuf_append_str(&fields, "\"metric_name\":");
  append_json_string(&fields, name);
  forgeops_strbuf_append_str(&fields, ",\"value\":");
  forgeops_strbuf_append_str(&fields, number);
  forgeops_strbuf_append_str(&fields, ",\"hostname\":");
  append_json_string(&fields, hostname != NULL ? hostname : (config->server_name != NULL ? config->server_name : ""));
  forgeops_metrics_record(config, FORGEOPS_METRIC_INFRASTRUCTURE, value, fields.data);
  free(fields.data);
}

void forgeops_tracker_flush_metrics(void) {
  forgeops_configuration_t *config = forgeops_tracker_configuration();
  forgeops_metrics_flush(config, FORGEOPS_METRIC_CUSTOM);
  forgeops_metrics_flush(config, FORGEOPS_METRIC_INFRASTRUCTURE);
}

void forgeops_tracker_upload_pending_reports(void) {
  forgeops_upload_pending_reports(forgeops_tracker_configuration());
}

void forgeops_tracker_reset_for_testing(void) {
  forgeops_metrics_reset_for_testing(); /* before the configuration is destroyed: the flush threads read it */
  forgeops_spans_reset_for_testing(); /* before the configuration is destroyed: the delivery thread reads it */
  forgeops_performance_reset_for_testing(); /* before the configuration is destroyed: the flush thread reads it */
  forgeops_configuration_destroy(shared_configuration);
  shared_configuration = NULL;
  handlers_installed = 0;
  free_current_user();
  forgeops_breadcrumbs_reset_for_testing();
  /* Deliberately not touching the real signal dispositions here: resetting those between test
   * runs would risk leaving the *test process itself* without a safety net if a later, unrelated
   * test genuinely crashes. Same reasoning as this repo's own Objective-C/Swift clients' own
   * _resetForTesting. */
}
