#ifndef FORGEOPS_TRACKER_H
#define FORGEOPS_TRACKER_H

#include <stddef.h>

#include "forgeops_tracker/configuration.h"
#include "forgeops_tracker/metrics.h"
#include "forgeops_tracker/spans.h"

/*
 * Public entry point. Typical usage, as early as possible in main():
 *
 *     forgeops_configuration_t *config = forgeops_tracker_configuration();
 *     forgeops_configuration_set_dsn(config, "https://<api_key>@getforgeops.net/api/v1/events");
 *     forgeops_tracker_install_handlers();
 *
 * There's no configure-block style API here the way the higher-level clients in this repo have:
 * plain C has no closures to pass one as, so forgeops_tracker_configuration() just hands back the
 * shared Configuration struct directly for you to set fields on (config->environment = "production";
 * or via forgeops_configuration_set_dsn for the one field that needs to invalidate cached parsing).
 *
 * See README.md for what forgeops_tracker_install_handlers actually covers (an uncaught fatal
 * signal, the only "automatic capture" story that exists for plain C: there's no equivalent to
 * an uncaught-exception hook, because C has no exceptions at all) and why a crash report always
 * uploads on the *next* call to forgeops_tracker_upload_pending_reports (typically your own next
 * startup) rather than live during the crash itself.
 */

forgeops_configuration_t *forgeops_tracker_configuration(void);

/*
 * Installs the fatal-signal handlers, then uploads any reports left over from a previous crash or
 * process run. Call once, after configuring. Safe to call more than once: later calls are a
 * no-op.
 */
void forgeops_tracker_install_handlers(void);

/*
 * Report an error you've already detected explicitly, e.g. from your own error-handling code.
 * user_keys/user_values/user_count: the affected user to attach, following the same
 * parallel-arrays shape as context_keys/context_values/context_count. Pass user_count 0 (with
 * user_keys/user_values either NULL or ignored) to fall back to whatever
 * forgeops_tracker_set_user last established on this thread, if anything; pass a non-zero count
 * to override that for this one report.
 */
void forgeops_tracker_capture_error(const char *exception_class, const char *message, const char **context_keys, const char **context_values, size_t context_count, const char **user_keys, const char **user_values, size_t user_count);

/*
 * The same as forgeops_tracker_capture_error, for an error caused by a database call: pass the
 * SQL that ran. C has no exception type that could carry it, and no C database library puts it
 * anywhere this SDK could find, so the code that ran the query hands it over.
 *
 * With capture_sql_objects on (the default), the names of the stored procedure, table and view the
 * statement touched are sent, so an issue says where to start looking. With capture_sql_statement
 * on too (off by default), the statement itself is sent as well, with every string and number
 * replaced by "?" first. The raw statement never leaves this process either way.
 */
void forgeops_tracker_capture_error_with_sql(const char *exception_class, const char *message, const char *sql, const char **context_keys, const char **context_values, size_t context_count, const char **user_keys, const char **user_values, size_t user_count);

/*
 * Manually attaches an affected user to whatever gets reported from here on, *on this thread* (an
 * explicit forgeops_tracker_capture_error call with user_count 0, or a fatal signal, filled in at
 * upload time): there's no way to automatically detect "the current user" in plain C, so call
 * this yourself, e.g. right after authenticating a request. A plain C11 _Thread_local, not a
 * process-wide global: the right choice for a server handling more than one request at a time,
 * each on its own thread, the same reasoning gems/forge_ops_tracker documents for its own
 * Thread.current use; a single-threaded program just has the one thread's worth of state, so this
 * still behaves like a plain global there. Copies (strdup's) every key/value pair given, and
 * frees whatever was set before: the caller retains ownership of user_keys/user_values, and may
 * free or reuse them immediately after this call returns. Pass user_count 0 to clear whatever was
 * set, e.g. once a request finishes or on sign-out.
 */
void forgeops_tracker_set_user(const char **user_keys, const char **user_values, size_t user_count);

/*
 * Records one breadcrumb: an entry in a small, bounded trail of recent events attached to whatever
 * gets reported next *on this thread* (a forgeops_tracker_capture_error call, or a fatal signal),
 * so an issue's detail page can show what led up to it. category/level may be NULL, meaning
 * "custom"/"info"; data_keys/data_values/data_count follow the same parallel-arrays shape as
 * context (NULL/0 for none). Only the config's max_breadcrumbs (30) most recent are kept per
 * thread, oldest dropped first; does nothing when config->track_breadcrumbs is 0. message and data
 * values are PII-scrubbed here, when added, not when reported (see breadcrumbs.h for why); every
 * string is copied, so the caller keeps ownership of everything it passes.
 *
 * Nothing records one automatically: this client has no framework integration to time a request
 * from, so every breadcrumb here is one you add by hand. A plain per-thread trail, the same
 * isolation choice forgeops_tracker_set_user makes: a thread that serves more than one unit of work
 * in a row (a thread pool worker, say) must call forgeops_tracker_clear_breadcrumbs itself at the
 * start of each one, or the previous one's trail carries over. A fatal signal keeps this thread's
 * trail too: the handler dumps it into the crash report directly (see breadcrumbs.h).
 */
void forgeops_tracker_add_breadcrumb(const char *message, const char *category, const char *level, const char **data_keys, const char **data_values, size_t data_count);

/* Empties this thread's breadcrumb trail: see forgeops_tracker_add_breadcrumb for when to call it. */
void forgeops_tracker_clear_breadcrumbs(void);

/*
 * Times work in-process and reports one small aggregate per transaction name (how many times it ran,
 * total and maximum duration) every config->performance_flush_interval_seconds (60 by default), for
 * the Performance page's per-transaction table, not one network call per timed call.
 * forgeops_tracker_record_performance records a duration you measured yourself, in milliseconds; a
 * no-op when config->track_performance is 0 or reporting isn't enabled for this environment.
 *
 * This client has no web framework integration, so nothing is timed automatically: wrap whatever you
 * want on the Performance page yourself, e.g. a request handler. Plain C has no closures to pass a
 * block to time, so the timer helpers below bracket it instead:
 *
 *     forgeops_performance_timer_t timer = forgeops_tracker_performance_start("GET /users/:id");
 *     handle_request(request);
 *     forgeops_tracker_performance_stop(&timer);
 *
 * Keep transaction_name low-cardinality ("GET /users/:id", not "GET /users/42"): every distinct name
 * is its own row (and at most FORGEOPS_PERFORMANCE_MAX_TRANSACTIONS are kept per process). The name
 * is copied when recorded, but forgeops_tracker_performance_start only keeps the pointer until the
 * matching stop: pass a string that outlives the call, typically a literal.
 *
 * Unlike the rest of this client, this starts one background pthread (on the first recorded
 * duration) that flushes on the interval, and registers an atexit hook that flushes the last partial
 * window on a normal exit; both block on libcurl, never the caller of a record/stop call. A process
 * that exits some other way (a fatal signal, _exit) loses the last window, the same as anything
 * queued in memory.
 */
typedef struct {
  const char *name;
  long long started_at_ns; /* CLOCK_MONOTONIC */
} forgeops_performance_timer_t;

void forgeops_tracker_record_performance(const char *transaction_name, double duration_ms);
forgeops_performance_timer_t forgeops_tracker_performance_start(const char *transaction_name);
void forgeops_tracker_performance_stop(forgeops_performance_timer_t *timer);

/*
 * Delivers whatever has been tallied so far right now, instead of waiting for the next interval.
 * Synchronous: blocks on libcurl for up to config->timeout_seconds.
 */
void forgeops_tracker_flush_performance(void);

/*
 * Distributed tracing: one request's or job's own call tree, sent to ForgeOps only when the whole
 * thing took at least config->trace_capture_threshold_ms (1000 by default), so fast calls cost
 * nothing on the wire. Bracket the unit of work with trace_start/trace_stop, and anything inside it,
 * on the same thread, can add spans; a span nests under whichever span is open. Traces are per
 * service: nothing is propagated across services.
 *
 *     forgeops_trace_t trace = forgeops_tracker_trace_start();
 *     forgeops_span_t span = forgeops_tracker_span_start("charge card", "service");
 *     charge(order);
 *     forgeops_tracker_span_stop(&span);
 *     forgeops_tracker_trace_stop(&trace, "GET /checkout");
 *
 * kind is one of controller, service, database, redis, http, job, other (NULL or anything else is
 * sent as "other", since the server rejects a whole trace over one unknown kind). Names are copied;
 * data is optional parallel key/value arrays (NULL/0 for none). A trace holds at most
 * FORGEOPS_SPANS_MAX_SPANS spans. Outside a trace every call here is a harmless no-op, as is
 * everything when config->track_tracing is 0 or reporting isn't enabled for this environment.
 *
 * This client has no web framework integration, so nothing starts a trace or records a span
 * automatically: you bracket what you want traced. A trace_start inside an open trace does not start
 * a second one, and its matching trace_stop does nothing. The trace lives in a _Thread_local, like
 * the breadcrumb trail: always call trace_stop on the thread that called trace_start, or the open
 * trace leaks with the thread.
 *
 * Like the performance flusher, delivery runs on one background pthread (started on the first
 * finished slow trace) fed by a bounded queue, plus an atexit hook that drains what is left on a
 * normal exit; a full queue drops the trace rather than blocking the caller.
 */
typedef struct {
  long long started_at_unix_ms;
  long long started_at_ns; /* CLOCK_MONOTONIC */
  int owns; /* 1 if this call started the trace and trace_stop should finish it */
} forgeops_trace_t;

typedef struct {
  const char *name;
  const char *kind;
  forgeops_span_state_t state;
} forgeops_span_t;

forgeops_trace_t forgeops_tracker_trace_start(void);
void forgeops_tracker_trace_stop(forgeops_trace_t *trace, const char *root_name);
forgeops_span_t forgeops_tracker_span_start(const char *name, const char *kind);
void forgeops_tracker_span_stop(forgeops_span_t *span);
void forgeops_tracker_span_stop_with_data(forgeops_span_t *span, const char **data_keys, const char **data_values, size_t data_count);

/* Records a span you timed yourself under the current one. started_at_unix_ms is wall-clock milliseconds since the epoch. */
void forgeops_tracker_record_span(const char *name, const char *kind, long long started_at_unix_ms, double duration_ms, const char **data_keys, const char **data_values, size_t data_count);

/*
 * Custom metrics and infrastructure monitoring: two explicit calls (nothing is automatic, so there is no
 * track_metrics flag). forgeops_tracker_capture_metric records a named business event (a signup, a
 * payment, anything you want to name): pass 1.0 for a bare counter or a real magnitude, and it may be
 * negative (a refund). forgeops_tracker_capture_infrastructure_metric records one reading (cpu, memory,
 * disk, anything else a script of yours reads) from one of your own hosts; hostname NULL means
 * config->server_name, so a script on the box it reports about needs none. Both are buffered and flushed
 * as one batch every config->metric_flush_interval_seconds / infrastructure_metric_flush_interval_seconds
 * (60) on a background pthread started at the first capture, and flushed once more by an atexit hook on
 * a normal exit, which is what a short-lived cron program that captures a few readings and returns from
 * main relies on; call forgeops_tracker_flush_metrics if it might exit another way (_exit, a signal).
 * Every entry is stored as captured (a signup is a row, not a running total), so a count or sum computed
 * later is exact. Both are a no-op when reporting isn't enabled for this environment, and a NaN or
 * infinite value is dropped. Names are copied. A buffer holds at most FORGEOPS_METRICS_MAX_ENTRIES
 * entries and drops further ones until a flush succeeds. A failed delivery keeps every entry, and one
 * captured while a delivery is in flight is kept too.
 */
void forgeops_tracker_capture_metric(const char *name, double value);
void forgeops_tracker_capture_infrastructure_metric(const char *name, double value, const char *hostname);

/* Delivers every buffered metric and infrastructure reading right now. Synchronous: blocks on libcurl for up to config->timeout_seconds. */
void forgeops_tracker_flush_metrics(void);

/* Uploads every pending report (from a past crash, or a past forgeops_tracker_capture_error call
 * whose upload hasn't happened yet). Synchronous: call it from your own background thread if
 * you don't want it blocking the caller. forgeops_tracker_install_handlers already calls this
 * once; call it again yourself whenever else makes sense for your app (periodically, or right
 * after a forgeops_tracker_capture_error call, since that case (unlike a crash) didn't just
 * terminate the process and has no particular reason to wait for the next launch). */
void forgeops_tracker_upload_pending_reports(void);

/* @internal not part of the public API: used by signal_handler.c's own upload-time completion to
 * fill in whatever user forgeops_tracker_set_user last established on this thread (a signal
 * handler itself can never safely read this: see signal_handler.h's own comment on what's safe to
 * touch there). The two out-parameter arrays point directly into this thread's own current-user
 * storage; valid only until the next forgeops_tracker_set_user/forgeops_tracker_reset_for_testing
 * call on this same thread, and must not be freed by the caller. */
void forgeops_tracker_current_user(const char ***out_keys, const char ***out_values, size_t *out_count);

/* Not part of the public API: resets module state between test cases. */
void forgeops_tracker_reset_for_testing(void);

#endif
