#ifndef FORGEOPS_TRACKER_SPANS_H
#define FORGEOPS_TRACKER_SPANS_H

#include <stddef.h>

#include "forgeops_tracker/configuration.h"

/*
 * One thread's trace: a tree of timed spans (a request's or job's own call tree) that is sent to
 * ForgeOps only when its root took at least config->trace_capture_threshold_ms. Internal: the
 * public API is in forgeops_tracker.h.
 *
 * The open trace lives in a C11 _Thread_local, the same isolation choice the breadcrumb trail and
 * forgeops_tracker_set_user make. Each finished span is appended, already encoded as one JSON
 * object, to a growing buffer; nesting comes from a stack of open span ids (FORGEOPS_SPANS_MAX_DEPTH
 * deep: a span opened deeper than that nests under the deepest one tracked), and a trace holds at
 * most FORGEOPS_SPANS_MAX_SPANS spans including the root. Kinds are the closed set the ingestion API
 * accepts (controller, service, database, redis, http, job, other): anything else is sent as
 * "other", since one bad kind would make the server reject the whole trace.
 *
 * A finished trace is handed to a background delivery thread through a bounded queue, the same
 * shape as the performance flusher's thread: one joinable pthread started lazily on the first
 * finished slow trace, blocking on libcurl, never the caller. An atexit hook drains what is still
 * queued on a normal exit; a process that exits some other way loses it.
 */
#define FORGEOPS_SPANS_MAX_SPANS 500
#define FORGEOPS_SPANS_MAX_DEPTH 64
#define FORGEOPS_SPANS_QUEUE_LIMIT 100
#define FORGEOPS_SPAN_ID_LENGTH 16

/* Open state for one span: see forgeops_tracker_span_start. */
typedef struct {
  char id[FORGEOPS_SPAN_ID_LENGTH + 1];
  char parent[FORGEOPS_SPAN_ID_LENGTH + 1];
  long long started_at_unix_ms;
  long long started_at_ns; /* CLOCK_MONOTONIC */
  int active;
} forgeops_span_state_t;

/*
 * Starts a trace on the calling thread. Returns 1 if this call started it (the caller owns the root
 * and should end it), 0 if a trace is already open here, or if tracing is off or reporting isn't
 * enabled (nothing is recorded then, but every later call still works as a harmless no-op).
 */
int forgeops_spans_trace_begin(const forgeops_configuration_t *config);

/* Ends the calling thread's trace, always clearing it, and queues it when the root took long enough. */
void forgeops_spans_trace_end(const forgeops_configuration_t *config, const char *root_name, long long started_at_unix_ms, double duration_ms);

/* Opens a span under whatever is open (or the root); state->active is 0 outside a trace. */
void forgeops_spans_start(forgeops_span_state_t *state);

/* Closes a span opened with forgeops_spans_start and records it. */
void forgeops_spans_stop(const forgeops_configuration_t *config, forgeops_span_state_t *state, const char *name, const char *kind, double duration_ms, const char **data_keys, const char **data_values, size_t data_count);

/* Records an already-finished span under whatever is currently open; a no-op outside a trace. */
void forgeops_spans_record(const forgeops_configuration_t *config, const char *name, const char *kind, long long started_at_unix_ms, double duration_ms, const char **data_keys, const char **data_values, size_t data_count);

/* Not part of the public API: 1 if the calling thread has an open trace. */
int forgeops_spans_active_for_testing(void);

/* Not part of the public API: how many spans (not counting the root) the calling thread's open trace holds, or -1 with none. */
int forgeops_spans_count_for_testing(void);

/* Not part of the public API: 1 once a finished trace has started the delivery thread. */
int forgeops_spans_worker_started_for_testing(void);

/* Not part of the public API: drops the calling thread's trace, then stops and joins the delivery thread and discards its queue. */
void forgeops_spans_reset_for_testing(void);

#endif
