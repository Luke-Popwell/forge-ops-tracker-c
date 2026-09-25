#ifndef FORGEOPS_TRACKER_CHANGES_H
#define FORGEOPS_TRACKER_CHANGES_H

#include <stddef.h>

#include "forgeops_tracker/configuration.h"

/*
 * Builds one recorded change (see forgeops_tracker_record_change) and hands it to a background
 * delivery thread for the DSN's /changes endpoint. Internal: the public API is in forgeops_tracker.h.
 *
 * Kinds are the closed set the changes API accepts (feature_flag, config, migration, dependency,
 * infrastructure, other): anything else is sent as "other", since the server rejects an unknown kind
 * outright. The title is cut to FORGEOPS_CHANGES_MAX_TITLE_CHARS characters (never through the middle
 * of a multibyte UTF-8 character), the server's own limit.
 *
 * Delivery is the same shape as the span queue's: one joinable pthread started lazily on the first
 * recorded change, fed by a bounded queue, blocking on libcurl, never the caller. A full queue drops
 * the change rather than blocking; a failed delivery (a 403 on a plan without change tracking
 * included) is dropped quietly, never retried. An atexit hook drains what is still queued on a
 * normal exit; a process that exits some other way loses it.
 */
#define FORGEOPS_CHANGES_QUEUE_LIMIT 100
#define FORGEOPS_CHANGES_MAX_TITLE_CHARS 200

/* The optional parts of a change, for forgeops_tracker_record_change_with_options. */
typedef struct {
  const char *environment; /* NULL means config->environment */
  const char *service;
  const char *actor;
  const char *url;
  const char *id; /* your own idempotency key: a retried call with the same id records the change once */
  long long occurred_at_unix_ms; /* wall-clock milliseconds since the epoch; 0 means now */
} forgeops_change_options_t;

/*
 * Builds the JSON body for one change, or NULL when title is NULL or blank. Newly allocated; the
 * caller frees it. Exposed (not static) so tests can check the wire shape without a server.
 */
char *forgeops_changes_build(const forgeops_configuration_t *config, const char *kind, const char *title, const char **details_keys, const char **details_values, size_t details_count, const forgeops_change_options_t *options);

/* Takes ownership of body and queues it for delivery. Returns 1 if queued, 0 if dropped (queue full). */
int forgeops_changes_enqueue(const forgeops_configuration_t *config, char *body);

/* Not part of the public API: stops and joins the delivery thread and discards anything queued. */
void forgeops_changes_reset_for_testing(void);

#endif
