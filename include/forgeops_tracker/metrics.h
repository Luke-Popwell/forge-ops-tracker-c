#ifndef FORGEOPS_TRACKER_METRICS_H
#define FORGEOPS_TRACKER_METRICS_H

#include <stddef.h>

#include "forgeops_tracker/configuration.h"

/*
 * Collects individual forgeops_tracker_capture_metric / forgeops_tracker_capture_infrastructure_metric
 * calls in-process and periodically flushes them as one batch, rather than one network call per
 * capture. Internal: the public API is in forgeops_tracker.h. Unlike performance.h this keeps a list of
 * individually meaningful entries instead of summing them into buckets: a customer's own signup or
 * payment is exactly the kind of thing they will want a genuinely accurate count/sum of later, so the
 * server stores one row per entry as-is. Ported from gems/forge_ops_tracker's metric_buffer.rb and
 * infrastructure_metric_buffer.rb, which are the same class twice; here it is one module with two
 * independent buffers, selected by a forgeops_metric_kind_t.
 *
 * Three deliberate differences from the Ruby buffers:
 *
 *  - A flush snapshots the first N entries and, on success, removes exactly those N, instead of
 *    resetting the whole list, so an entry recorded while the request is in flight (the lock is
 *    released around the network call) is kept for the next flush rather than lost.
 *  - A buffer is capped at FORGEOPS_METRICS_MAX_ENTRIES, and once full further entries are dropped
 *    until a flush succeeds: a plan without the feature answers 403 on every flush, and an uncapped
 *    buffer would then grow for as long as the process lives. Dropping the newest rather than the
 *    oldest keeps the entries a flush is delivering at the front of the array, which is what makes
 *    removing exactly them afterward exact.
 *  - A NaN or infinite value is dropped at record time: printf would write "nan"/"inf", which is not
 *    valid JSON, and one bad entry would make the server reject the whole batch behind it.
 *
 * Each entry is stored already encoded as one JSON object, so a flush only has to join them. Like the
 * performance flusher, one joinable pthread per buffer is started lazily on the first capture, and an
 * atexit hook flushes what is left on a normal exit (which is what a short-lived cron program that
 * captures a few readings and returns from main relies on).
 */
#define FORGEOPS_METRICS_MAX_ENTRIES 1000

typedef enum { FORGEOPS_METRIC_CUSTOM = 0, FORGEOPS_METRIC_INFRASTRUCTURE = 1 } forgeops_metric_kind_t;

/*
 * Adds one entry. `fields_json` is the already-encoded body of the object without its braces (for
 * example "\"metric_name\":\"signup\",\"value\":1"); recorded_at is appended here. Returns 1 if kept,
 * 0 if dropped (non-finite value, or the buffer is full).
 */
int forgeops_metrics_record(const forgeops_configuration_t *config, forgeops_metric_kind_t kind, double value, const char *fields_json);

/* Delivers everything buffered for `kind` as one batch. A failed delivery keeps every entry. */
void forgeops_metrics_flush(const forgeops_configuration_t *config, forgeops_metric_kind_t kind);

/*
 * Not part of the public API: called between the snapshot and the delivery inside
 * forgeops_metrics_flush, with no lock held, so a test can record "concurrently" at exactly the moment
 * the race window is open without a second thread. NULL clears it.
 */
void forgeops_metrics_set_before_delivery_hook_for_testing(void (*hook)(void));

/* Not part of the public API: how many entries `kind` currently holds. */
size_t forgeops_metrics_count_for_testing(forgeops_metric_kind_t kind);

/* Not part of the public API: stops and joins both flush threads and discards every entry. */
void forgeops_metrics_reset_for_testing(void);

#endif
