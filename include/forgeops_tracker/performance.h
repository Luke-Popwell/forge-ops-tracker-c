#ifndef FORGEOPS_TRACKER_PERFORMANCE_H
#define FORGEOPS_TRACKER_PERFORMANCE_H

#include "forgeops_tracker/configuration.h"

/*
 * Times work in-process, bucketed by transaction name, and periodically flushes each distinct
 * bucket as one small aggregate report, rather than one network call per timed call. Internal: the
 * public API is in forgeops_tracker.h. Ported from gems/forge_ops_tracker's performance_flusher.rb
 * and sdks/go's own port of it, including the one thing both of those learned the hard way: see
 * forgeops_performance_flush's own comment on why it subtracts what it delivered instead of
 * clearing the buckets.
 *
 * Unlike the rest of this client, which never starts a thread of its own (a crash report is written
 * now and uploaded by an explicit call, see forgeops_tracker.h), this one does: a periodic flush
 * has no call site to piggyback on. One joinable pthread, started lazily on the first recorded
 * duration, sleeping on a condition variable between flushes (so it can be stopped promptly), plus
 * an atexit hook that flushes the last partial window on a normal exit. That thread and the
 * flush both block on libcurl, never the caller of record.
 *
 * Every distinct transaction name is its own bucket, kept in a plain array with a linear lookup: the
 * documented use is a handful of low-cardinality names ("GET /users/:id"), not thousands. Capped at
 * FORGEOPS_PERFORMANCE_MAX_TRANSACTIONS so a name accidentally built from an id can't grow this
 * process without bound: past the cap, a new name is dropped, an existing one keeps counting.
 */
#define FORGEOPS_PERFORMANCE_MAX_TRANSACTIONS 500

/* Does nothing when config->track_performance is 0 or reporting isn't enabled for this environment. */
void forgeops_performance_record(const forgeops_configuration_t *config, const char *transaction_name, double duration_ms);

/*
 * Snapshots the buffered buckets and delivers them as one batch. A failed delivery keeps every
 * bucket where it is, so the next flush's batch just grows instead of losing what was already
 * tallied: there's no other copy of this data anywhere.
 *
 * Only exactly what this snapshot delivered is removed afterward, subtracted from whatever is in
 * each bucket by then, never the whole set cleared outright. forgeops_performance_record can run on
 * another thread while delivery is in flight (the lock is deliberately released around the network
 * call), so a record for a transaction already in the snapshot, or a brand-new one, can land in the
 * exact window between the snapshot and delivery succeeding. Clearing afterward, as if delivery
 * had covered everything now in the set, would silently discard that data forever. This is a real
 * bug sdks/go had and fixed, and that gems/forge_ops_tracker's reference implementation still has;
 * see this SDK's own test for a deterministic reproduction.
 */
void forgeops_performance_flush(const forgeops_configuration_t *config);

/*
 * Not part of the public API: called between the snapshot and the delivery inside
 * forgeops_performance_flush, with no lock held, so a test can record "concurrently" at exactly
 * the moment the race window is open without needing a second thread. NULL clears it.
 */
void forgeops_performance_set_before_delivery_hook_for_testing(void (*hook)(void));

/*
 * Not part of the public API: current (count, duration sum, max) for one transaction. Returns 0 if
 * there is no bucket by that name.
 */
int forgeops_performance_tally_for_testing(const char *transaction_name, unsigned long *count, double *duration_sum_ms, double *max_duration_ms);

/* Not part of the public API: stops and joins the flush thread (if one was started) and empties every bucket. */
void forgeops_performance_reset_for_testing(void);

#endif
