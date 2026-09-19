#ifndef FORGEOPS_TRACKER_BREADCRUMBS_H
#define FORGEOPS_TRACKER_BREADCRUMBS_H

#include <stddef.h>

#include "forgeops_tracker/configuration.h"

/*
 * The per-thread breadcrumb trail forgeops_tracker_add_breadcrumb appends to. Internal: the public
 * API is in forgeops_tracker.h.
 *
 * Each entry is stored already fully encoded as one JSON object, in a fixed-size slot of a
 * heap-allocated ring owned by the calling thread (a pointer to it lives in a C11 _Thread_local,
 * the same isolation choice forgeops_tracker_set_user makes and for the same reason). That shape is
 * what makes the one thing here with no counterpart in the higher-level clients possible: a fatal
 * signal is this SDK's only automatic capture path, its handler runs on the crashing thread, and it
 * can only call async-signal-safe functions, so it can't build anything, but it *can* walk
 * pre-encoded bytes with plain reads and write() them out. So the handler dumps this thread's
 * trail straight into the raw crash report (see forgeops_breadcrumbs_write_raw_to_fd), and the
 * next launch's forgeops_signal_handler_complete_json turns that into a "breadcrumbs" array. No
 * persistence file is needed (unlike this repo's Objective-C/Swift clients, where the report is
 * uploaded by a different process and a handler can't read Foundation state at all).
 *
 * Message and data values are PII-scrubbed at add time, not report time, for the same reason:
 * the raw report can't be scrubbed later. Category, level, and timestamp never are.
 */

/* Per-entry slot size, including the terminating NUL. An entry that would encode larger than this
 * has data pairs dropped, then its message shortened, until it fits. */
#define FORGEOPS_BREADCRUMB_SLOT_SIZE 1024

/* Hard ceiling on how many entries a thread's ring can hold, whatever max_breadcrumbs says: the
 * ring is allocated once, at that thread's first breadcrumb, at min(max_breadcrumbs, this). */
#define FORGEOPS_BREADCRUMB_RING_LIMIT 100

/* category/level may be NULL: "custom"/"info". data_keys/data_values/data_count: same
 * parallel-arrays shape as context (NULL/0 for none). Does nothing when config->track_breadcrumbs
 * is 0. */
void forgeops_breadcrumb_add(const forgeops_configuration_t *config, const char *message, const char *category, const char *level, const char **data_keys, const char **data_values, size_t data_count);

/* Empties this thread's trail. */
void forgeops_breadcrumbs_clear(void);

/*
 * A copy of this thread's trail, oldest first: a newly-allocated array of newly-allocated JSON
 * object strings, or NULL with *out_count 0 when empty. Free with
 * forgeops_breadcrumbs_free_snapshot.
 */
char **forgeops_breadcrumbs_snapshot(size_t *out_count);
void forgeops_breadcrumbs_free_snapshot(char **json_objects, size_t count);

/*
 * Writes this thread's trail to fd, one "#breadcrumb <json>\n" line per entry, oldest first.
 * Async-signal-safe: only write() and strlen(), never allocating. Called from the fatal-signal
 * handler.
 */
void forgeops_breadcrumbs_write_raw_to_fd(int fd);

/* Not part of the public API: clears this thread's trail and frees its ring. */
void forgeops_breadcrumbs_reset_for_testing(void);

#endif
