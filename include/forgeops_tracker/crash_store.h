#ifndef FORGEOPS_TRACKER_CRASH_STORE_H
#define FORGEOPS_TRACKER_CRASH_STORE_H

#include "forgeops_tracker/configuration.h"

/*
 * Persists already-built JSON event payloads to disk under
 * config->crash_reports_directory and reads them back -- this SDK's "queue," in the sense every
 * other SDK's DeliveryQueue is its own queue, except this one survives the process dying (which,
 * for a crash reporter, is the one guarantee that actually matters). Mirrors this repo's own
 * Objective-C/Swift clients' own CrashStore -- see their own class comments for the full
 * rationale.
 *
 * Unlike those two, this stores the payload as plain pre-built JSON text (forgeops_build_event_json
 * already returns exactly that), not a re-parseable structured value -- there is no JSON parser
 * anywhere in this client, only an encoder, since nothing here ever needs to read a payload back
 * as anything other than the raw bytes to POST.
 */

/* Writes json_payload to a new file, named by a timestamp + a small counter so concurrent writes
 * (unlikely, but not impossible) never collide. Returns 0 on success, -1 on any failure -- never
 * crashes the host app over a write failure. */
int forgeops_crash_store_write(const forgeops_configuration_t *config, const char *json_payload);

/*
 * Lists every pending payload's path, oldest first, as a NULL-terminated array of newly-allocated
 * strings the caller must free (each string, then the array itself via
 * forgeops_crash_store_free_paths) -- or NULL if the directory doesn't exist or is empty.
 */
char **forgeops_crash_store_pending_paths(const forgeops_configuration_t *config);

void forgeops_crash_store_free_paths(char **paths);

/* Reads path's full contents as a newly-allocated string the caller must free, or NULL on any
 * failure. */
char *forgeops_crash_store_read(const char *path);

void forgeops_crash_store_delete(const char *path);

#endif
