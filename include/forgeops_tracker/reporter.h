#ifndef FORGEOPS_TRACKER_REPORTER_H
#define FORGEOPS_TRACKER_REPORTER_H

#include <stddef.h>

#include "forgeops_tracker/configuration.h"

/*
 * Ties Configuration, the event builder, and the crash store together. Mirrors every other SDK's
 * own Reporter/ErrorSubscriber in spirit -- split into two halves (capture now, upload later)
 * rather than one call, because a crash reporter's two real responsibilities happen at two
 * different, unrelated moments: the crash/error itself (capture, write to disk, nothing else --
 * no live network call, see event_builder.h's own comment for why), and whenever the host app
 * next calls forgeops_upload_pending_reports (typically at the next startup, same as this repo's
 * own Objective-C/Swift clients).
 */

/* Builds and writes an event to the crash store -- does nothing if the configuration is disabled
 * (no DSN, wrong environment). Never fails loudly: any internal error is silently dropped, the
 * same "an error reporter must never itself crash the host app" guarantee every client in this
 * repo makes. */
void forgeops_report_error(const forgeops_configuration_t *config, const char *exception_class, const char *message, const char **context_keys, const char **context_values, size_t context_count);

/*
 * Uploads every pending report left over from a previous call (or previous process launch),
 * deleting each on success and leaving a failed one in place for the next attempt. Synchronous --
 * call this from your own background thread if you don't want it blocking the caller.
 */
void forgeops_upload_pending_reports(const forgeops_configuration_t *config);

#endif
