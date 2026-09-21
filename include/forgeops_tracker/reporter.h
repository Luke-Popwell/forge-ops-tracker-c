#ifndef FORGEOPS_TRACKER_REPORTER_H
#define FORGEOPS_TRACKER_REPORTER_H

#include <stddef.h>

#include "forgeops_tracker/configuration.h"

/*
 * Ties Configuration, the event builder, and the crash store together. Mirrors every other SDK's
 * own Reporter/ErrorSubscriber in spirit: split into two halves (capture now, upload later)
 * rather than one call, because a crash reporter's two real responsibilities happen at two
 * different, unrelated moments: the crash/error itself (capture, write to disk, nothing else,
 * no live network call, see event_builder.h's own comment for why), and whenever the host app
 * next calls forgeops_upload_pending_reports (typically at the next startup, same as this repo's
 * own Objective-C/Swift clients).
 */

/* Builds and writes an event to the crash store: does nothing if the configuration is disabled
 * (no DSN, wrong environment). Never fails loudly: any internal error is silently dropped, the
 * same "an error reporter must never itself crash the host app" guarantee every client in this
 * repo makes. user_keys/user_values/user_count: see forgeops_build_event_json's own comment;
 * passed straight through with no ambient-user resolution of its own, that's forgeops_tracker.c's
 * job. breadcrumb_json/breadcrumb_count: see forgeops_build_event_json's own comment; passed
 * straight through the same way. */
void forgeops_report_error(const forgeops_configuration_t *config, const char *exception_class, const char *message, const char **context_keys, const char **context_values, size_t context_count, const char **user_keys, const char **user_values, size_t user_count, const char **breadcrumb_json, size_t breadcrumb_count);

/* The same as forgeops_report_error, plus the raw SQL statement behind the error (NULL when there
 * isn't one): see forgeops_build_event_json_with_sql. */
void forgeops_report_error_with_sql(const forgeops_configuration_t *config, const char *exception_class, const char *message, const char **context_keys, const char **context_values, size_t context_count, const char **user_keys, const char **user_values, size_t user_count, const char **breadcrumb_json, size_t breadcrumb_count, const char *sql);

/*
 * Uploads every pending report left over from a previous call (or previous process launch),
 * deleting each on success and leaving a failed one in place for the next attempt. Synchronous:
 * call this from your own background thread if you don't want it blocking the caller.
 */
void forgeops_upload_pending_reports(const forgeops_configuration_t *config);

#endif
