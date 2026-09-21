#ifndef FORGEOPS_TRACKER_EVENT_BUILDER_H
#define FORGEOPS_TRACKER_EVENT_BUILDER_H

#include <stddef.h>

#include "forgeops_tracker/configuration.h"

/*
 * Builds the JSON payload the ingestion API expects, as a single newly-allocated string the
 * caller must free (or NULL on allocation failure). Unlike every other client in this repo, this
 * doesn't build an intermediate structured payload before encoding it: there's no dynamically-
 * typed value type in C to build one out of, so this writes the JSON text directly. This is also
 * why context here is always string-valued: a `const char **keys`/`const char **values` pair of
 * parallel arrays, not the arbitrary nested maps/arrays every other client's context supports.
 *
 * Captures the current call stack itself, via backtrace()/backtrace_symbols() (POSIX,
 * <execinfo.h>): the same mechanism this repo's own Objective-C/Swift clients use for their own
 * signal handlers, just called here at an ordinary (non-signal-handler) call site, which is why
 * this can afford the nicer regex-based frame parsing those signal handlers can't (see
 * event_builder.c's own comment). Like the Go/Rust clients in this repo, the stack is captured at
 * the report call site, not from wherever exception_class/message came from: plain C has
 * nothing resembling an exception object that would carry one.
 *
 * context_keys/context_values must have context_count entries each, or both be NULL with
 * context_count 0. Same shape for user_keys/user_values/user_count: the affected user to attach,
 * omitted from the JSON entirely when user_count is 0. Unlike context, a user entry is never
 * scrubbed (see forgeops_build_event_json's own .c comment): redacting it would defeat the whole
 * point of identifying users in the first place, the same exemption exception_class/environment/
 * release/server_name already get.
 *
 * breadcrumb_json/breadcrumb_count: the breadcrumb trail leading up to this report, oldest first,
 * each entry one already-encoded JSON object (see breadcrumbs.h: entries are encoded, and their
 * message/data PII-scrubbed, when they're added, so nothing here re-scrubs them). Emitted as a
 * top-level "breadcrumbs" array, omitted entirely (never an empty array) when breadcrumb_count is 0.
 */
char *forgeops_build_event_json(const forgeops_configuration_t *config, const char *exception_class, const char *message, const char **context_keys, const char **context_values, size_t context_count, const char **user_keys, const char **user_values, size_t user_count, const char **breadcrumb_json, size_t breadcrumb_count);

/*
 * The same as forgeops_build_event_json, plus the raw SQL statement behind the error (NULL when
 * there isn't one). The statement is masked here (see sql_statement.h) before anything is
 * attached: with config->capture_sql_objects on, a top-level "sql_objects" object names the
 * procedures/tables/views it touched; with config->capture_sql_statement on too, a top-level
 * "sql_statement" carries the masked text. The raw statement is never written to the payload.
 */
char *forgeops_build_event_json_with_sql(const forgeops_configuration_t *config, const char *exception_class, const char *message, const char **context_keys, const char **context_values, size_t context_count, const char **user_keys, const char **user_values, size_t user_count, const char **breadcrumb_json, size_t breadcrumb_count, const char *sql);

/*
 * Reads up to 5 lines of source on either side of `line` (1-based) in `file`, at call time, and
 * returns it pre-encoded as a JSON object-fragment ready to append directly onto an in-progress
 * frame object: `,"context_line":"...","pre_context":[...],"post_context":[...]`. Any single
 * captured line longer than 500 characters is truncated with a trailing "...": guards against a
 * pathological minified/generated line ballooning the payload, the same "don't just trust the
 * SDK" posture MAX_FRAMES already gets on the server side.
 *
 * Gated on the same two things every other client in this repo gates its own source context
 * capture on: `config->capture_source_context` and `in_app`. Returns NULL (nothing to append) when
 * either of those is false/0, when `file` is NULL or `line` is <= 0, or when `file` can't be read
 * for any reason (missing, permission denied, a path that only ever existed inside a build step):
 * never an error of the caller's own, just no context for this one frame. The caller owns and must
 * free a non-NULL return value.
 *
 * This SDK's own two real capture paths (the fatal-signal handler in signal_handler.c, and this
 * file's own append_backtrace_json) never actually have a real file+line to offer: a compiled,
 * stripped C binary carries a binary image name and a resolved symbol, never a source path or
 * line number (see README.md's "Backtrace frames" section), so every frame either path produces
 * is `in_app: 0` with no line number at all. append_backtrace_json below still calls this function
 * for every frame it builds, exactly the way every other client in this repo calls its own
 * equivalent: it just always takes the early gated-off return in practice today, a real,
 * exercised, and independently tested no-op, not dead code kept only for show. capture_source_context
 * itself, and this function, both exist so this SDK is ready the moment it ever does gain a real
 * file+line source to offer (an explicit capture API accepting one directly, say), and so its
 * public API shape matches every other client's.
 */
char *forgeops_source_context_json(const forgeops_configuration_t *config, int in_app, const char *file, long line);

#endif
