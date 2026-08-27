#ifndef FORGEOPS_TRACKER_EVENT_BUILDER_H
#define FORGEOPS_TRACKER_EVENT_BUILDER_H

#include <stddef.h>

#include "forgeops_tracker/configuration.h"

/*
 * Builds the JSON payload the ingestion API expects, as a single newly-allocated string the
 * caller must free (or NULL on allocation failure). Unlike every other client in this repo, this
 * doesn't build an intermediate structured payload before encoding it -- there's no dynamically-
 * typed value type in C to build one out of, so this writes the JSON text directly. This is also
 * why context here is always string-valued: a `const char **keys`/`const char **values` pair of
 * parallel arrays, not the arbitrary nested maps/arrays every other client's context supports.
 *
 * Captures the current call stack itself, via backtrace()/backtrace_symbols() (POSIX,
 * <execinfo.h>) -- the same mechanism this repo's own Objective-C/Swift clients use for their own
 * signal handlers, just called here at an ordinary (non-signal-handler) call site, which is why
 * this can afford the nicer regex-based frame parsing those signal handlers can't (see
 * event_builder.c's own comment). Like the Go/Rust clients in this repo, the stack is captured at
 * the report call site, not from wherever exception_class/message came from -- plain C has
 * nothing resembling an exception object that would carry one.
 *
 * context_keys/context_values must have context_count entries each, or both be NULL with
 * context_count 0.
 */
char *forgeops_build_event_json(const forgeops_configuration_t *config, const char *exception_class, const char *message, const char **context_keys, const char **context_values, size_t context_count);

#endif
