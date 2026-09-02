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

/*
 * Reads up to 5 lines of source on either side of `line` (1-based) in `file`, at call time, and
 * returns it pre-encoded as a JSON object-fragment ready to append directly onto an in-progress
 * frame object: `,"context_line":"...","pre_context":[...],"post_context":[...]`. Any single
 * captured line longer than 500 characters is truncated with a trailing "..." -- guards against a
 * pathological minified/generated line ballooning the payload, the same "don't just trust the
 * SDK" posture MAX_FRAMES already gets on the server side.
 *
 * Gated on the same two things every other client in this repo gates its own source context
 * capture on: `config->capture_source_context` and `in_app`. Returns NULL (nothing to append) when
 * either of those is false/0, when `file` is NULL or `line` is <= 0, or when `file` can't be read
 * for any reason (missing, permission denied, a path that only ever existed inside a build step) --
 * never an error of the caller's own, just no context for this one frame. The caller owns and must
 * free a non-NULL return value.
 *
 * This SDK's own two real capture paths (the fatal-signal handler in signal_handler.c, and this
 * file's own append_backtrace_json) never actually have a real file+line to offer: a compiled,
 * stripped C binary carries a binary image name and a resolved symbol, never a source path or
 * line number (see README.md's "Backtrace frames" section), so every frame either path produces
 * is `in_app: 0` with no line number at all. append_backtrace_json below still calls this function
 * for every frame it builds, exactly the way every other client in this repo calls its own
 * equivalent -- it just always takes the early gated-off return in practice today, a real,
 * exercised, and independently tested no-op, not dead code kept only for show. capture_source_context
 * itself, and this function, both exist so this SDK is ready the moment it ever does gain a real
 * file+line source to offer (an explicit capture API accepting one directly, say), and so its
 * public API shape matches every other client's.
 */
char *forgeops_source_context_json(const forgeops_configuration_t *config, int in_app, const char *file, long line);

#endif
