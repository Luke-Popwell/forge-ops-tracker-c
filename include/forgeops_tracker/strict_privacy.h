#ifndef FORGEOPS_TRACKER_STRICT_PRIVACY_H
#define FORGEOPS_TRACKER_STRICT_PRIVACY_H

#include <stddef.h>

#include "forgeops_tracker/configuration.h"

/*
 * Strict privacy (config->strict_privacy): for apps that can't let personal or health data leave
 * their own servers. With it on, an event carries only structured facts about an error, never free
 * text: no message (a message_fingerprint instead), no breadcrumbs, no SQL statement, no source
 * context, only the user's id, and only the context keys named in privacy_allowed_fields. Span
 * names keep an outbound call's method and host but never its path, and span data keeps only
 * db.statement and db.system. The server applies the same rules again on arrival for a project
 * with its own Strict privacy setting on; doing it here means the text never leaves the process.
 *
 * Every function below is the exact algorithm in sdks/STRICT_PRIVACY.md, pinned by
 * sdks/strict_privacy_vectors.json (tests/fixtures/strict_privacy_vectors.json is a copy).
 */

/* Hex characters in a message_fingerprint, plus the NUL. */
#define FORGEOPS_MESSAGE_FINGERPRINT_LENGTH 32
#define FORGEOPS_MESSAGE_FINGERPRINT_SIZE (FORGEOPS_MESSAGE_FINGERPRINT_LENGTH + 1)

/*
 * The message with every email replaced by "<email>", every double-quoted run and then every
 * single-quoted run (quotes included, never across a line break) by "<str>", every "0x" plus 4 or
 * more hex digits cut to "0x", then every UUID and every standalone run of ASCII digits replaced by
 * "<uuid>" and "<n>", in that order. A single quote only opens or closes a run where it doesn't
 * touch an ASCII letter, digit or underscore on the outside, and "standalone" means not touching
 * one at all: a byte scan over the UTF-8 text, so a digit or letter in another script never counts
 * as one. NULL is treated as "". Newly allocated; NULL only on allocation failure.
 */
char *forgeops_strict_privacy_normalize_message(const char *message);

/*
 * The first 32 lowercase hex characters of the SHA-256 of the normalized message, written to out
 * (NUL-terminated). Returns 0, or -1 on allocation failure (out is then "").
 */
int forgeops_strict_privacy_message_fingerprint(const char *message, char out[FORGEOPS_MESSAGE_FINGERPRINT_SIZE]);

/*
 * A request or page path as strict privacy sends it, with no query or fragment. A route template
 * (any segment that starts with ":" or "*", or is wrapped in {}, <> or []) is kept as it is:
 * "/patients/:id/notes" stays. A raw path keeps only its first segment (":id" when that holds an
 * ASCII digit or is longer than 40 characters), then "/:path" if there was more:
 * "/patients/jane-doe/12" is "/patients/:path", "/42/edit" is "/:id/:path". No segments at all is
 * "/". Newly allocated; NULL only on allocation failure.
 */
char *forgeops_strict_privacy_strict_path(const char *path);

/* The name this function had before strict_path replaced its rule: the same function, kept so code
 * built against an earlier release still links. */
char *forgeops_strict_privacy_path_without_ids(const char *path);

/*
 * A span name with an outbound call's path and query taken out: "GET https://api.example.com/a/42"
 * is "GET api.example.com". The address is read by hand, never with a URL parser: its host counts
 * as one only when the address had a scheme or a port, or the host has a dot or is "localhost"
 * ("GET localhost:3000/a/1" is "GET localhost"). Otherwise, or with a target that starts with "/",
 * the target goes through forgeops_strict_privacy_strict_path ("GET /patients/42/notes" is
 * "GET /patients/:path", "GET /patients/:id" stays), and so does a name that is a path
 * ("/patients/jane-doe" is "/patients/:path"). Any other name ("OrdersController#create") is kept
 * as is. Newly allocated; NULL only on allocation failure.
 */
char *forgeops_strict_privacy_span_name(const char *name);

/*
 * A performance sample's transaction_name under strict privacy: the span name rule above, so a
 * route template or "Controller#action" is kept and a raw path keeps only its first segment
 * ("GET /patients/42/notes" is "GET /patients/:path"). NULL or
 * "" is returned as a copy. Newly allocated; NULL only on allocation failure or a NULL name.
 */
char *forgeops_strict_privacy_transaction_name(const char *name);

/*
 * The value under the "id" key of a user's parallel key/value arrays, the one user field strict
 * privacy sends (never email or username), or NULL when there is no id or it's blank. Borrowed
 * from user_values, not copied.
 */
const char *forgeops_strict_privacy_user_id(const char **user_keys, const char **user_values, size_t user_count);

/* 1 if key is one of config->privacy_allowed_fields, exactly; 0 otherwise. */
int forgeops_strict_privacy_allows_field(const forgeops_configuration_t *config, const char *key);

#endif
