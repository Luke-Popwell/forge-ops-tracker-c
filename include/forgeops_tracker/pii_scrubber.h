#ifndef FORGEOPS_TRACKER_PII_SCRUBBER_H
#define FORGEOPS_TRACKER_PII_SCRUBBER_H

#define FORGEOPS_REDACTED "[FILTERED]"

/*
 * Redacts likely-sensitive content out of a string before it ever leaves this process -- the
 * same patterns ForgeOps itself applies again on arrival (defense in depth: this layer keeps the
 * data off the wire and out of any logging in between; the server-side layer is what actually
 * protects the database). Ported from
 * gems/forge_ops_tracker/lib/forge_ops_tracker/pii_scrubber.rb, adapted for POSIX Extended
 * Regular Expressions (<regex.h>) rather than PCRE -- see pii_scrubber.c's own comment for what
 * that adaptation actually changes.
 *
 * Returns a newly-allocated string the caller must free, or NULL on allocation failure. Never
 * returns NULL for a non-NULL input except on genuine out-of-memory.
 */
char *forgeops_scrub_string(const char *input);

/*
 * Whether key looks like it names sensitive data (password, api_key, ssn, and similar),
 * case/punctuation-insensitively. A NULL or empty key is never sensitive.
 */
int forgeops_is_sensitive_key(const char *key);

#endif
