/*
 * POSIX Extended Regular Expressions (<regex.h>) have no `\d`, `\s`, or `\b` -- unlike the PCRE
 * syntax every other client in this repo's own regex engine accepts unmodified from the Ruby
 * original. `\d`/`\s` are straightforward to translate (`[0-9]`/`[[:space:]]`); `\b` (word
 * boundary) has no POSIX equivalent at all, so the boundary-sensitive patterns below (JWT, AWS
 * key, Stripe key, GitHub token, bearer token, SSN) simply don't require one here. Verified
 * directly (see /tmp/regextest*.c during development, not committed) that this doesn't cause
 * false negatives against any of this file's own test inputs -- interval expressions
 * ({n,m}) work fine on POSIX ERE, and every pattern below still requires its own literal
 * delimiters (a leading "AKIA", a "-" between SSN groups, and so on), so dropping `\b` only
 * risks a slightly wider match (redacting a token embedded inside a longer string that also
 * happens to contain non-token characters around it) never a narrower one that misses real PII.
 */
#include "forgeops_tracker/pii_scrubber.h"

#include <ctype.h>
#include <regex.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "strbuf.h"

typedef struct {
  const char *label;
  const char *pattern;
  int extra_flags;
} pattern_spec_t;

/* Every pattern here matches gems/forge_ops_tracker/lib/forge_ops_tracker/pii_scrubber.rb's own
 * 8 patterns as closely as POSIX ERE allows -- see this file's own top comment for the `\d`/`\s`/
 * `\b` adjustments that required. */
static const pattern_spec_t PATTERNS[] = {
    {"EMAIL", "[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}", 0},
    {"SSN", "[0-9]{3}-[0-9]{2}-[0-9]{4}", 0},
    {"CREDIT CARD", "[0-9]{4}[ -][0-9]{4}[ -][0-9]{4}[ -][0-9]{1,4}", 0},
    {"BEARER TOKEN", "Bearer[[:space:]]+[A-Za-z0-9._~+/-]+=*", REG_ICASE},
    {"JWT", "ey[A-Za-z0-9_-]{10,}\\.[A-Za-z0-9_-]{10,}\\.[A-Za-z0-9_-]{10,}", 0},
    {"AWS KEY", "AKIA[0-9A-Z]{16}", 0},
    {"STRIPE KEY", "[sr]k_(live|test)_[A-Za-z0-9]{10,}", 0},
    {"GITHUB TOKEN", "gh[pousr]_[A-Za-z0-9]{20,}", 0},
};
static const size_t PATTERN_COUNT = sizeof(PATTERNS) / sizeof(PATTERNS[0]);

static char *apply_pattern(const char *input, const pattern_spec_t *spec) {
  regex_t re;
  if (regcomp(&re, spec->pattern, REG_EXTENDED | spec->extra_flags) != 0) {
    /* A pattern here failing to compile is a bug in this file, not something a caller did --
     * every pattern above is a fixed literal compiled once per call. Fall back to returning the
     * input unmodified rather than crashing the host app over a scrubber bug. */
    return strdup(input);
  }

  forgeops_strbuf_t out;
  if (forgeops_strbuf_init(&out, strlen(input) + 32) != 0) {
    regfree(&re);
    return NULL;
  }

  const char *cursor = input;
  regmatch_t match;
  while (regexec(&re, cursor, 1, &match, cursor == input ? 0 : REG_NOTBOL) == 0) {
    forgeops_strbuf_append(&out, cursor, (size_t)match.rm_so);

    char replacement[64];
    snprintf(replacement, sizeof(replacement), "[%s FILTERED]", spec->label);
    forgeops_strbuf_append(&out, replacement, strlen(replacement));

    if (match.rm_eo == match.rm_so) {
      /* Defensive only -- none of the patterns above can match an empty string, but an infinite
       * loop here would hang the host app, so guard it anyway. */
      if (cursor[match.rm_eo] == '\0') break;
      forgeops_strbuf_append(&out, cursor + match.rm_eo, 1);
      cursor += match.rm_eo + 1;
    } else {
      cursor += match.rm_eo;
    }
  }
  forgeops_strbuf_append(&out, cursor, strlen(cursor));

  regfree(&re);
  return out.data;
}

char *forgeops_scrub_string(const char *input) {
  if (input == NULL) return NULL;

  char *current = strdup(input);
  if (current == NULL) return NULL;

  for (size_t i = 0; i < PATTERN_COUNT; i++) {
    char *next = apply_pattern(current, &PATTERNS[i]);
    free(current);
    if (next == NULL) return NULL;
    current = next;
  }
  return current;
}

static const char *SENSITIVE_KEYS[] = {
    "password", "passwd", "pwd",
    "secret", "apisecret", "clientsecret", "secretkey",
    "token", "accesstoken", "refreshtoken", "apikey", "apitoken", "authorization", "authtoken", "bearer", "sessiontoken", "csrftoken",
    "creditcard", "cardnumber", "cardnum", "cvv", "cvv2", "cvc",
    "ssn", "socialsecuritynumber", "socialsecurity",
    "privatekey",
};
static const size_t SENSITIVE_KEY_COUNT = sizeof(SENSITIVE_KEYS) / sizeof(SENSITIVE_KEYS[0]);

int forgeops_is_sensitive_key(const char *key) {
  if (key == NULL || key[0] == '\0') return 0;

  char normalized[256];
  size_t normalized_len = 0;
  for (const char *p = key; *p != '\0' && normalized_len < sizeof(normalized) - 1; p++) {
    if (isalnum((unsigned char)*p)) {
      normalized[normalized_len++] = (char)tolower((unsigned char)*p);
    }
  }
  normalized[normalized_len] = '\0';

  for (size_t i = 0; i < SENSITIVE_KEY_COUNT; i++) {
    if (strstr(normalized, SENSITIVE_KEYS[i]) != NULL) return 1;
  }
  return 0;
}
