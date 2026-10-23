/*
 * POSIX Extended Regular Expressions (<regex.h>) have no `\d`, `\s`, or `\b`: unlike the PCRE
 * syntax every other client in this repo's own regex engine accepts unmodified from the Ruby
 * original. `\d`/`\s` are straightforward to translate (`[0-9]`/`[[:space:]]`); `\b` (word
 * boundary) has no POSIX equivalent at all, so the boundary-sensitive patterns below (JWT, AWS
 * key, Stripe key, GitHub token, bearer token, SSN) simply don't require one here. Verified
 * directly (see /tmp/regextest*.c during development, not committed) that this doesn't cause
 * false negatives against any of this file's own test inputs: interval expressions
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
  /* Whether a match must also sit between word boundaries, checked by hand (POSIX has no `\b`). */
  int word_bounded;
} pattern_spec_t;

/* Every pattern here matches gems/forge_ops_tracker/lib/forge_ops_tracker/pii_scrubber.rb's own
 * 8 patterns as closely as POSIX ERE allows: see this file's own top comment for the `\d`/`\s`/
 * `\b` adjustments that required. The formatted card number is the exception that does check its
 * `\b` (word_bounded): without it, "4242 4242 4242 4242a" would be scrubbed here although the
 * server leaves it, and the card number rule below (sdks/PII_SCRUBBING.md) pins that it does. */
static const pattern_spec_t PATTERNS[] = {
    {"EMAIL", "[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}", 0, 0},
    {"SSN", "[0-9]{3}-[0-9]{2}-[0-9]{4}", 0, 0},
    {"CREDIT CARD", "[0-9]{4}[ -][0-9]{4}[ -][0-9]{4}[ -][0-9]{1,4}", 0, 1},
    {"BEARER TOKEN", "Bearer[[:space:]]+[A-Za-z0-9._~+/-]+=*", REG_ICASE, 0},
    {"JWT", "ey[A-Za-z0-9_-]{10,}\\.[A-Za-z0-9_-]{10,}\\.[A-Za-z0-9_-]{10,}", 0, 0},
    {"AWS KEY", "AKIA[0-9A-Z]{16}", 0, 0},
    {"STRIPE KEY", "[sr]k_(live|test)_[A-Za-z0-9]{10,}", 0, 0},
    {"GITHUB TOKEN", "gh[pousr]_[A-Za-z0-9]{20,}", 0, 0},
};
static const size_t PATTERN_COUNT = sizeof(PATTERNS) / sizeof(PATTERNS[0]);

/* ASCII only, as `\b` and the card and IBAN rules below have it: a UTF-8 byte of a non-ASCII
 * character is never a word character. */
static int is_ascii_digit(char c) { return c >= '0' && c <= '9'; }
static int is_ascii_upper(char c) { return c >= 'A' && c <= 'Z'; }
static int is_iban_char(char c) { return is_ascii_upper(c) || is_ascii_digit(c); }
static int is_word_char(char c) { return is_iban_char(c) || (c >= 'a' && c <= 'z') || c == '_'; }

static char *apply_pattern(const char *input, const pattern_spec_t *spec) {
  regex_t re;
  if (regcomp(&re, spec->pattern, REG_EXTENDED | spec->extra_flags) != 0) {
    /* A pattern here failing to compile is a bug in this file, not something a caller did:
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
  const char *search = input; /* where the next regexec starts; cursor <= search */
  regmatch_t match;
  while (regexec(&re, search, 1, &match, search == input ? 0 : REG_NOTBOL) == 0) {
    if (spec->word_bounded) {
      /* The one word_bounded pattern starts and ends with a digit, and the leftmost-longest match
       * at a start is the only one there that could end at a boundary (a shorter one ends right
       * before another digit), so a match missing either boundary means none starts there: look
       * again from the next byte. */
      const char *start = search + match.rm_so;
      const char *end = search + match.rm_eo;
      if ((start > input && is_word_char(start[-1])) || is_word_char(*end)) {
        if (*start == '\0') break;
        search = start + 1;
        continue;
      }
    }
    match.rm_so += (regoff_t)(search - cursor);
    match.rm_eo += (regoff_t)(search - cursor);
    forgeops_strbuf_append(&out, cursor, (size_t)match.rm_so);

    char replacement[64];
    snprintf(replacement, sizeof(replacement), "[%s FILTERED]", spec->label);
    forgeops_strbuf_append(&out, replacement, strlen(replacement));

    if (match.rm_eo == match.rm_so) {
      /* Defensive only: none of the patterns above can match an empty string, but an infinite
       * loop here would hang the host app, so guard it anyway. */
      if (cursor[match.rm_eo] == '\0') break;
      forgeops_strbuf_append(&out, cursor + match.rm_eo, 1);
      cursor += match.rm_eo + 1;
    } else {
      cursor += match.rm_eo;
    }
    search = cursor;
  }
  forgeops_strbuf_append(&out, cursor, strlen(cursor));

  regfree(&re);
  return out.data;
}

/*
 * IBANs and card numbers in any shape (sdks/PII_SCRUBBING.md is the rule every SDK follows, and
 * tests/fixtures/pii_scrubbing_vectors.json pins it). POSIX ERE has neither `\b` nor lookaround and
 * matches leftmost-longest rather than the way the server's backtracking engine does, so both are
 * found by hand here, byte by byte (the character tests are above PATTERNS).
 */

/* `\b` at pos (0 < pos <= len). */
static int is_word_boundary(const char *s, size_t len, size_t pos) {
  return is_word_char(s[pos - 1]) != (pos < len && is_word_char(s[pos]));
}

/* Whether " " plus four [A-Z0-9] starts at pos. */
static int is_iban_group(const char *s, size_t len, size_t pos) {
  if (pos + 5 > len || s[pos] != ' ') return 0;
  for (size_t k = 1; k <= 4; k++) {
    if (!is_iban_char(s[pos + k])) return 0;
  }
  return 1;
}

/*
 * Where a match of \b[A-Z]{2}\d{2}(?:[A-Z0-9]{11,30}|(?: [A-Z0-9]{4}){2,7}(?: [A-Z0-9]{1,4})?)\b
 * starting at start ends, or 0 when there's none: exactly what a backtracking engine returns,
 * trying the compact branch first, every quantifier greedy, and giving back one repetition at a
 * time until the closing \b holds.
 */
static size_t iban_candidate_end(const char *s, size_t len, size_t start) {
  if (start > 0 && is_word_char(s[start - 1])) return 0;
  if (start + 4 > len || !is_ascii_upper(s[start]) || !is_ascii_upper(s[start + 1]) ||
      !is_ascii_digit(s[start + 2]) || !is_ascii_digit(s[start + 3])) {
    return 0;
  }
  size_t rest = start + 4;

  size_t compact = 0;
  while (compact < 30 && rest + compact < len && is_iban_char(s[rest + compact])) compact++;
  for (size_t k = compact; k >= 11; k--) {
    if (is_word_boundary(s, len, rest + k)) return rest + k;
  }

  size_t groups = 0;
  while (groups < 7 && is_iban_group(s, len, rest + 5 * groups)) groups++;
  for (size_t g = groups; g >= 2; g--) {
    size_t after = rest + 5 * g;
    if (after < len && s[after] == ' ') {
      size_t tail = 0;
      while (tail < 4 && after + 1 + tail < len && is_iban_char(s[after + 1 + tail])) tail++;
      for (size_t t = tail; t >= 1; t--) {
        if (is_word_boundary(s, len, after + 1 + t)) return after + 1 + t;
      }
    }
    if (is_word_boundary(s, len, after)) return after;
  }
  return 0;
}

/* The IBAN check, a digit at a time so no big integers are needed: with spaces removed, 15 to 34
 * characters; the first four moved to the end, each letter read as two digits (A is 10, Z is 35),
 * and the remainder by 97 is 1. */
static int is_iban(const char *candidate, size_t len) {
  char compact[64];
  size_t n = 0;
  for (size_t k = 0; k < len; k++) {
    if (candidate[k] == ' ') continue;
    if (n == 34) return 0;
    compact[n++] = candidate[k];
  }
  if (n < 15) return 0;
  unsigned remainder = 0;
  for (size_t k = 0; k < n; k++) {
    char c = compact[(k + 4) % n];
    if (is_ascii_upper(c)) {
      unsigned value = (unsigned)(c - 'A') + 10;
      remainder = (remainder * 10 + value / 10) % 97;
      remainder = (remainder * 10 + value % 10) % 97;
    } else {
      remainder = (remainder * 10 + (unsigned)(c - '0')) % 97;
    }
  }
  return remainder == 1;
}

/* Every IBAN candidate, left to right and non-overlapping, replaced when it passes the check. */
static char *scrub_ibans(const char *input) {
  size_t len = strlen(input);
  forgeops_strbuf_t out;
  if (forgeops_strbuf_init(&out, len + 32) != 0) return NULL;
  int failed = 0;
  size_t copied = 0;
  for (size_t i = 0; i < len;) {
    size_t end = iban_candidate_end(input, len, i);
    if (end == 0) {
      i++;
      continue;
    }
    if (is_iban(input + i, end - i)) {
      failed |= forgeops_strbuf_append(&out, input + copied, i - copied);
      failed |= forgeops_strbuf_append_str(&out, "[IBAN FILTERED]");
      copied = end;
    }
    i = end;
  }
  failed |= forgeops_strbuf_append(&out, input + copied, len - copied);
  if (failed) {
    free(out.data);
    return NULL;
  }
  return out.data;
}

/* 4, 51 to 55, 2221 to 2720, 34, 37, 6011, 644 to 649, 65, 3528 to 3589, 36, 300 to 305, 62. */
static int has_card_prefix(const char *d) {
  int two = (d[0] - '0') * 10 + (d[1] - '0');
  int three = two * 10 + (d[2] - '0');
  int four = three * 10 + (d[3] - '0');
  return d[0] == '4' || (two >= 51 && two <= 55) || two == 34 || two == 37 || two == 65 || two == 36 ||
         two == 62 || (four >= 2221 && four <= 2720) || four == 6011 || (four >= 3528 && four <= 3589) ||
         (three >= 644 && three <= 649) || (three >= 300 && three <= 305);
}

/* 13 to 19 digits, a card network's prefix, and the Luhn check. */
static int is_card_number(const char *digits, size_t len) {
  if (len < 13 || len > 19 || !has_card_prefix(digits)) return 0;
  int sum = 0;
  for (size_t k = 0; k < len; k++) {
    int value = digits[len - 1 - k] - '0';
    if (k % 2 == 1) {
      value *= 2;
      if (value > 9) value -= 9;
    }
    sum += value;
  }
  return sum % 10 == 0;
}

/*
 * One run (digits joined by single spaces or dashes), written to out with its card numbers
 * replaced: from each group on, the longest stretch of whole groups that is a card number is
 * replaced, and scanning carries on after it; with none, from the next group. So a card followed
 * by its CVV ("4242424242424242 123"), two cards in a row, and Amex's 4-6-5 grouping are all found.
 */
static int scrub_card_numbers_in(forgeops_strbuf_t *out, const char *run, size_t len) {
  int failed = 0;
  size_t group = 0; /* where group i starts */
  while (group < len) {
    /* A card number has at most 19 digits, so only stretches that short can be one; the last one
     * that is wins, the same as trying the longest stretch first. */
    char joined[20];
    size_t joined_len = 0;
    size_t found_end = 0; /* where the matching stretch's last group ends */
    size_t pos = group;
    while (pos < len) {
      size_t group_end = pos;
      while (group_end < len && is_ascii_digit(run[group_end])) group_end++;
      if (joined_len + (group_end - pos) > 19) break;
      memcpy(joined + joined_len, run + pos, group_end - pos);
      joined_len += group_end - pos;
      if (is_card_number(joined, joined_len)) found_end = group_end;
      pos = group_end + 1; /* past the separator */
    }

    size_t group_end = group;
    while (group_end < len && is_ascii_digit(run[group_end])) group_end++;
    size_t written_to = found_end != 0 ? found_end : group_end;
    if (found_end != 0) {
      failed |= forgeops_strbuf_append_str(out, "[CREDIT CARD FILTERED]");
    } else {
      failed |= forgeops_strbuf_append(out, run + group, group_end - group);
    }
    if (written_to < len) failed |= forgeops_strbuf_append(out, run + written_to, 1); /* its separator */
    group = written_to + 1;
  }
  return failed;
}

/*
 * Finds what (?<![A-Za-z0-9_])\d(?:[ -]?\d)*(?![A-Za-z0-9_]) would, by hand: a run of digits joined
 * by single spaces or dashes, starting at a digit not preceded by a word character. When the full
 * run is followed by a word character, a regex engine backs off to just before the run's last
 * separator (a separator is not a word character); with no separator to back off to, the run is no
 * match at all and scanning carries on after it.
 */
static char *scrub_card_numbers(const char *input) {
  size_t len = strlen(input);
  forgeops_strbuf_t out;
  if (forgeops_strbuf_init(&out, len + 32) != 0) return NULL;
  int failed = 0;
  size_t copied = 0;
  size_t i = 0;
  while (i < len) {
    if (!is_ascii_digit(input[i]) || (i > 0 && is_word_char(input[i - 1]))) {
      i++;
      continue;
    }
    size_t end = i + 1;
    size_t last_separator = 0; /* 0: none (a separator is never at a run's first byte) */
    while (end < len) {
      if (is_ascii_digit(input[end])) {
        end++;
      } else if ((input[end] == ' ' || input[end] == '-') && end + 1 < len && is_ascii_digit(input[end + 1])) {
        last_separator = end;
        end += 2;
      } else {
        break;
      }
    }
    if (end < len && is_word_char(input[end])) {
      if (last_separator == 0) {
        i = end;
        continue;
      }
      end = last_separator;
    }
    failed |= forgeops_strbuf_append(&out, input + copied, i - copied);
    failed |= scrub_card_numbers_in(&out, input + i, end - i);
    copied = end;
    i = end;
  }
  failed |= forgeops_strbuf_append(&out, input + copied, len - copied);
  if (failed) {
    free(out.data);
    return NULL;
  }
  return out.data;
}

char *forgeops_scrub_string(const char *input) {
  if (input == NULL) return NULL;

  /* IBANs first: a spaced IBAN's middle groups look like a formatted card number. */
  char *current = scrub_ibans(input);
  if (current == NULL) return NULL;

  for (size_t i = 0; i < PATTERN_COUNT; i++) {
    char *next = apply_pattern(current, &PATTERNS[i]);
    free(current);
    if (next == NULL) return NULL;
    current = next;
  }

  /* Then card numbers in any other shape. */
  char *scrubbed = scrub_card_numbers(current);
  free(current);
  return scrubbed;
}

static const char *SENSITIVE_KEYS[] = {
    "password", "passwd", "pwd",
    "secret", "apisecret", "clientsecret", "secretkey",
    "token", "accesstoken", "refreshtoken", "apikey", "apitoken", "authorization", "authtoken", "bearer", "sessiontoken", "csrftoken",
    "creditcard", "cardnumber", "cardnum", "cvv", "cvv2", "cvc",
    "iban", "accountnumber", "routingnumber", "bankaccount",
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
