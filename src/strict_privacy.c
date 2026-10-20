/*
 * See strict_privacy.h. The message steps are written as byte scans rather than POSIX regular
 * expressions: POSIX ERE has no lookaround, and its idea of a word character follows the locale,
 * while the spec fixes word characters as ASCII [A-Za-z0-9_] whatever the language thinks. Every
 * byte of a multi-byte UTF-8 character is >= 0x80, so none of them is ever a word character here,
 * which is exactly the rule.
 *
 * SHA-256 is a small self-contained implementation (FIPS 180-4) rather than a new dependency: this
 * SDK links nothing else that has one (libcurl's own hashing isn't public API), and the fingerprint
 * only ever hashes one short message per event.
 */
#include "forgeops_tracker/strict_privacy.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#include "strbuf.h"

/* SHA-256 */

static const uint32_t SHA256_K[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};

#define ROTR(x, n) (((x) >> (n)) | ((x) << (32 - (n))))

static void sha256_block(uint32_t state[8], const unsigned char block[64]) {
  uint32_t w[64];
  for (int i = 0; i < 16; i++) {
    w[i] = ((uint32_t)block[i * 4] << 24) | ((uint32_t)block[i * 4 + 1] << 16) | ((uint32_t)block[i * 4 + 2] << 8) | (uint32_t)block[i * 4 + 3];
  }
  for (int i = 16; i < 64; i++) {
    uint32_t s0 = ROTR(w[i - 15], 7) ^ ROTR(w[i - 15], 18) ^ (w[i - 15] >> 3);
    uint32_t s1 = ROTR(w[i - 2], 17) ^ ROTR(w[i - 2], 19) ^ (w[i - 2] >> 10);
    w[i] = w[i - 16] + s0 + w[i - 7] + s1;
  }

  uint32_t a = state[0], b = state[1], c = state[2], d = state[3], e = state[4], f = state[5], g = state[6], h = state[7];
  for (int i = 0; i < 64; i++) {
    uint32_t t1 = h + (ROTR(e, 6) ^ ROTR(e, 11) ^ ROTR(e, 25)) + ((e & f) ^ (~e & g)) + SHA256_K[i] + w[i];
    uint32_t t2 = (ROTR(a, 2) ^ ROTR(a, 13) ^ ROTR(a, 22)) + ((a & b) ^ (a & c) ^ (b & c));
    h = g;
    g = f;
    f = e;
    e = d + t1;
    d = c;
    c = b;
    b = a;
    a = t1 + t2;
  }
  state[0] += a;
  state[1] += b;
  state[2] += c;
  state[3] += d;
  state[4] += e;
  state[5] += f;
  state[6] += g;
  state[7] += h;
}

static void sha256(const unsigned char *data, size_t length, unsigned char digest[32]) {
  uint32_t state[8] = {0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};

  size_t whole = length - length % 64;
  for (size_t i = 0; i < whole; i += 64) sha256_block(state, data + i);

  /* The tail, a 0x80 byte, zero padding and the bit length: one block, or two when the tail leaves
   * no room for the 8 length bytes. */
  unsigned char tail[128] = {0};
  size_t rest = length - whole;
  memcpy(tail, data + whole, rest);
  tail[rest] = 0x80;
  size_t tail_length = rest + 9 <= 64 ? 64 : 128;
  uint64_t bits = (uint64_t)length * 8;
  for (int i = 0; i < 8; i++) tail[tail_length - 1 - i] = (unsigned char)(bits >> (i * 8));
  for (size_t i = 0; i < tail_length; i += 64) sha256_block(state, tail + i);

  for (int i = 0; i < 8; i++) {
    digest[i * 4] = (unsigned char)(state[i] >> 24);
    digest[i * 4 + 1] = (unsigned char)(state[i] >> 16);
    digest[i * 4 + 2] = (unsigned char)(state[i] >> 8);
    digest[i * 4 + 3] = (unsigned char)state[i];
  }
}

/* message_fingerprint */

static int is_word(unsigned char c) {
  return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_';
}

static int is_digit(unsigned char c) {
  return c >= '0' && c <= '9';
}

static int is_hex(unsigned char c) {
  return is_digit(c) || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
}

/* Step 2: "0x" followed by 4 or more hex digits becomes "0x". */
static int replace_hex_object_ids(const char *in, forgeops_strbuf_t *out) {
  size_t i = 0;
  while (in[i] != '\0') {
    if (in[i] == '0' && in[i + 1] == 'x') {
      size_t run = 0;
      while (is_hex((unsigned char)in[i + 2 + run])) run++;
      if (run >= 4) {
        if (forgeops_strbuf_append(out, "0x", 2) != 0) return -1;
        i += 2 + run;
        continue;
      }
    }
    if (forgeops_strbuf_append(out, in + i, 1) != 0) return -1;
    i++;
  }
  return 0;
}

/* 1 if in[at] starts an 8-4-4-4-12 hex UUID; in is NUL-terminated, so the scan stops at its end. */
static int uuid_at(const char *in, size_t at) {
  static const size_t GROUPS[5] = {8, 4, 4, 4, 12};
  size_t i = at;
  for (int group = 0; group < 5; group++) {
    if (group > 0) {
      if (in[i] != '-') return 0;
      i++;
    }
    for (size_t n = 0; n < GROUPS[group]; n++, i++) {
      if (!is_hex((unsigned char)in[i])) return 0;
    }
  }
  return 1;
}

#define UUID_LENGTH 36

/* Step 3: a UUID with no ASCII word character directly before or after it becomes "<uuid>". */
static int replace_uuids(const char *in, forgeops_strbuf_t *out) {
  size_t i = 0;
  while (in[i] != '\0') {
    int boundary_before = i == 0 || !is_word((unsigned char)in[i - 1]);
    if (boundary_before && uuid_at(in, i) && !is_word((unsigned char)in[i + UUID_LENGTH])) {
      if (forgeops_strbuf_append_str(out, "<uuid>") != 0) return -1;
      i += UUID_LENGTH;
      continue;
    }
    if (forgeops_strbuf_append(out, in + i, 1) != 0) return -1;
    i++;
  }
  return 0;
}

/* Step 4: a run of ASCII digits with no ASCII word character directly before or after it becomes
 * "<n>". A run that touches one is copied whole: no shorter part of it can match either, since the
 * rest of the run is itself a word character. */
static int replace_numbers(const char *in, forgeops_strbuf_t *out) {
  size_t i = 0;
  while (in[i] != '\0') {
    if (!is_digit((unsigned char)in[i])) {
      if (forgeops_strbuf_append(out, in + i, 1) != 0) return -1;
      i++;
      continue;
    }
    size_t end = i;
    while (is_digit((unsigned char)in[end])) end++;
    int boundary_before = i == 0 || !is_word((unsigned char)in[i - 1]);
    int boundary_after = !is_word((unsigned char)in[end]);
    int failed = boundary_before && boundary_after ? forgeops_strbuf_append_str(out, "<n>") : forgeops_strbuf_append(out, in + i, end - i);
    if (failed != 0) return -1;
    i = end;
  }
  return 0;
}

char *forgeops_strict_privacy_normalize_message(const char *message) {
  int (*const steps[3])(const char *, forgeops_strbuf_t *) = {replace_hex_object_ids, replace_uuids, replace_numbers};
  char *current = strdup(message != NULL ? message : "");
  for (int step = 0; current != NULL && step < 3; step++) {
    forgeops_strbuf_t out;
    if (forgeops_strbuf_init(&out, strlen(current) + 16) != 0) {
      free(current);
      return NULL;
    }
    int failed = steps[step](current, &out);
    free(current);
    if (failed != 0) {
      free(out.data);
      return NULL;
    }
    current = out.data;
  }
  return current;
}

int forgeops_strict_privacy_message_fingerprint(const char *message, char out[FORGEOPS_MESSAGE_FINGERPRINT_SIZE]) {
  out[0] = '\0';
  char *normalized = forgeops_strict_privacy_normalize_message(message);
  if (normalized == NULL) return -1;

  unsigned char digest[32];
  sha256((const unsigned char *)normalized, strlen(normalized), digest);
  free(normalized);
  for (int i = 0; i < FORGEOPS_MESSAGE_FINGERPRINT_LENGTH / 2; i++) {
    snprintf(out + i * 2, 3, "%02x", digest[i]);
  }
  return 0;
}

/* Paths and span names */

#define MAX_SEGMENT_CHARACTERS 40

/* 1 when in[start, end) holds no newline: the server's "." never matches one. */
static int no_newline(const char *in, size_t start, size_t end) {
  return memchr(in + start, '\n', end - start) == NULL;
}

/* 1 when the segment in[start, end) is a route parameter: ":id", "{id}", "<int:id>", "[slug]" or
 * "*path" (something after the ":", something inside the brackets). */
static int is_route_parameter(const char *in, size_t start, size_t end) {
  size_t length = end - start;
  const char *s = in + start;
  if (length >= 2 && s[0] == ':') return no_newline(in, start + 1, end);
  if (length >= 1 && s[0] == '*') return no_newline(in, start + 1, end);
  if (length >= 3 && ((s[0] == '{' && s[length - 1] == '}') || (s[0] == '<' && s[length - 1] == '>') || (s[0] == '[' && s[length - 1] == ']'))) {
    return no_newline(in, start + 1, end - 1);
  }
  return 0;
}

/* 1 when the segment in[start, end) holds an ASCII digit or is longer than 40 characters (counted
 * as UTF-8 characters, not bytes): an id, a token or a name slug. */
static int is_id_segment(const char *in, size_t start, size_t end) {
  size_t characters = 0;
  for (size_t i = start; i < end; i++) {
    unsigned char c = (unsigned char)in[i];
    if (is_digit(c)) return 1;
    if ((c & 0xC0) != 0x80) characters++;
  }
  return characters > MAX_SEGMENT_CHARACTERS;
}

char *forgeops_strict_privacy_strict_path(const char *path) {
  if (path == NULL) path = "";
  size_t length = strcspn(path, "?#");

  /* A route template is kept whole: its words are a developer's and its parameters placeholders. */
  for (size_t start = 0; start <= length;) {
    size_t end = start;
    while (end < length && path[end] != '/') end++;
    if (is_route_parameter(path, start, end)) return strndup(path, length);
    start = end + 1;
  }

  /* A raw path keeps only its first non-empty segment: anything after it can name a person. */
  size_t first = 0;
  while (first < length && path[first] == '/') first++;
  if (first == length) return strdup("/");
  size_t first_end = first;
  while (first_end < length && path[first_end] != '/') first_end++;
  size_t rest = first_end;
  while (rest < length && path[rest] == '/') rest++;

  forgeops_strbuf_t out;
  if (forgeops_strbuf_init(&out, first_end - first + 16) != 0) return NULL;
  int failed = path[0] == '/' && forgeops_strbuf_append(&out, "/", 1) != 0;
  if (is_id_segment(path, first, first_end)) {
    failed = failed || forgeops_strbuf_append_str(&out, ":id") != 0;
  } else {
    failed = failed || forgeops_strbuf_append(&out, path + first, first_end - first) != 0;
  }
  if (rest < length) failed = failed || forgeops_strbuf_append_str(&out, "/:path") != 0;
  if (failed) {
    free(out.data);
    return NULL;
  }
  return out.data;
}

char *forgeops_strict_privacy_path_without_ids(const char *path) {
  return forgeops_strict_privacy_strict_path(path);
}

static const char *const HTTP_METHODS[] = {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"};

static int is_space(unsigned char c) {
  return c == ' ' || c == '\t' || c == '\n' || c == '\v' || c == '\f' || c == '\r';
}

static int is_alpha(unsigned char c) {
  return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z');
}

/* The length of a leading "scheme://" (any scheme: a letter, then letters, digits, "+", "." or
 * "-"), or 0 when target doesn't start with one. */
static size_t scheme_length(const char *target, size_t target_length) {
  if (target_length == 0 || !is_alpha((unsigned char)target[0])) return 0;
  size_t i = 1;
  while (i < target_length && (is_alpha((unsigned char)target[i]) || is_digit((unsigned char)target[i]) || target[i] == '+' || target[i] == '.' || target[i] == '-')) i++;
  if (i + 3 <= target_length && strncmp(target + i, "://", 3) == 0) return i + 3;
  return 0;
}

/* The host of an outbound call's target, read by hand (a URL parser that rejects an address must
 * never mean the whole address is sent instead): drop a leading "scheme://", keep what comes before
 * the first "/", "?" or "#", drop anything up to and including the last "@" and a trailing ":port".
 * It only counts as a host when the address had a scheme or a port, or the host has a dot or is
 * "localhost". Newly allocated, or NULL when there's no host. */
static char *host_of(const char *target, size_t target_length) {
  size_t scheme = scheme_length(target, target_length);
  const char *authority = target + scheme;
  size_t length = 0;
  while (scheme + length < target_length && authority[length] != '/' && authority[length] != '?' && authority[length] != '#') length++;
  for (size_t i = length; i > 0; i--) {
    if (authority[i - 1] == '@') { /* the last one: a password can hold an "@", a host never does */
      authority += i;
      length -= i;
      break;
    }
  }

  size_t digits = 0;
  while (digits < length && is_digit((unsigned char)authority[length - 1 - digits])) digits++;
  int port = digits > 0 && digits < length && authority[length - 1 - digits] == ':';
  if (port) length -= digits + 1;
  if (length == 0) return NULL;

  int dotted = memchr(authority, '.', length) != NULL;
  int localhost = length == 9 && strncasecmp(authority, "localhost", 9) == 0;
  if (!scheme && !port && !dotted && !localhost) return NULL;
  return strndup(authority, length);
}

char *forgeops_strict_privacy_span_name(const char *name) {
  if (name == NULL) return NULL;
  if (name[0] == '/') return forgeops_strict_privacy_strict_path(name); /* a span named by a raw path */
  size_t method_length = 0;
  const char *method = NULL;
  for (size_t m = 0; m < sizeof(HTTP_METHODS) / sizeof(HTTP_METHODS[0]); m++) {
    size_t length = strlen(HTTP_METHODS[m]);
    if (strncasecmp(name, HTTP_METHODS[m], length) == 0 && is_space((unsigned char)name[length])) {
      method = HTTP_METHODS[m];
      method_length = length;
      break;
    }
  }
  const char *target = name + method_length;
  while (method != NULL && is_space((unsigned char)*target)) target++;
  size_t target_length = 0;
  while (target[target_length] != '\0' && !is_space((unsigned char)target[target_length])) target_length++;
  if (method == NULL || target_length == 0) return strdup(name);

  forgeops_strbuf_t out;
  if (forgeops_strbuf_init(&out, 64) != 0) return NULL;
  forgeops_strbuf_append_str(&out, method);
  forgeops_strbuf_append(&out, " ", 1);

  char *host = target[0] == '/' ? NULL : host_of(target, target_length);
  if (host != NULL) {
    forgeops_strbuf_append_str(&out, host);
  } else {
    char *target_copy = strndup(target, target_length);
    char *path = target_copy != NULL ? forgeops_strict_privacy_strict_path(target_copy) : NULL;
    if (path != NULL) forgeops_strbuf_append_str(&out, path);
    free(path);
    free(target_copy);
  }
  free(host);
  return out.data;
}

char *forgeops_strict_privacy_transaction_name(const char *name) {
  if (name == NULL) return NULL;
  return name[0] == '\0' ? strdup(name) : forgeops_strict_privacy_span_name(name);
}

int forgeops_strict_privacy_allows_field(const forgeops_configuration_t *config, const char *key) {
  if (config == NULL || key == NULL) return 0;
  for (int i = 0; i < config->privacy_allowed_field_count; i++) {
    if (config->privacy_allowed_fields[i] != NULL && strcmp(config->privacy_allowed_fields[i], key) == 0) return 1;
  }
  return 0;
}

const char *forgeops_strict_privacy_user_id(const char **user_keys, const char **user_values, size_t user_count) {
  if (user_keys == NULL || user_values == NULL) return NULL;
  for (size_t i = 0; i < user_count; i++) {
    if (user_keys[i] == NULL || strcmp(user_keys[i], "id") != 0 || user_values[i] == NULL) continue;
    for (const char *p = user_values[i]; *p != '\0'; p++) {
      if (!is_space((unsigned char)*p)) return user_values[i];
    }
  }
  return NULL;
}
