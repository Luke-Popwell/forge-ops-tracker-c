#include "forgeops_tracker/trace_parent.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static int is_lower_hex(const char *s, size_t length) {
  for (size_t i = 0; i < length; i++) {
    char c = s[i];
    if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) return 0;
  }
  return 1;
}

static int all_zeros(const char *s, size_t length) {
  for (size_t i = 0; i < length; i++) {
    if (s[i] != '0') return 0;
  }
  return 1;
}

int forgeops_traceparent_parse(const char *value, char *trace_id, char *parent_span_id) {
  if (value == NULL) return 0;
  while (isspace((unsigned char)*value)) value++;
  size_t length = strlen(value);
  while (length > 0 && isspace((unsigned char)value[length - 1])) length--;

  /* The four fields every version shares: "vv-" + 32 + "-" + 16 + "-ff". */
  const size_t fixed = FORGEOPS_TRACEPARENT_SIZE - 1;
  if (length < fixed) return 0;
  if (!is_lower_hex(value, 2) || value[2] != '-' || !is_lower_hex(value + 3, 32) || value[35] != '-' ||
      !is_lower_hex(value + 36, 16) || value[52] != '-' || !is_lower_hex(value + 53, 2)) {
    return 0;
  }
  if (strncmp(value, "ff", 2) == 0) return 0;
  if (length > fixed && (strncmp(value, "00", 2) == 0 || value[fixed] != '-')) return 0;
  if (all_zeros(value + 3, 32) || all_zeros(value + 36, 16)) return 0;

  memcpy(trace_id, value + 3, 32);
  trace_id[32] = '\0';
  memcpy(parent_span_id, value + 36, 16);
  parent_span_id[16] = '\0';
  return 1;
}

void forgeops_traceparent_build(const char *trace_id, const char *span_id, char *out) {
  /* Always "01" (sampled) on the way out: whether a trace is sent is only decided once it's over
   * (see trace_capture_threshold_ms), long after this header has gone out, so "this may be
   * recorded" is the only honest answer. The next service makes its own decision either way. */
  snprintf(out, FORGEOPS_TRACEPARENT_SIZE, "00-%.32s-%.16s-01", trace_id, span_id);
}

static void random_hex(char *out, size_t hex_length) {
  size_t bytes = hex_length / 2;
  unsigned char raw[16];
  int filled = 0;
  FILE *urandom = fopen("/dev/urandom", "rb");
  if (urandom != NULL) {
    filled = fread(raw, 1, bytes, urandom) == bytes;
    fclose(urandom);
  }
  if (!filled) {
    /* No /dev/urandom: an id only has to be unique within one project's traces, not unpredictable. */
    static unsigned int seed = 0;
    if (seed == 0) seed = (unsigned int)time(NULL) ^ (unsigned int)(size_t)&seed;
    for (size_t i = 0; i < bytes; i++) raw[i] = (unsigned char)(rand_r(&seed) & 0xff);
  }
  for (size_t i = 0; i < bytes; i++) snprintf(out + i * 2, 3, "%02x", raw[i]);
}

void forgeops_trace_random_id(char *out, size_t hex_length) {
  if (hex_length > 32) hex_length = 32;
  do {
    random_hex(out, hex_length);
  } while (all_zeros(out, hex_length));
  out[hex_length] = '\0';
}

int forgeops_url_host(const char *url, char *out, size_t out_size) {
  if (out_size == 0) return 0;
  out[0] = '\0';
  if (url == NULL) return 0;
  const char *separator = strstr(url, "://");
  if (separator == NULL || separator == url) return 0;

  const char *authority = separator + 3;
  const char *end = authority + strcspn(authority, "/?#");
  const char *host = authority;
  for (const char *p = authority; p < end; p++) {
    if (*p == '@') host = p + 1; /* the last "@" ends the userinfo */
  }

  size_t host_length;
  if (host < end && *host == '[') {
    const char *close = memchr(host, ']', (size_t)(end - host));
    if (close == NULL) return 0;
    host_length = (size_t)(close - host) + 1;
  } else {
    const char *colon = memchr(host, ':', (size_t)(end - host));
    host_length = (size_t)((colon != NULL ? colon : end) - host);
  }
  if (host_length == 0 || host_length >= out_size) return 0;

  for (size_t i = 0; i < host_length; i++) out[i] = (char)tolower((unsigned char)host[i]);
  out[host_length] = '\0';
  return 1;
}
