/*
 * Captures a real backtrace via backtrace()/backtrace_symbols() (POSIX, <execinfo.h>) and parses
 * each frame line with a regex -- e.g. "12  MyApp    0x0000000100abcd12 -[MyClass myMethod] + 82"
 * -- into an image name (closest available analog to "file"; a compiled C binary has no source
 * paths left in it) and a symbol name (closest analog to "method"). Verified directly against
 * real backtrace_symbols() output on Darwin before relying on this shape (see this SDK's own
 * README for the platform-specific caveat: the exact format is not POSIX-standardized, only
 * confirmed here and on Linux/glibc, which uses a compatible "image(symbol+offset) [address]"
 * layout close enough that this same regex still extracts a usable image/symbol pair from it).
 * This is the same regex-parsing approach this repo's own Objective-C client's FOTEventBuilder
 * uses for -callStackSymbols, just against a POSIX-level backtrace instead of an Objective-C
 * runtime one.
 *
 * `line` is always JSON null here for the same reason it is in the Objective-C client: that
 * information simply doesn't exist in a compiled, stripped binary at runtime.
 */
#include "forgeops_tracker/event_builder.h"

#include <execinfo.h>
#include <regex.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "forgeops_tracker/pii_scrubber.h"
#include "strbuf.h"

#define MAX_FRAMES 64

static void json_append_escaped_string(forgeops_strbuf_t *out, const char *value) {
  forgeops_strbuf_append(out, "\"", 1);
  for (const unsigned char *p = (const unsigned char *)value; *p != '\0'; p++) {
    switch (*p) {
      case '"': forgeops_strbuf_append(out, "\\\"", 2); break;
      case '\\': forgeops_strbuf_append(out, "\\\\", 2); break;
      case '\n': forgeops_strbuf_append(out, "\\n", 2); break;
      case '\r': forgeops_strbuf_append(out, "\\r", 2); break;
      case '\t': forgeops_strbuf_append(out, "\\t", 2); break;
      default:
        if (*p < 0x20) {
          char escaped[8];
          snprintf(escaped, sizeof(escaped), "\\u%04x", *p);
          forgeops_strbuf_append_str(out, escaped);
        } else {
          forgeops_strbuf_append(out, (const char *)p, 1);
        }
    }
  }
  forgeops_strbuf_append(out, "\"", 1);
}

static void json_append_string_or_null(forgeops_strbuf_t *out, const char *value) {
  if (value == NULL) {
    forgeops_strbuf_append_str(out, "null");
  } else {
    json_append_escaped_string(out, value);
  }
}

typedef struct {
  char *image;
  char *symbol;
} frame_t;

static void trim_trailing_space(char *s) {
  size_t len = strlen(s);
  while (len > 0 && (s[len - 1] == ' ' || s[len - 1] == '\t')) {
    s[--len] = '\0';
  }
}

static int parse_frame_line(const regex_t *re, const char *line, frame_t *frame) {
  regmatch_t groups[3];
  if (regexec(re, line, 3, groups, 0) != 0) return -1; /* an unparseable line is skipped, not an error -- see PHP's own client for the same philosophy */

  size_t image_len = (size_t)(groups[1].rm_eo - groups[1].rm_so);
  size_t symbol_len = (size_t)(groups[2].rm_eo - groups[2].rm_so);

  frame->image = malloc(image_len + 1);
  frame->symbol = malloc(symbol_len + 1);
  if (frame->image == NULL || frame->symbol == NULL) {
    free(frame->image);
    free(frame->symbol);
    return -1;
  }
  memcpy(frame->image, line + groups[1].rm_so, image_len);
  frame->image[image_len] = '\0';
  memcpy(frame->symbol, line + groups[2].rm_so, symbol_len);
  frame->symbol[symbol_len] = '\0';
  trim_trailing_space(frame->symbol);
  return 0;
}

static void append_backtrace_json(forgeops_strbuf_t *out, int scrub_pii) {
  void *addresses[MAX_FRAMES];
  int frame_count = backtrace(addresses, MAX_FRAMES);
  char **symbols = backtrace_symbols(addresses, frame_count);

  regex_t re;
  /* Same shape as this repo's own Objective-C client's FOTFrameRegex, adapted to POSIX ERE (see
   * this file's own top comment on \d/\s/\b). */
  int compiled = regcomp(&re, "^[[:space:]]*[0-9]+[[:space:]]+([^[:space:]]+)[[:space:]]+0x[0-9a-fA-F]+[[:space:]]+(.+)\\+[[:space:]]*[0-9]+[[:space:]]*$", REG_EXTENDED) == 0;

  forgeops_strbuf_append(out, "[", 1);
  int wrote_any = 0;
  if (compiled && symbols != NULL) {
    for (int i = 0; i < frame_count; i++) {
      frame_t frame = {0};
      if (parse_frame_line(&re, symbols[i], &frame) != 0) continue;

      char *image = frame.image;
      char *symbol = frame.symbol;
      char *scrubbed_image = NULL;
      char *scrubbed_symbol = NULL;
      if (scrub_pii) {
        scrubbed_image = forgeops_scrub_string(image);
        scrubbed_symbol = forgeops_scrub_string(symbol);
        if (scrubbed_image != NULL) image = scrubbed_image;
        if (scrubbed_symbol != NULL) symbol = scrubbed_symbol;
      }

      if (wrote_any) forgeops_strbuf_append(out, ",", 1);
      wrote_any = 1;
      forgeops_strbuf_append_str(out, "{\"file\":");
      json_append_string_or_null(out, image);
      forgeops_strbuf_append_str(out, ",\"line\":null,\"method\":");
      json_append_string_or_null(out, symbol);
      forgeops_strbuf_append_str(out, ",\"in_app\":false}"); /* a compiled C binary's own image is indistinguishable from a system library's by name alone -- see README.md */

      free(scrubbed_image);
      free(scrubbed_symbol);
      free(frame.image);
      free(frame.symbol);
    }
  }
  forgeops_strbuf_append(out, "]", 1);

  if (compiled) regfree(&re);
  free(symbols);
}

static void append_iso8601_now(forgeops_strbuf_t *out) {
  time_t now = time(NULL);
  struct tm utc;
  gmtime_r(&now, &utc);
  char formatted[32];
  strftime(formatted, sizeof(formatted), "%Y-%m-%dT%H:%M:%SZ", &utc);
  json_append_escaped_string(out, formatted);
}

char *forgeops_build_event_json(const forgeops_configuration_t *config, const char *exception_class, const char *message, const char **context_keys, const char **context_values, size_t context_count) {
  forgeops_strbuf_t out;
  if (forgeops_strbuf_init(&out, 512) != 0) return NULL;

  char *scrubbed_message = config->scrub_pii ? forgeops_scrub_string(message) : NULL;
  const char *message_to_write = scrubbed_message != NULL ? scrubbed_message : message;

  forgeops_strbuf_append_str(&out, "{\"exception_class\":");
  json_append_string_or_null(&out, exception_class);
  forgeops_strbuf_append_str(&out, ",\"message\":");
  json_append_string_or_null(&out, message_to_write);
  forgeops_strbuf_append_str(&out, ",\"backtrace\":");
  append_backtrace_json(&out, config->scrub_pii);
  forgeops_strbuf_append_str(&out, ",\"occurred_at\":");
  append_iso8601_now(&out);
  forgeops_strbuf_append_str(&out, ",\"environment\":");
  json_append_string_or_null(&out, config->environment);
  forgeops_strbuf_append_str(&out, ",\"release\":");
  json_append_string_or_null(&out, config->release);
  forgeops_strbuf_append_str(&out, ",\"server_name\":");
  json_append_string_or_null(&out, config->server_name);

  forgeops_strbuf_append_str(&out, ",\"context\":{");
  for (size_t i = 0; i < context_count; i++) {
    if (i > 0) forgeops_strbuf_append(&out, ",", 1);
    json_append_escaped_string(&out, context_keys[i]);
    forgeops_strbuf_append(&out, ":", 1);

    if (config->scrub_pii && forgeops_is_sensitive_key(context_keys[i])) {
      json_append_escaped_string(&out, FORGEOPS_REDACTED);
      continue;
    }
    char *scrubbed_value = config->scrub_pii ? forgeops_scrub_string(context_values[i]) : NULL;
    json_append_string_or_null(&out, scrubbed_value != NULL ? scrubbed_value : context_values[i]);
    free(scrubbed_value);
  }
  forgeops_strbuf_append_str(&out, "},\"tags\":{}}");

  free(scrubbed_message);
  return out.data;
}
