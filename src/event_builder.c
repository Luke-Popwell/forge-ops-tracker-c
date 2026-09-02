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

/* How many lines of source to grab on either side of a frame's culprit line (see
 * forgeops_source_context_json), and the longest a single captured line is allowed to be before
 * getting truncated -- guards against a single pathological minified/generated line ballooning the
 * payload. ForgeOps itself re-truncates on arrival too, the same "don't just trust the SDK"
 * posture MAX_FRAMES already gets on the server side. */
#define CONTEXT_LINES 5
#define MAX_CONTEXT_LINE_LENGTH 500

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

/* Reads a single line (any length) from `f` into a newly-allocated, NUL-terminated buffer with the
 * trailing newline (and a preceding '\r', for CRLF files) stripped. Returns NULL at EOF with
 * nothing read, or on allocation failure -- indistinguishable from plain EOF to the caller, which
 * is fine: both just mean "stop reading, use whatever full lines were already collected." */
static char *read_line(FILE *f) {
  size_t capacity = 128;
  size_t length = 0;
  char *buf = malloc(capacity);
  if (buf == NULL) return NULL;

  int saw_any = 0;
  int c;
  while ((c = fgetc(f)) != EOF) {
    saw_any = 1;
    if (c == '\n') break;
    if (length + 1 >= capacity) {
      size_t new_capacity = capacity * 2;
      char *grown = realloc(buf, new_capacity);
      if (grown == NULL) {
        free(buf);
        return NULL;
      }
      buf = grown;
      capacity = new_capacity;
    }
    buf[length++] = (char)c;
  }
  if (!saw_any) {
    free(buf);
    return NULL;
  }

  if (length > 0 && buf[length - 1] == '\r') length--;
  buf[length] = '\0';
  return buf;
}

/* Returns a newly-allocated, possibly-truncated copy of `line` the caller must free (or NULL only
 * on allocation failure). */
static char *truncate_line(const char *line) {
  size_t len = strlen(line);
  if (len <= MAX_CONTEXT_LINE_LENGTH) return strdup(line);

  char *out = malloc(MAX_CONTEXT_LINE_LENGTH + 4); /* + "...\0" */
  if (out == NULL) return NULL;
  memcpy(out, line, MAX_CONTEXT_LINE_LENGTH);
  memcpy(out + MAX_CONTEXT_LINE_LENGTH, "...", 4); /* the 4th byte is the NUL */
  return out;
}

char *forgeops_source_context_json(const forgeops_configuration_t *config, int in_app, const char *file, long line) {
  if (config == NULL || !config->capture_source_context || !in_app) return NULL;
  if (file == NULL || file[0] == '\0' || line <= 0) return NULL;

  FILE *f = fopen(file, "r");
  if (f == NULL) return NULL;

  char **lines = NULL;
  size_t count = 0, capacity = 0;
  int alloc_failed = 0;

  for (;;) {
    char *one_line = read_line(f);
    if (one_line == NULL) break;

    if (count == capacity) {
      size_t new_capacity = capacity == 0 ? 64 : capacity * 2;
      char **grown = realloc(lines, new_capacity * sizeof(char *));
      if (grown == NULL) {
        free(one_line);
        alloc_failed = 1;
        break;
      }
      lines = grown;
      capacity = new_capacity;
    }
    lines[count++] = one_line;
  }
  int had_read_error = ferror(f);
  fclose(f);

  char *result = NULL;
  size_t index = (size_t)(line - 1);
  if (!alloc_failed && !had_read_error && index < count) {
    size_t from = index >= CONTEXT_LINES ? index - CONTEXT_LINES : 0;
    size_t to = index + CONTEXT_LINES;
    if (to > count - 1) to = count - 1;

    forgeops_strbuf_t ctx;
    if (forgeops_strbuf_init(&ctx, 128) == 0) {
      forgeops_strbuf_append_str(&ctx, ",\"context_line\":");
      char *culprit = truncate_line(lines[index]);
      json_append_string_or_null(&ctx, culprit);
      free(culprit);

      forgeops_strbuf_append_str(&ctx, ",\"pre_context\":[");
      for (size_t i = from; i < index; i++) {
        if (i > from) forgeops_strbuf_append(&ctx, ",", 1);
        char *pre = truncate_line(lines[i]);
        json_append_string_or_null(&ctx, pre);
        free(pre);
      }
      forgeops_strbuf_append_str(&ctx, "],\"post_context\":[");
      for (size_t i = index + 1; i <= to; i++) {
        if (i > index + 1) forgeops_strbuf_append(&ctx, ",", 1);
        char *post = truncate_line(lines[i]);
        json_append_string_or_null(&ctx, post);
        free(post);
      }
      forgeops_strbuf_append_str(&ctx, "]");
      result = ctx.data;
    }
  }

  for (size_t i = 0; i < count; i++) free(lines[i]);
  free(lines);
  return result;
}

static void append_backtrace_json(forgeops_strbuf_t *out, const forgeops_configuration_t *config) {
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
      if (config->scrub_pii) {
        scrubbed_image = forgeops_scrub_string(image);
        scrubbed_symbol = forgeops_scrub_string(symbol);
        if (scrubbed_image != NULL) image = scrubbed_image;
        if (scrubbed_symbol != NULL) symbol = scrubbed_symbol;
      }

      /* Always 0/-1: a compiled C binary's own image is indistinguishable from a system library's
       * by name alone (see README.md), and it carries no source line number at all -- so this
       * frame is never in_app and forgeops_source_context_json below always takes its own gated-off
       * return. Wired in anyway, exactly the way every other client in this repo wires its own
       * per-frame source context call, so this file is ready the moment a real file+line source
       * ever exists to offer it (see event_builder.h's own comment on forgeops_source_context_json). */
      int in_app = 0;
      long source_line = -1;

      if (wrote_any) forgeops_strbuf_append(out, ",", 1);
      wrote_any = 1;
      forgeops_strbuf_append_str(out, "{\"file\":");
      json_append_string_or_null(out, image);
      forgeops_strbuf_append_str(out, ",\"line\":null,\"method\":");
      json_append_string_or_null(out, symbol);
      forgeops_strbuf_append_str(out, ",\"in_app\":");
      forgeops_strbuf_append_str(out, in_app ? "true" : "false");

      char *context_json = forgeops_source_context_json(config, in_app, image, source_line);
      if (context_json != NULL) {
        forgeops_strbuf_append_str(out, context_json);
        free(context_json);
      }
      forgeops_strbuf_append(out, "}", 1);

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
  append_backtrace_json(&out, config);
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
