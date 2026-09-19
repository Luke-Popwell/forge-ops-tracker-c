#include "forgeops_tracker/signal_handler.h"

#include <execinfo.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include "forgeops_tracker/breadcrumbs.h"
#include "forgeops_tracker/forgeops_tracker.h"
#include "strbuf.h"

static const int FATAL_SIGNALS[] = {SIGABRT, SIGILL, SIGSEGV, SIGFPE, SIGBUS, SIGTRAP};
static const size_t FATAL_SIGNAL_COUNT = sizeof(FATAL_SIGNALS) / sizeof(FATAL_SIGNALS[0]);

/* Prepared once, at installation time, so the handler itself never allocates: see this file's
 * own header comment for why that matters here. */
static char crash_directory[PATH_MAX];

void forgeops_signal_handler_write_report(int signal_number) {
  char path[PATH_MAX];
  /* snprintf and time() aren't on POSIX's strict async-signal-safe list, but both are widely
   * relied on in practice by real-world signal handlers: this repo's own Objective-C/Swift
   * clients take the same pragmatic stance rather than hand-rolling an integer-to-string
   * formatter; documented here as a deliberate, informed tradeoff, not an oversight. */
  snprintf(path, sizeof(path), "%s/signal-%d-%ld.txt", crash_directory, signal_number, (long)time(NULL));

  int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
  if (fd >= 0) {
    const char *name = strsignal(signal_number);
    if (name != NULL) {
      write(fd, name, strlen(name));
      write(fd, "\n", 1);
    }

    void *frames[64];
    int frame_count = backtrace(frames, 64);
    /* backtrace_symbols_fd(), unlike backtrace_symbols(), writes directly to a file descriptor
     * without allocating a string array first: documented by both glibc and Darwin's own libc
     * as the signal-safer of the two for exactly this reason. */
    backtrace_symbols_fd(frames, frame_count, fd);

    /* This (crashing) thread's own breadcrumb trail, already encoded: see breadcrumbs.h. Only
     * write() and strlen() inside, no allocation. Last, after the backtrace, so a problem here can
     * never cost the backtrace itself. */
    forgeops_breadcrumbs_write_raw_to_fd(fd);

    close(fd);
  }
}

static void handle_fatal_signal(int signal_number) {
  forgeops_signal_handler_write_report(signal_number);

  /* Restore the default disposition and re-raise, rather than swallowing the signal: the
   * process should still actually crash the same way it would without this handler installed,
   * the same "rethrow, don't swallow" invariant every other framework integration in this repo
   * holds to. */
  signal(signal_number, SIG_DFL);
  raise(signal_number);
}

void forgeops_signal_handler_install(const char *crash_reports_directory) {
  mkdir(crash_reports_directory, 0755); /* best-effort: if this fails, the handler's own open() below will too, and just writes nothing; never worth crashing installation over */

  strncpy(crash_directory, crash_reports_directory, sizeof(crash_directory) - 1);
  crash_directory[sizeof(crash_directory) - 1] = '\0';

  struct sigaction action;
  memset(&action, 0, sizeof(action));
  action.sa_handler = handle_fatal_signal;
  sigemptyset(&action.sa_mask);
  action.sa_flags = 0;

  for (size_t i = 0; i < FATAL_SIGNAL_COUNT; i++) {
    sigaction(FATAL_SIGNALS[i], &action, NULL);
  }
}

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

char *forgeops_signal_handler_complete_json(const forgeops_configuration_t *config, const char *path) {
  FILE *f = fopen(path, "r");
  if (f == NULL) return NULL;

  char signal_name[256] = "unknown signal";
  if (fgets(signal_name, sizeof(signal_name), f) != NULL) {
    size_t len = strlen(signal_name);
    if (len > 0 && signal_name[len - 1] == '\n') signal_name[len - 1] = '\0';
  }

  forgeops_strbuf_t out;
  if (forgeops_strbuf_init(&out, 512) != 0) {
    fclose(f);
    return NULL;
  }

  forgeops_strbuf_append_str(&out, "{\"exception_class\":\"Signal: ");
  /* signal_name is appended raw here (not through json_append_escaped_string) only because it's
   * folded into a literal prefix: strsignal() output is always plain ASCII in practice, so this
   * is safe; every other string in this payload still goes through proper escaping. */
  for (const char *p = signal_name; *p != '\0'; p++) {
    if (*p == '"' || *p == '\\') forgeops_strbuf_append(&out, "\\", 1);
    forgeops_strbuf_append(&out, p, 1);
  }
  forgeops_strbuf_append_str(&out, "\",\"message\":\"Uncaught fatal signal: ");
  for (const char *p = signal_name; *p != '\0'; p++) {
    if (*p == '"' || *p == '\\') forgeops_strbuf_append(&out, "\\", 1);
    forgeops_strbuf_append(&out, p, 1);
  }
  forgeops_strbuf_append_str(&out, "\",\"backtrace\":[");

  /* Sized for a whole "#breadcrumb <json>\n" line (see breadcrumbs.h), not just a backtrace line:
   * a shorter buffer would split one entry across two fgets() calls. */
  char line[FORGEOPS_BREADCRUMB_SLOT_SIZE + 64];
  int wrote_any = 0;
  forgeops_strbuf_t crumbs;
  int have_crumbs = forgeops_strbuf_init(&crumbs, 256) == 0;
  size_t crumb_count = 0;
  while (fgets(line, sizeof(line), f) != NULL) {
    size_t len = strlen(line);
    if (len > 0 && line[len - 1] == '\n') line[--len] = '\0';
    if (len == 0) continue;

    if (strncmp(line, "#breadcrumb ", 12) == 0) {
      /* A line the process died in the middle of writing (or any corruption) would break the whole
       * payload's JSON: only take an entry that at least looks like a complete object. */
      const char *json = line + 12;
      size_t json_len = len - 12;
      if (have_crumbs && json_len >= 2 && json[0] == '{' && json[json_len - 1] == '}') {
        if (crumb_count > 0) forgeops_strbuf_append(&crumbs, ",", 1);
        forgeops_strbuf_append(&crumbs, json, json_len);
        crumb_count++;
      }
      continue;
    }

    if (wrote_any) forgeops_strbuf_append(&out, ",", 1);
    wrote_any = 1;
    forgeops_strbuf_append_str(&out, "{\"file\":null,\"line\":null,\"method\":");
    json_append_escaped_string(&out, line);
    forgeops_strbuf_append_str(&out, ",\"in_app\":false}");
  }
  fclose(f);

  forgeops_strbuf_append_str(&out, "],\"occurred_at\":");
  time_t now = time(NULL);
  struct tm utc;
  gmtime_r(&now, &utc);
  char formatted[32];
  strftime(formatted, sizeof(formatted), "%Y-%m-%dT%H:%M:%SZ", &utc);
  json_append_escaped_string(&out, formatted);

  forgeops_strbuf_append_str(&out, ",\"environment\":");
  json_append_string_or_null(&out, config->environment);
  forgeops_strbuf_append_str(&out, ",\"release\":");
  json_append_string_or_null(&out, config->release);
  forgeops_strbuf_append_str(&out, ",\"server_name\":");
  json_append_string_or_null(&out, config->server_name);
  forgeops_strbuf_append_str(&out, ",\"context\":{},\"tags\":{}");

  /* Filled in with whoever is "current" (on *this* thread) at upload time, not necessarily who
   * was signed in the moment the signal actually fired: the signal handler itself can never
   * safely read this (see this file's own top comment on what's safe to touch there), the same
   * "best effort, filled in later" treatment environment/release/server_name above already get.
   * See forgeops_tracker_current_user's own comment for why this is thread-local. */
  const char **user_keys = NULL;
  const char **user_values = NULL;
  size_t user_count = 0;
  forgeops_tracker_current_user(&user_keys, &user_values, &user_count);
  if (user_count > 0) {
    forgeops_strbuf_append_str(&out, ",\"user\":{");
    for (size_t i = 0; i < user_count; i++) {
      if (i > 0) forgeops_strbuf_append(&out, ",", 1);
      json_append_escaped_string(&out, user_keys[i]);
      forgeops_strbuf_append(&out, ":", 1);
      json_append_string_or_null(&out, user_values[i]);
    }
    forgeops_strbuf_append(&out, "}", 1);
  }

  /* The crashing thread's trail, dumped by the handler itself: the one field here that is exact
   * rather than filled in at upload time. Already scrubbed when each entry was added. */
  if (crumb_count > 0) {
    forgeops_strbuf_append_str(&out, ",\"breadcrumbs\":[");
    forgeops_strbuf_append_str(&out, crumbs.data);
    forgeops_strbuf_append(&out, "]", 1);
  }
  if (have_crumbs) free(crumbs.data);
  forgeops_strbuf_append(&out, "}", 1);

  return out.data;
}
