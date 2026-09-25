/*
 * A minimal, hand-rolled test runner rather than an external framework (Unity/CMocka/Criterion):
 * this SDK has exactly one real dependency (libcurl, for HTTP, see client.h's own comment
 * on why that one's unavoidable) and a test framework isn't, the same "only depend on what's
 * genuinely necessary" line every client in this repo draws.
 */
#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include <dirent.h>
#include <pthread.h>

#include "forgeops_tracker/breadcrumbs.h"
#include "forgeops_tracker/client.h"
#include "forgeops_tracker/configuration.h"
#include "forgeops_tracker/crash_store.h"
#include "forgeops_tracker/event_builder.h"
#include "forgeops_tracker/forgeops_tracker.h"
#ifndef __has_feature
#define __has_feature(x) 0
#endif
#include <math.h>
#include "forgeops_tracker/performance.h"
#include "forgeops_tracker/pii_scrubber.h"
#include "forgeops_tracker/reporter.h"
#include "forgeops_tracker/signal_handler.h"
#include "forgeops_tracker/spans.h"
#include "forgeops_tracker/trace_parent.h"

static int g_tests_run = 0;
static int g_tests_failed = 0;
static int g_current_test_failed = 0;

#define TEST(name) static void name(void)
#define RUN(name)                                  \
  do {                                              \
    g_tests_run++;                                  \
    g_current_test_failed = 0;                      \
    name();                                         \
    if (g_current_test_failed) {                    \
      g_tests_failed++;                             \
      printf("FAIL %s\n", #name);                   \
    } else {                                        \
      printf("PASS %s\n", #name);                   \
    }                                                \
  } while (0)

#define ASSERT_TRUE(cond)                                                          \
  do {                                                                             \
    if (!(cond)) {                                                                 \
      printf("  assertion failed at %s:%d: %s\n", __FILE__, __LINE__, #cond);      \
      g_current_test_failed = 1;                                                   \
      return;                                                                      \
    }                                                                              \
  } while (0)

#define ASSERT_STREQ(actual, expected)                                                                        \
  do {                                                                                                         \
    const char *_a = (actual);                                                                                \
    const char *_e = (expected);                                                                              \
    if (_a == NULL || _e == NULL || strcmp(_a, _e) != 0) {                                                     \
      printf("  assertion failed at %s:%d: expected %s == \"%s\", got \"%s\"\n", __FILE__, __LINE__, #actual, \
             _e ? _e : "(null)", _a ? _a : "(null)");                                                          \
      g_current_test_failed = 1;                                                                               \
      return;                                                                                                  \
    }                                                                                                          \
  } while (0)

#define ASSERT_NULL(v) ASSERT_TRUE((v) == NULL)
#define ASSERT_NOT_NULL(v) ASSERT_TRUE((v) != NULL)

/* ---- Configuration ------------------------------------------------------------------------- */

TEST(configuration_defaults) {
  forgeops_configuration_t *config = forgeops_configuration_create();
  ASSERT_NOT_NULL(config);
  ASSERT_STREQ(config->environment, "development");
  ASSERT_TRUE(config->scrub_pii == 1);
  ASSERT_TRUE(config->capture_source_context == 1);
  ASSERT_TRUE(config->timeout_seconds > 0);
  ASSERT_TRUE(config->enabled_environment_count == 2);
  forgeops_configuration_destroy(config);
}

TEST(configuration_api_key_and_ingestion_url) {
  forgeops_configuration_t *config = forgeops_configuration_create();
  forgeops_configuration_set_dsn(config, "https://abc123@forgeops.example/api/v1/events");

  char *api_key = forgeops_configuration_api_key(config);
  ASSERT_STREQ(api_key, "abc123");
  free(api_key);

  char *url = forgeops_configuration_ingestion_url(config);
  ASSERT_STREQ(url, "https://forgeops.example/api/v1/events");
  free(url);

  forgeops_configuration_destroy(config);
}

TEST(configuration_api_key_percent_decodes) {
  forgeops_configuration_t *config = forgeops_configuration_create();
  forgeops_configuration_set_dsn(config, "https://ab%2Fc@forgeops.example/api/v1/events");

  char *api_key = forgeops_configuration_api_key(config);
  ASSERT_STREQ(api_key, "ab/c");
  free(api_key);

  forgeops_configuration_destroy(config);
}

TEST(configuration_empty_or_malformed_dsn) {
  forgeops_configuration_t *config = forgeops_configuration_create();

  forgeops_configuration_set_dsn(config, "");
  ASSERT_NULL(forgeops_configuration_api_key(config));
  ASSERT_NULL(forgeops_configuration_ingestion_url(config));

  forgeops_configuration_set_dsn(config, "not-a-url");
  ASSERT_NULL(forgeops_configuration_api_key(config));
  ASSERT_NULL(forgeops_configuration_ingestion_url(config));

  forgeops_configuration_destroy(config);
}

TEST(configuration_dsn_with_no_userinfo) {
  forgeops_configuration_t *config = forgeops_configuration_create();
  forgeops_configuration_set_dsn(config, "https://forgeops.example/no-userinfo");

  ASSERT_NULL(forgeops_configuration_api_key(config));
  char *url = forgeops_configuration_ingestion_url(config);
  ASSERT_STREQ(url, "https://forgeops.example/no-userinfo");
  free(url);

  forgeops_configuration_destroy(config);
}

TEST(configuration_is_enabled) {
  forgeops_configuration_t *config = forgeops_configuration_create();
  forgeops_configuration_set_dsn(config, "https://key@host/path");

  free(config->environment);
  config->environment = strdup("production");
  ASSERT_TRUE(forgeops_configuration_is_enabled(config));

  free(config->environment);
  config->environment = strdup("development");
  ASSERT_TRUE(!forgeops_configuration_is_enabled(config));

  free(config->environment);
  config->environment = strdup("production");
  forgeops_configuration_set_dsn(config, NULL);
  ASSERT_TRUE(!forgeops_configuration_is_enabled(config));

  forgeops_configuration_destroy(config);
}

/* ---- PII scrubbing -------------------------------------------------------------------------- */

TEST(pii_scrub_email) {
  char *result = forgeops_scrub_string("contact user@example.com for help");
  ASSERT_STREQ(result, "contact [EMAIL FILTERED] for help");
  free(result);
}

TEST(pii_scrub_credit_card) {
  const char *input = "charged card 4242-4242-4242-4242 successfully";
  char *result = forgeops_scrub_string(input);
  ASSERT_TRUE(strcmp(result, input) != 0);
  free(result);
}

TEST(pii_leaves_ordinary_numeric_id_alone) {
  const char *input = "order id 1234567890123456";
  char *result = forgeops_scrub_string(input);
  ASSERT_STREQ(result, input);
  free(result);
}

TEST(pii_scrub_ssn) {
  char *result = forgeops_scrub_string("ssn on file: 123-45-6789");
  ASSERT_STREQ(result, "ssn on file: [SSN FILTERED]");
  free(result);
}

TEST(pii_scrub_known_token_formats) {
  /* Each fake credential below is split across adjacent string literals (which the C compiler
   * concatenates into one string at compile time, same runtime value either way), not one
   * contiguous literal: none of these were ever real, but GitHub's push protection flags the
   * shape regardless of context, and a single literal here would block pushing this file
   * anywhere. */
  const char *cases[] = {
      "Authorization: Bearer abc123DEF.456-xyz",
      "aws key " "AKIA" "ABCDEFGHIJKLMNOP" " in use",
      "stripe key " "sk_live_" "abcdefghijklmnop",
      "github token " "ghp_" "abcdefghijklmnopqrstuvwxyz0123456789",
      "jwt eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dQw4w9WgXcQ",
  };
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
    char *result = forgeops_scrub_string(cases[i]);
    ASSERT_TRUE(strcmp(result, cases[i]) != 0);
    free(result);
  }
}

TEST(pii_is_sensitive_key_ignores_case_and_punctuation) {
  ASSERT_TRUE(forgeops_is_sensitive_key("API_KEY"));
  ASSERT_TRUE(forgeops_is_sensitive_key("Api-Key"));
  ASSERT_TRUE(forgeops_is_sensitive_key("apiKey"));
  ASSERT_TRUE(forgeops_is_sensitive_key("X-Api-Key"));
  ASSERT_TRUE(!forgeops_is_sensitive_key("username"));
  ASSERT_TRUE(!forgeops_is_sensitive_key(NULL));
  ASSERT_TRUE(!forgeops_is_sensitive_key(""));
}

/* ---- Event builder --------------------------------------------------------------------------- */

TEST(event_builder_basic_fields) {
  forgeops_configuration_t *config = forgeops_configuration_create();
  free(config->environment);
  config->environment = strdup("production");
  free(config->release);
  config->release = strdup("abc123");
  free(config->server_name);
  config->server_name = strdup("web-1");

  const char *keys[] = {"order_id"};
  const char *values[] = {"42"};
  char *json = forgeops_build_event_json(config, "MyError", "boom", keys, values, 1, NULL, NULL, 0, NULL, 0);

  ASSERT_NOT_NULL(json);
  ASSERT_TRUE(strstr(json, "\"exception_class\":\"MyError\"") != NULL);
  ASSERT_TRUE(strstr(json, "\"message\":\"boom\"") != NULL);
  ASSERT_TRUE(strstr(json, "\"environment\":\"production\"") != NULL);
  ASSERT_TRUE(strstr(json, "\"release\":\"abc123\"") != NULL);
  ASSERT_TRUE(strstr(json, "\"server_name\":\"web-1\"") != NULL);
  ASSERT_TRUE(strstr(json, "\"order_id\":\"42\"") != NULL);
  ASSERT_TRUE(strstr(json, "\"backtrace\":[{") != NULL); /* a real, non-empty backtrace */
  ASSERT_TRUE(strstr(json, "\"sdk_name\":\"c\"") != NULL);
  ASSERT_TRUE(strstr(json, "\"user\"") == NULL); /* omitted entirely when none was given */

  free(json);
  forgeops_configuration_destroy(config);
}

TEST(event_builder_scrubs_message_and_context_by_default) {
  forgeops_configuration_t *config = forgeops_configuration_create();

  const char *keys[] = {"api_key"};
  const char *values[] = {"shh-secret"};
  char *json = forgeops_build_event_json(config, "MyError", "failed for user@example.com", keys, values, 1, NULL, NULL, 0, NULL, 0);

  ASSERT_TRUE(strstr(json, "failed for [EMAIL FILTERED]") != NULL);
  ASSERT_TRUE(strstr(json, "\"api_key\":\"[FILTERED]\"") != NULL);
  ASSERT_TRUE(strstr(json, "shh-secret") == NULL);

  free(json);
  forgeops_configuration_destroy(config);
}

TEST(event_builder_leaves_payload_untouched_when_scrub_pii_disabled) {
  forgeops_configuration_t *config = forgeops_configuration_create();
  config->scrub_pii = 0;

  char *json = forgeops_build_event_json(config, "MyError", "contact user@example.com", NULL, NULL, 0, NULL, NULL, 0, NULL, 0);

  ASSERT_TRUE(strstr(json, "contact user@example.com") != NULL);

  free(json);
  forgeops_configuration_destroy(config);
}

TEST(event_builder_never_attaches_source_context_in_practice) {
  /* Documents/exercises README.md's own claim: this SDK's real capture path never has a real
   * file+line to offer (a compiled binary carries an image name and a symbol, never a source
   * location), so every frame forgeops_build_event_json actually produces is in_app: false with no
   * line number: capture_source_context defaults on, but there's nothing for it to attach here. */
  forgeops_configuration_t *config = forgeops_configuration_create();
  ASSERT_TRUE(config->capture_source_context == 1);

  char *json = forgeops_build_event_json(config, "MyError", "boom", NULL, NULL, 0, NULL, NULL, 0, NULL, 0);

  ASSERT_NOT_NULL(json);
  ASSERT_TRUE(strstr(json, "\"in_app\":true") == NULL);
  ASSERT_TRUE(strstr(json, "context_line") == NULL);
  ASSERT_TRUE(strstr(json, "pre_context") == NULL);
  ASSERT_TRUE(strstr(json, "post_context") == NULL);

  free(json);
  forgeops_configuration_destroy(config);
}

TEST(event_builder_includes_the_user_when_given_one_never_scrubbed_even_though_its_an_email) {
  forgeops_configuration_t *config = forgeops_configuration_create();

  const char *user_keys[] = {"id", "email"};
  const char *user_values[] = {"42", "ada@example.com"};
  char *json = forgeops_build_event_json(config, "MyError", "boom", NULL, NULL, 0, user_keys, user_values, 2, NULL, 0);

  ASSERT_NOT_NULL(json);
  ASSERT_TRUE(strstr(json, "\"user\":{") != NULL);
  ASSERT_TRUE(strstr(json, "\"email\":\"ada@example.com\"") != NULL);

  free(json);
  forgeops_configuration_destroy(config);
}

/* ---- Source context (forgeops_source_context_json directly) ------------------------------------
 *
 * append_backtrace_json (exercised just above) never actually has a real file+line to hand this
 * function (see README.md's "Backtrace frames" section) so these tests call
 * forgeops_source_context_json directly, with a real temp file on disk (mkstemp, not a checked-in
 * fixture), the same way the reference gem's own spec suite exercises the equivalent Ruby method
 * directly against a real Tempfile. This is real, correct, independently-tested code; it's simply
 * never reached by this SDK's own two capture paths today.
 */

static char *write_temp_source_file(const char *contents) {
  char path_template[] = "/tmp/forgeops-c-tests-source-XXXXXX";
  int fd = mkstemp(path_template);
  if (fd < 0) return NULL;

  size_t len = strlen(contents);
  ssize_t written = write(fd, contents, len);
  close(fd);
  if (written < 0 || (size_t)written != len) {
    unlink(path_template);
    return NULL;
  }
  return strdup(path_template);
}

static char *numbered_lines(int count) {
  /* "line N" per line, newline-joined, no trailing newline: big enough for every count this
   * file's own tests actually use. */
  char *buf = malloc(4096);
  buf[0] = '\0';
  for (int i = 1; i <= count; i++) {
    char line[32];
    snprintf(line, sizeof(line), i < count ? "line %d\n" : "line %d", i);
    strcat(buf, line);
  }
  return buf;
}

TEST(source_context_attaches_window_around_the_culprit_line_by_default) {
  char *contents = numbered_lines(20);
  char *path = write_temp_source_file(contents);
  free(contents);
  ASSERT_NOT_NULL(path);

  forgeops_configuration_t *config = forgeops_configuration_create();
  char *json = forgeops_source_context_json(config, /* in_app */ 1, path, 10);

  ASSERT_NOT_NULL(json);
  ASSERT_TRUE(strstr(json, "\"context_line\":\"line 10\"") != NULL);
  ASSERT_TRUE(strstr(json, "\"pre_context\":[\"line 5\",\"line 6\",\"line 7\",\"line 8\",\"line 9\"]") != NULL);
  ASSERT_TRUE(strstr(json, "\"post_context\":[\"line 11\",\"line 12\",\"line 13\",\"line 14\",\"line 15\"]") != NULL);

  free(json);
  forgeops_configuration_destroy(config);
  unlink(path);
  free(path);
}

TEST(source_context_clamps_at_file_boundaries_rather_than_crashing) {
  char *contents = numbered_lines(3);
  char *path = write_temp_source_file(contents);
  free(contents);
  ASSERT_NOT_NULL(path);

  forgeops_configuration_t *config = forgeops_configuration_create();

  char *first = forgeops_source_context_json(config, 1, path, 1);
  ASSERT_NOT_NULL(first);
  ASSERT_TRUE(strstr(first, "\"pre_context\":[]") != NULL);
  ASSERT_TRUE(strstr(first, "\"post_context\":[\"line 2\",\"line 3\"]") != NULL);
  free(first);

  char *last = forgeops_source_context_json(config, 1, path, 3);
  ASSERT_NOT_NULL(last);
  ASSERT_TRUE(strstr(last, "\"pre_context\":[\"line 1\",\"line 2\"]") != NULL);
  ASSERT_TRUE(strstr(last, "\"post_context\":[]") != NULL);
  free(last);

  forgeops_configuration_destroy(config);
  unlink(path);
  free(path);
}

TEST(source_context_truncates_a_line_longer_than_max_context_line_length) {
  char overlong[601];
  memset(overlong, 'x', 600);
  overlong[600] = '\0';
  char *path = write_temp_source_file(overlong);
  ASSERT_NOT_NULL(path);

  forgeops_configuration_t *config = forgeops_configuration_create();
  char *json = forgeops_source_context_json(config, 1, path, 1);

  ASSERT_NOT_NULL(json);
  char expected[600] = "\"context_line\":\"";
  memset(expected + strlen(expected), 'x', 500);
  expected[strlen("\"context_line\":\"") + 500] = '\0';
  strcat(expected, "...\"");
  ASSERT_TRUE(strstr(json, expected) != NULL);

  free(json);
  forgeops_configuration_destroy(config);
  unlink(path);
  free(path);
}

TEST(source_context_returns_null_when_not_in_app) {
  char *contents = numbered_lines(20);
  char *path = write_temp_source_file(contents);
  free(contents);
  ASSERT_NOT_NULL(path);

  forgeops_configuration_t *config = forgeops_configuration_create();
  char *json = forgeops_source_context_json(config, /* in_app */ 0, path, 10);

  ASSERT_NULL(json);

  forgeops_configuration_destroy(config);
  unlink(path);
  free(path);
}

TEST(source_context_returns_null_when_capture_source_context_disabled) {
  char *contents = numbered_lines(20);
  char *path = write_temp_source_file(contents);
  free(contents);
  ASSERT_NOT_NULL(path);

  forgeops_configuration_t *config = forgeops_configuration_create();
  config->capture_source_context = 0;

  char *json = forgeops_source_context_json(config, 1, path, 10);

  ASSERT_NULL(json);

  forgeops_configuration_destroy(config);
  unlink(path);
  free(path);
}

TEST(source_context_returns_null_when_the_file_cannot_be_read) {
  forgeops_configuration_t *config = forgeops_configuration_create();

  char *json = forgeops_source_context_json(config, 1, "/tmp/forgeops-c-tests-does-not-exist.c", 1);

  ASSERT_NULL(json);

  forgeops_configuration_destroy(config);
}

/* ---- Crash store ------------------------------------------------------------------------------ */

static forgeops_configuration_t *new_config_with_temp_crash_dir(void) {
  forgeops_configuration_t *config = forgeops_configuration_create();
  free(config->crash_reports_directory);
  char path[256];
  snprintf(path, sizeof(path), "/tmp/forgeops-c-tests-%d-%ld", getpid(), (long)time(NULL));
  config->crash_reports_directory = strdup(path);
  return config;
}

static void remove_directory_recursive(const char *path) {
  char cmd[512];
  snprintf(cmd, sizeof(cmd), "rm -rf '%s'", path);
  if (system(cmd) != 0) { /* best-effort test cleanup; nothing to do if it fails */
  }
}

TEST(crash_store_write_and_read_round_trip) {
  forgeops_configuration_t *config = new_config_with_temp_crash_dir();

  ASSERT_TRUE(forgeops_crash_store_write(config, "{\"exception_class\":\"Boom\"}") == 0);

  char **paths = forgeops_crash_store_pending_paths(config);
  ASSERT_NOT_NULL(paths);
  ASSERT_NOT_NULL(paths[0]);
  ASSERT_NULL(paths[1]);

  char *contents = forgeops_crash_store_read(paths[0]);
  ASSERT_STREQ(contents, "{\"exception_class\":\"Boom\"}");

  free(contents);
  forgeops_crash_store_free_paths(paths);
  remove_directory_recursive(config->crash_reports_directory);
  forgeops_configuration_destroy(config);
}

TEST(crash_store_delete_removes_it) {
  forgeops_configuration_t *config = new_config_with_temp_crash_dir();
  forgeops_crash_store_write(config, "{}");

  char **paths = forgeops_crash_store_pending_paths(config);
  ASSERT_NOT_NULL(paths);
  forgeops_crash_store_delete(paths[0]);
  forgeops_crash_store_free_paths(paths);

  char **remaining = forgeops_crash_store_pending_paths(config);
  ASSERT_NULL(remaining);

  remove_directory_recursive(config->crash_reports_directory);
  forgeops_configuration_destroy(config);
}

TEST(crash_store_pending_paths_is_null_for_missing_directory) {
  forgeops_configuration_t *config = new_config_with_temp_crash_dir();
  ASSERT_NULL(forgeops_crash_store_pending_paths(config));
  forgeops_configuration_destroy(config);
}

/* ---- Client (real local HTTP server, forked off) ----------------------------------------------- */

static int start_test_server(int status_code, pid_t *child_pid_out) {
  int listen_fd = socket(AF_INET, SOCK_STREAM, 0);
  int reuse = 1;
  setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));

  struct sockaddr_in addr;
  memset(&addr, 0, sizeof(addr));
  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  addr.sin_port = 0;
  bind(listen_fd, (struct sockaddr *)&addr, sizeof(addr));
  listen(listen_fd, 1);

  socklen_t addr_len = sizeof(addr);
  getsockname(listen_fd, (struct sockaddr *)&addr, &addr_len);
  int port = ntohs(addr.sin_port);

  pid_t pid = fork();
  if (pid == 0) {
    int client_fd = accept(listen_fd, NULL, NULL);
    if (client_fd >= 0) {
      /* Must read the full request (headers *and* body) before responding: closing the
       * socket the moment the header terminator shows up (this test server's first draft) can
       * race the client still writing its POST body, which curl reports as a failed request
       * regardless of what status code this server meant to send. Content-Length is always
       * present here (forgeops_client_deliver always POSTs one), so this doesn't need to handle
       * chunked encoding. */
      char buf[8192];
      size_t total = 0;
      ssize_t n;
      char *header_end = NULL;
      while (header_end == NULL && (n = read(client_fd, buf + total, sizeof(buf) - total - 1)) > 0) {
        total += (size_t)n;
        buf[total] = '\0';
        header_end = strstr(buf, "\r\n\r\n");
        if (total >= sizeof(buf) - 1) break;
      }

      long content_length = 0;
      const char *cl_header = header_end != NULL ? strstr(buf, "Content-Length:") : NULL;
      if (cl_header != NULL) content_length = strtol(cl_header + strlen("Content-Length:"), NULL, 10);

      size_t body_already_read = header_end != NULL ? total - (size_t)(header_end + 4 - buf) : 0;
      while (header_end != NULL && (long)body_already_read < content_length) {
        n = read(client_fd, buf, sizeof(buf) - 1);
        if (n <= 0) break;
        body_already_read += (size_t)n;
      }

      char response[128];
      snprintf(response, sizeof(response), "HTTP/1.1 %d OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n", status_code);
      write(client_fd, response, strlen(response));
      close(client_fd);
    }
    close(listen_fd);
    _exit(0);
  }

  close(listen_fd);
  *child_pid_out = pid;
  return port;
}

TEST(client_delivers_on_2xx_response) {
  pid_t child;
  int port = start_test_server(202, &child);

  forgeops_configuration_t *config = forgeops_configuration_create();
  char dsn[256];
  snprintf(dsn, sizeof(dsn), "http://the-api-key@127.0.0.1:%d/api/v1/events", port);
  forgeops_configuration_set_dsn(config, dsn);

  int delivered = forgeops_client_deliver(config, "{\"message\":\"boom\"}");
  ASSERT_TRUE(delivered);

  waitpid(child, NULL, 0);
  forgeops_configuration_destroy(config);
}

TEST(client_returns_false_on_non_2xx_response) {
  pid_t child;
  int port = start_test_server(500, &child);

  forgeops_configuration_t *config = forgeops_configuration_create();
  char dsn[256];
  snprintf(dsn, sizeof(dsn), "http://key@127.0.0.1:%d/api/v1/events", port);
  forgeops_configuration_set_dsn(config, dsn);

  ASSERT_TRUE(!forgeops_client_deliver(config, "{}"));

  waitpid(child, NULL, 0);
  forgeops_configuration_destroy(config);
}

TEST(client_returns_false_with_no_dsn) {
  forgeops_configuration_t *config = forgeops_configuration_create();
  ASSERT_TRUE(!forgeops_client_deliver(config, "{}"));
  forgeops_configuration_destroy(config);
}

TEST(client_returns_false_when_unreachable) {
  forgeops_configuration_t *config = forgeops_configuration_create();
  forgeops_configuration_set_dsn(config, "http://key@127.0.0.1:1/events");
  config->timeout_seconds = 1;
  ASSERT_TRUE(!forgeops_client_deliver(config, "{}"));
  forgeops_configuration_destroy(config);
}

/* ---- Reporter ----------------------------------------------------------------------------------- */

TEST(reporter_report_does_nothing_when_disabled) {
  forgeops_configuration_t *config = new_config_with_temp_crash_dir();
  forgeops_configuration_set_dsn(config, "https://key@host/events");
  free(config->environment);
  config->environment = strdup("development"); /* not enabled */

  forgeops_report_error(config, "Boom", "bad", NULL, NULL, 0, NULL, NULL, 0, NULL, 0);

  ASSERT_NULL(forgeops_crash_store_pending_paths(config));
  remove_directory_recursive(config->crash_reports_directory);
  forgeops_configuration_destroy(config);
}

TEST(reporter_report_writes_a_pending_report_when_enabled) {
  forgeops_configuration_t *config = new_config_with_temp_crash_dir();
  forgeops_configuration_set_dsn(config, "https://key@host/events");
  free(config->environment);
  config->environment = strdup("production");

  forgeops_report_error(config, "Boom", "bad", NULL, NULL, 0, NULL, NULL, 0, NULL, 0);

  char **paths = forgeops_crash_store_pending_paths(config);
  ASSERT_NOT_NULL(paths);
  forgeops_crash_store_free_paths(paths);

  remove_directory_recursive(config->crash_reports_directory);
  forgeops_configuration_destroy(config);
}

TEST(reporter_report_includes_the_given_user_never_scrubbed_even_though_its_an_email) {
  forgeops_configuration_t *config = new_config_with_temp_crash_dir();
  forgeops_configuration_set_dsn(config, "https://key@host/events");
  free(config->environment);
  config->environment = strdup("production");

  const char *user_keys[] = {"id", "email"};
  const char *user_values[] = {"42", "alice@example.com"};
  forgeops_report_error(config, "Boom", "bad", NULL, NULL, 0, user_keys, user_values, 2, NULL, 0);

  char **paths = forgeops_crash_store_pending_paths(config);
  ASSERT_NOT_NULL(paths);
  char *contents = forgeops_crash_store_read(paths[0]);
  ASSERT_TRUE(strstr(contents, "alice@example.com") != NULL);

  free(contents);
  forgeops_crash_store_free_paths(paths);
  remove_directory_recursive(config->crash_reports_directory);
  forgeops_configuration_destroy(config);
}

TEST(reporter_upload_pending_reports_delivers_and_deletes_on_success) {
  pid_t child;
  int port = start_test_server(202, &child);

  forgeops_configuration_t *config = new_config_with_temp_crash_dir();
  char dsn[256];
  snprintf(dsn, sizeof(dsn), "http://key@127.0.0.1:%d/events", port);
  forgeops_configuration_set_dsn(config, dsn);
  free(config->environment);
  config->environment = strdup("production");

  forgeops_report_error(config, "Boom", "bad", NULL, NULL, 0, NULL, NULL, 0, NULL, 0);
  forgeops_upload_pending_reports(config);

  ASSERT_NULL(forgeops_crash_store_pending_paths(config));

  waitpid(child, NULL, 0);
  remove_directory_recursive(config->crash_reports_directory);
  forgeops_configuration_destroy(config);
}

TEST(reporter_upload_pending_reports_leaves_file_on_failure) {
  pid_t child;
  int port = start_test_server(500, &child);

  forgeops_configuration_t *config = new_config_with_temp_crash_dir();
  char dsn[256];
  snprintf(dsn, sizeof(dsn), "http://key@127.0.0.1:%d/events", port);
  forgeops_configuration_set_dsn(config, dsn);
  free(config->environment);
  config->environment = strdup("production");

  forgeops_report_error(config, "Boom", "bad", NULL, NULL, 0, NULL, NULL, 0, NULL, 0);
  forgeops_upload_pending_reports(config);

  char **paths = forgeops_crash_store_pending_paths(config);
  ASSERT_NOT_NULL(paths);
  forgeops_crash_store_free_paths(paths);

  waitpid(child, NULL, 0);
  remove_directory_recursive(config->crash_reports_directory);
  forgeops_configuration_destroy(config);
}

/* ---- Public facade -------------------------------------------------------------------------------- */

TEST(tracker_capture_error_delivers_through_the_full_stack) {
  pid_t child;
  int port = start_test_server(202, &child);

  forgeops_tracker_reset_for_testing();
  forgeops_configuration_t *config = forgeops_tracker_configuration();
  char dsn[256];
  snprintf(dsn, sizeof(dsn), "http://key@127.0.0.1:%d/events", port);
  forgeops_configuration_set_dsn(config, dsn);
  free(config->environment);
  config->environment = strdup("production");
  free(config->crash_reports_directory);
  char dir[256];
  snprintf(dir, sizeof(dir), "/tmp/forgeops-c-tracker-tests-%d", getpid());
  config->crash_reports_directory = strdup(dir);

  forgeops_tracker_capture_error("Boom", "bad", NULL, NULL, 0, NULL, NULL, 0);
  forgeops_tracker_upload_pending_reports();

  ASSERT_NULL(forgeops_crash_store_pending_paths(config));

  waitpid(child, NULL, 0);
  remove_directory_recursive(dir);
  forgeops_tracker_reset_for_testing();
}

TEST(tracker_set_user_attaches_the_user_to_a_later_capture_error_call) {
  forgeops_tracker_reset_for_testing();
  forgeops_configuration_t *config = forgeops_tracker_configuration();
  forgeops_configuration_set_dsn(config, "https://key@host/events");
  free(config->environment);
  config->environment = strdup("production");
  free(config->crash_reports_directory);
  char dir[256];
  snprintf(dir, sizeof(dir), "/tmp/forgeops-c-tracker-set-user-tests-%d", getpid());
  config->crash_reports_directory = strdup(dir);

  const char *user_keys[] = {"id", "email"};
  const char *user_values[] = {"42", "alice@example.com"};
  forgeops_tracker_set_user(user_keys, user_values, 2);
  forgeops_tracker_capture_error("Boom", "bad", NULL, NULL, 0, NULL, NULL, 0);

  char **paths = forgeops_crash_store_pending_paths(config);
  ASSERT_NOT_NULL(paths);
  char *contents = forgeops_crash_store_read(paths[0]);
  ASSERT_TRUE(strstr(contents, "alice@example.com") != NULL);

  free(contents);
  forgeops_crash_store_free_paths(paths);
  remove_directory_recursive(dir);
  forgeops_tracker_reset_for_testing();
}

TEST(tracker_an_explicit_user_argument_overrides_whatever_set_user_last_set) {
  forgeops_tracker_reset_for_testing();
  forgeops_configuration_t *config = forgeops_tracker_configuration();
  forgeops_configuration_set_dsn(config, "https://key@host/events");
  free(config->environment);
  config->environment = strdup("production");
  free(config->crash_reports_directory);
  char dir[256];
  snprintf(dir, sizeof(dir), "/tmp/forgeops-c-tracker-override-user-tests-%d", getpid());
  config->crash_reports_directory = strdup(dir);

  const char *set_keys[] = {"id"};
  const char *set_values[] = {"42"};
  forgeops_tracker_set_user(set_keys, set_values, 1);

  const char *override_keys[] = {"id"};
  const char *override_values[] = {"99"};
  forgeops_tracker_capture_error("Boom", "bad", NULL, NULL, 0, override_keys, override_values, 1);

  char **paths = forgeops_crash_store_pending_paths(config);
  ASSERT_NOT_NULL(paths);
  char *contents = forgeops_crash_store_read(paths[0]);
  ASSERT_TRUE(strstr(contents, "\"id\":\"99\"") != NULL);

  free(contents);
  forgeops_crash_store_free_paths(paths);
  remove_directory_recursive(dir);
  forgeops_tracker_reset_for_testing();
}

TEST(tracker_reset_for_testing_clears_the_current_user) {
  const char *user_keys[] = {"id"};
  const char *user_values[] = {"42"};
  forgeops_tracker_set_user(user_keys, user_values, 1);
  forgeops_tracker_reset_for_testing();

  forgeops_configuration_t *config = forgeops_tracker_configuration();
  forgeops_configuration_set_dsn(config, "https://key@host/events");
  free(config->environment);
  config->environment = strdup("production");
  free(config->crash_reports_directory);
  char dir[256];
  snprintf(dir, sizeof(dir), "/tmp/forgeops-c-tracker-reset-user-tests-%d", getpid());
  config->crash_reports_directory = strdup(dir);

  forgeops_tracker_capture_error("Boom", "bad", NULL, NULL, 0, NULL, NULL, 0);

  char **paths = forgeops_crash_store_pending_paths(config);
  ASSERT_NOT_NULL(paths);
  char *contents = forgeops_crash_store_read(paths[0]);
  ASSERT_TRUE(strstr(contents, "\"user\"") == NULL);

  free(contents);
  forgeops_crash_store_free_paths(paths);
  remove_directory_recursive(dir);
  forgeops_tracker_reset_for_testing();
}

TEST(tracker_install_handlers_is_idempotent) {
  forgeops_tracker_reset_for_testing();
  char dir[256];
  snprintf(dir, sizeof(dir), "/tmp/forgeops-c-tracker-install-tests-%d", getpid());
  forgeops_configuration_t *config = forgeops_tracker_configuration();
  free(config->crash_reports_directory);
  config->crash_reports_directory = strdup(dir);

  /* Must not crash on a second call. */
  forgeops_tracker_install_handlers();
  forgeops_tracker_install_handlers();

  remove_directory_recursive(dir);
  forgeops_tracker_reset_for_testing();
}

/* ---- Breadcrumbs -------------------------------------------------------------------------------- */

/* A tracker configured to write (not deliver) into a per-test directory, so a test can read back
 * exactly what forgeops_tracker_capture_error would have sent. */
static forgeops_configuration_t *breadcrumb_test_setup(const char *label, char *dir, size_t dir_size) {
  forgeops_tracker_reset_for_testing();
  forgeops_configuration_t *config = forgeops_tracker_configuration();
  forgeops_configuration_set_dsn(config, "https://key@host/events");
  free(config->environment);
  config->environment = strdup("production");
  free(config->crash_reports_directory);
  snprintf(dir, dir_size, "/tmp/forgeops-c-breadcrumb-%s-%d", label, getpid());
  config->crash_reports_directory = strdup(dir);
  return config;
}

/* The JSON of the one pending report capture_error wrote. Caller frees. */
static char *read_only_pending_report(const forgeops_configuration_t *config) {
  char **paths = forgeops_crash_store_pending_paths(config);
  if (paths == NULL) return NULL;
  char *contents = forgeops_crash_store_read(paths[0]);
  forgeops_crash_store_free_paths(paths);
  return contents;
}

TEST(breadcrumbs_add_attaches_the_trail_to_a_later_capture_error_call) {
  char dir[256];
  forgeops_configuration_t *config = breadcrumb_test_setup("attach", dir, sizeof(dir));

  const char *data_keys[] = {"order_id"};
  const char *data_values[] = {"42"};
  forgeops_tracker_add_breadcrumb("charging card", "payment", "info", data_keys, data_values, 1);
  forgeops_tracker_capture_error("Boom", "bad", NULL, NULL, 0, NULL, NULL, 0);

  char *contents = read_only_pending_report(config);
  ASSERT_NOT_NULL(contents);
  ASSERT_TRUE(strstr(contents, "\"breadcrumbs\":[{\"category\":\"payment\",\"message\":\"charging card\",\"level\":\"info\"") != NULL);
  ASSERT_TRUE(strstr(contents, "\"data\":{\"order_id\":\"42\"}") != NULL);

  free(contents);
  remove_directory_recursive(dir);
  forgeops_tracker_reset_for_testing();
}

TEST(breadcrumbs_null_category_and_level_default_to_custom_and_info) {
  size_t count = 0;
  forgeops_tracker_reset_for_testing();
  forgeops_tracker_add_breadcrumb("something happened", NULL, NULL, NULL, NULL, 0);

  char **crumbs = forgeops_breadcrumbs_snapshot(&count);
  ASSERT_TRUE(count == 1);
  ASSERT_TRUE(strstr(crumbs[0], "\"category\":\"custom\"") != NULL);
  ASSERT_TRUE(strstr(crumbs[0], "\"level\":\"info\"") != NULL);
  ASSERT_TRUE(strstr(crumbs[0], "\"data\":{}") != NULL);
  ASSERT_TRUE(strstr(crumbs[0], "\"timestamp\":\"20") != NULL);

  forgeops_breadcrumbs_free_snapshot(crumbs, count);
  forgeops_tracker_reset_for_testing();
}

TEST(breadcrumbs_keep_only_the_most_recent_max_breadcrumbs_dropping_the_oldest) {
  size_t count = 0;
  forgeops_tracker_reset_for_testing();
  forgeops_tracker_configuration()->max_breadcrumbs = 2;

  forgeops_tracker_add_breadcrumb("first", NULL, NULL, NULL, NULL, 0);
  forgeops_tracker_add_breadcrumb("second", NULL, NULL, NULL, NULL, 0);
  forgeops_tracker_add_breadcrumb("third", NULL, NULL, NULL, NULL, 0);

  char **crumbs = forgeops_breadcrumbs_snapshot(&count);
  ASSERT_TRUE(count == 2);
  ASSERT_TRUE(strstr(crumbs[0], "\"message\":\"second\"") != NULL);
  ASSERT_TRUE(strstr(crumbs[1], "\"message\":\"third\"") != NULL);

  forgeops_breadcrumbs_free_snapshot(crumbs, count);
  forgeops_tracker_reset_for_testing();
}

TEST(breadcrumbs_wrap_around_the_ring_many_times_and_stay_in_order) {
  size_t count = 0;
  forgeops_tracker_reset_for_testing();
  forgeops_tracker_configuration()->max_breadcrumbs = 3;

  for (int i = 0; i < 10; i++) {
    char message[16];
    snprintf(message, sizeof(message), "crumb %d", i);
    forgeops_tracker_add_breadcrumb(message, NULL, NULL, NULL, NULL, 0);
  }

  char **crumbs = forgeops_breadcrumbs_snapshot(&count);
  ASSERT_TRUE(count == 3);
  ASSERT_TRUE(strstr(crumbs[0], "crumb 7") != NULL);
  ASSERT_TRUE(strstr(crumbs[1], "crumb 8") != NULL);
  ASSERT_TRUE(strstr(crumbs[2], "crumb 9") != NULL);

  forgeops_breadcrumbs_free_snapshot(crumbs, count);
  forgeops_tracker_reset_for_testing();
}

TEST(breadcrumbs_record_nothing_when_track_breadcrumbs_is_off) {
  size_t count = 0;
  forgeops_tracker_reset_for_testing();
  forgeops_tracker_configuration()->track_breadcrumbs = 0;

  forgeops_tracker_add_breadcrumb("nope", NULL, NULL, NULL, NULL, 0);

  ASSERT_NULL(forgeops_breadcrumbs_snapshot(&count));
  ASSERT_TRUE(count == 0);
  forgeops_tracker_reset_for_testing();
}

TEST(breadcrumbs_clear_empties_the_trail_and_the_report_carries_no_breadcrumbs_key) {
  char dir[256];
  forgeops_configuration_t *config = breadcrumb_test_setup("clear", dir, sizeof(dir));

  forgeops_tracker_add_breadcrumb("first", NULL, NULL, NULL, NULL, 0);
  forgeops_tracker_clear_breadcrumbs();
  forgeops_tracker_capture_error("Boom", "bad", NULL, NULL, 0, NULL, NULL, 0);

  char *contents = read_only_pending_report(config);
  ASSERT_NOT_NULL(contents);
  ASSERT_TRUE(strstr(contents, "\"breadcrumbs\"") == NULL);

  free(contents);
  remove_directory_recursive(dir);
  forgeops_tracker_reset_for_testing();
}

TEST(breadcrumbs_scrub_message_and_data_when_added_but_not_category_or_level) {
  size_t count = 0;
  forgeops_tracker_reset_for_testing();

  const char *data_keys[] = {"email", "password"};
  const char *data_values[] = {"alice@example.com", "hunter2"};
  forgeops_tracker_add_breadcrumb("emailed alice@example.com", "custom", "info", data_keys, data_values, 2);

  char **crumbs = forgeops_breadcrumbs_snapshot(&count);
  ASSERT_TRUE(count == 1);
  ASSERT_TRUE(strstr(crumbs[0], "alice@example.com") == NULL);
  ASSERT_TRUE(strstr(crumbs[0], "hunter2") == NULL);
  ASSERT_TRUE(strstr(crumbs[0], "\"message\":\"emailed [EMAIL FILTERED]\"") != NULL);
  ASSERT_TRUE(strstr(crumbs[0], "\"password\":\"[FILTERED]\"") != NULL);
  ASSERT_TRUE(strstr(crumbs[0], "\"category\":\"custom\"") != NULL);

  forgeops_breadcrumbs_free_snapshot(crumbs, count);
  forgeops_tracker_reset_for_testing();
}

TEST(breadcrumbs_leave_values_untouched_when_scrub_pii_is_off) {
  size_t count = 0;
  forgeops_tracker_reset_for_testing();
  forgeops_tracker_configuration()->scrub_pii = 0;

  forgeops_tracker_add_breadcrumb("emailed alice@example.com", NULL, NULL, NULL, NULL, 0);

  char **crumbs = forgeops_breadcrumbs_snapshot(&count);
  ASSERT_TRUE(count == 1);
  ASSERT_TRUE(strstr(crumbs[0], "alice@example.com") != NULL);

  forgeops_breadcrumbs_free_snapshot(crumbs, count);
  forgeops_tracker_reset_for_testing();
}

TEST(breadcrumbs_escape_quotes_and_control_characters_into_valid_json) {
  size_t count = 0;
  forgeops_tracker_reset_for_testing();

  forgeops_tracker_add_breadcrumb("said \"hi\"\nthen left\\", NULL, NULL, NULL, NULL, 0);

  char **crumbs = forgeops_breadcrumbs_snapshot(&count);
  ASSERT_TRUE(count == 1);
  ASSERT_TRUE(strstr(crumbs[0], "\"message\":\"said \\\"hi\\\"\\nthen left\\\\\"") != NULL);

  forgeops_breadcrumbs_free_snapshot(crumbs, count);
  forgeops_tracker_reset_for_testing();
}

TEST(breadcrumbs_an_oversized_entry_is_shrunk_to_fit_its_slot_never_overflowing_it) {
  size_t count = 0;
  forgeops_tracker_reset_for_testing();

  char long_message[2000];
  memset(long_message, 'x', sizeof(long_message) - 1);
  long_message[sizeof(long_message) - 1] = '\0';
  char long_value[2000];
  memset(long_value, 'y', sizeof(long_value) - 1);
  long_value[sizeof(long_value) - 1] = '\0';
  const char *data_keys[] = {"a", "b", "c", "d", "e", "f"};
  const char *data_values[] = {long_value, long_value, long_value, long_value, long_value, long_value};
  forgeops_tracker_add_breadcrumb(long_message, NULL, NULL, data_keys, data_values, 6);

  char **crumbs = forgeops_breadcrumbs_snapshot(&count);
  ASSERT_TRUE(count == 1);
  ASSERT_TRUE(strlen(crumbs[0]) < FORGEOPS_BREADCRUMB_SLOT_SIZE);
  ASSERT_TRUE(crumbs[0][0] == '{' && crumbs[0][strlen(crumbs[0]) - 1] == '}');

  forgeops_breadcrumbs_free_snapshot(crumbs, count);
  forgeops_tracker_reset_for_testing();
}

TEST(breadcrumbs_truncation_never_cuts_a_multibyte_utf8_character_in_half) {
  size_t count = 0;
  forgeops_tracker_reset_for_testing();

  /* 200 three-byte characters = 600 bytes: over the 300-byte message cap, and 300 is a multiple
   * of 3 so this lands exactly on a boundary; one leading ASCII byte shifts it to mid-character. */
  char message[1 + 200 * 3 + 1];
  message[0] = 'a';
  for (int i = 0; i < 200; i++) memcpy(message + 1 + i * 3, "\xE2\x82\xAC", 3); /* the euro sign */
  message[sizeof(message) - 1] = '\0';
  forgeops_tracker_add_breadcrumb(message, NULL, NULL, NULL, NULL, 0);

  char **crumbs = forgeops_breadcrumbs_snapshot(&count);
  ASSERT_TRUE(count == 1);
  /* Every euro sign that made it in is whole: the byte after a lead byte 0xE2 is always 0x82. */
  for (const unsigned char *p = (const unsigned char *)crumbs[0]; *p != '\0'; p++) {
    if (*p == 0xE2) {
      ASSERT_TRUE(p[1] == 0x82 && p[2] == 0xAC);
    }
  }

  forgeops_breadcrumbs_free_snapshot(crumbs, count);
  forgeops_tracker_reset_for_testing();
}

static void *add_breadcrumb_on_another_thread(void *arg) {
  (void)arg;
  forgeops_tracker_add_breadcrumb("recorded on another thread", NULL, NULL, NULL, NULL, 0);
  size_t count = 0;
  char **crumbs = forgeops_breadcrumbs_snapshot(&count);
  int only_its_own = count == 1 && strstr(crumbs[0], "another thread") != NULL;
  forgeops_breadcrumbs_free_snapshot(crumbs, count);
  return only_its_own ? (void *)1 : (void *)0;
}

TEST(breadcrumbs_are_isolated_per_thread) {
  size_t count = 0;
  forgeops_tracker_reset_for_testing();
  forgeops_tracker_add_breadcrumb("recorded on the main thread", NULL, NULL, NULL, NULL, 0);

  pthread_t thread;
  ASSERT_TRUE(pthread_create(&thread, NULL, add_breadcrumb_on_another_thread, NULL) == 0);
  void *result = NULL;
  pthread_join(thread, &result);
  ASSERT_TRUE(result == (void *)1);

  char **crumbs = forgeops_breadcrumbs_snapshot(&count);
  ASSERT_TRUE(count == 1);
  ASSERT_TRUE(strstr(crumbs[0], "main thread") != NULL);

  forgeops_breadcrumbs_free_snapshot(crumbs, count);
  forgeops_tracker_reset_for_testing();
}

TEST(breadcrumbs_reset_for_testing_clears_the_trail) {
  size_t count = 0;
  forgeops_tracker_add_breadcrumb("leftover", NULL, NULL, NULL, NULL, 0);
  forgeops_tracker_reset_for_testing();

  ASSERT_NULL(forgeops_breadcrumbs_snapshot(&count));
}

TEST(breadcrumbs_event_builder_includes_the_given_trail_and_omits_the_key_when_empty) {
  forgeops_configuration_t *config = forgeops_configuration_create();
  free(config->environment);
  config->environment = strdup("production");
  const char *crumbs[] = {"{\"category\":\"a\",\"message\":\"m1\",\"level\":\"info\",\"timestamp\":\"t\",\"data\":{}}", "{\"category\":\"b\",\"message\":\"m2\",\"level\":\"info\",\"timestamp\":\"t\",\"data\":{}}"};

  char *with = forgeops_build_event_json(config, "MyError", "boom", NULL, NULL, 0, NULL, NULL, 0, crumbs, 2);
  char *without = forgeops_build_event_json(config, "MyError", "boom", NULL, NULL, 0, NULL, NULL, 0, NULL, 0);

  ASSERT_TRUE(strstr(with, "\"breadcrumbs\":[{\"category\":\"a\"") != NULL);
  ASSERT_TRUE(strstr(with, "},{\"category\":\"b\"") != NULL);
  ASSERT_TRUE(strstr(without, "\"breadcrumbs\"") == NULL);

  free(with);
  free(without);
  forgeops_configuration_destroy(config);
}

TEST(breadcrumbs_a_fatal_signals_raw_report_carries_the_crashing_threads_trail) {
  char dir[256];
  forgeops_configuration_t *config = breadcrumb_test_setup("signal", dir, sizeof(dir));

  /* Runs the handler's real report-writing body in-process (delivering an actual fatal signal
   * would crash the test process: see signal_handler.h), then completes the raw file the way the
   * next launch's upload does. */
  forgeops_signal_handler_install(dir);
  const char *data_keys[] = {"order_id"};
  const char *data_values[] = {"42"};
  forgeops_tracker_add_breadcrumb("charging card", "payment", "info", data_keys, data_values, 1);
  forgeops_tracker_add_breadcrumb("about to crash", NULL, "warning", NULL, NULL, 0);
  forgeops_signal_handler_write_report(11);

  DIR *directory = opendir(dir);
  ASSERT_NOT_NULL(directory);
  char raw_path[512] = {0};
  struct dirent *entry;
  while ((entry = readdir(directory)) != NULL) {
    if (strncmp(entry->d_name, "signal-11-", 10) == 0) snprintf(raw_path, sizeof(raw_path), "%s/%s", dir, entry->d_name);
  }
  closedir(directory);
  ASSERT_TRUE(raw_path[0] != '\0');

  char *json = forgeops_signal_handler_complete_json(config, raw_path);
  ASSERT_NOT_NULL(json);
  ASSERT_TRUE(strstr(json, "\"breadcrumbs\":[{\"category\":\"payment\",\"message\":\"charging card\"") != NULL);
  ASSERT_TRUE(strstr(json, "},{\"category\":\"custom\",\"message\":\"about to crash\",\"level\":\"warning\"") != NULL);
  ASSERT_TRUE(strstr(json, "\"data\":{\"order_id\":\"42\"}") != NULL);
  /* The breadcrumb lines are their own field, never mistaken for backtrace frames. */
  ASSERT_TRUE(strstr(json, "\"method\":\"#breadcrumb") == NULL);

  free(json);
  remove_directory_recursive(dir);
  forgeops_tracker_reset_for_testing();
}

TEST(breadcrumbs_a_raw_signal_report_with_no_trail_has_no_breadcrumbs_key) {
  char dir[256];
  forgeops_configuration_t *config = breadcrumb_test_setup("signal-empty", dir, sizeof(dir));

  forgeops_signal_handler_install(dir);
  forgeops_signal_handler_write_report(6);

  DIR *directory = opendir(dir);
  ASSERT_NOT_NULL(directory);
  char raw_path[512] = {0};
  struct dirent *entry;
  while ((entry = readdir(directory)) != NULL) {
    if (strncmp(entry->d_name, "signal-6-", 9) == 0) snprintf(raw_path, sizeof(raw_path), "%s/%s", dir, entry->d_name);
  }
  closedir(directory);

  char *json = forgeops_signal_handler_complete_json(config, raw_path);
  ASSERT_NOT_NULL(json);
  ASSERT_TRUE(strstr(json, "\"breadcrumbs\"") == NULL);

  free(json);
  remove_directory_recursive(dir);
  forgeops_tracker_reset_for_testing();
}

TEST(breadcrumbs_a_truncated_breadcrumb_line_in_a_raw_report_is_dropped_not_spliced_into_the_json) {
  char dir[256];
  forgeops_configuration_t *config = breadcrumb_test_setup("signal-truncated", dir, sizeof(dir));
  mkdir(dir, 0755);
  char raw_path[512];
  snprintf(raw_path, sizeof(raw_path), "%s/signal-11-1.txt", dir);
  FILE *f = fopen(raw_path, "w");
  ASSERT_NOT_NULL(f);
  fputs("Segmentation fault: 11\n", f);
  fputs("#breadcrumb {\"category\":\"custom\",\"message\":\"complete\",\"level\":\"info\",\"timestamp\":\"t\",\"data\":{}}\n", f);
  fputs("#breadcrumb {\"category\":\"custom\",\"message\":\"cut off mid-wri", f);
  fclose(f);

  char *json = forgeops_signal_handler_complete_json(config, raw_path);
  ASSERT_NOT_NULL(json);
  ASSERT_TRUE(strstr(json, "\"message\":\"complete\"") != NULL);
  ASSERT_TRUE(strstr(json, "cut off") == NULL);

  free(json);
  remove_directory_recursive(dir);
  forgeops_tracker_reset_for_testing();
}

/* ---- Performance monitoring ----------------------------------------------------------------------- */

/* Like start_test_server, but serves status_count connections then exits, writing each request's
 * body to body_path (overwriting), so a test can read back exactly what was delivered. */
static int start_capturing_test_server(const int *status_codes, size_t status_count, const char *body_path, pid_t *child_pid_out) {
  int listen_fd = socket(AF_INET, SOCK_STREAM, 0);
  int reuse = 1;
  setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));

  struct sockaddr_in addr;
  memset(&addr, 0, sizeof(addr));
  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  addr.sin_port = 0;
  bind(listen_fd, (struct sockaddr *)&addr, sizeof(addr));
  listen(listen_fd, 4);

  socklen_t addr_len = sizeof(addr);
  getsockname(listen_fd, (struct sockaddr *)&addr, &addr_len);
  int port = ntohs(addr.sin_port);

  pid_t pid = fork();
  if (pid == 0) {
    for (size_t served = 0; served < status_count; served++) {
      int client_fd = accept(listen_fd, NULL, NULL);
      if (client_fd < 0) break;

      static char buf[65536];
      size_t total = 0;
      char *header_end = NULL;
      long content_length = 0;
      ssize_t n;
      while ((n = read(client_fd, buf + total, sizeof(buf) - total - 1)) > 0) {
        total += (size_t)n;
        buf[total] = '\0';
        if (header_end == NULL) {
          header_end = strstr(buf, "\r\n\r\n");
          const char *cl_header = header_end != NULL ? strstr(buf, "Content-Length:") : NULL;
          if (cl_header != NULL) content_length = strtol(cl_header + strlen("Content-Length:"), NULL, 10);
        }
        if (header_end != NULL && (long)(total - (size_t)(header_end + 4 - buf)) >= content_length) break;
      }

      FILE *out = fopen(body_path, "w");
      if (out != NULL) {
        if (header_end != NULL) fwrite(header_end + 4, 1, total - (size_t)(header_end + 4 - buf), out);
        fclose(out);
      }

      char response[128];
      snprintf(response, sizeof(response), "HTTP/1.1 %d OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n", status_codes[served]);
      write(client_fd, response, strlen(response));
      close(client_fd);
    }
    close(listen_fd);
    _exit(0);
  }

  close(listen_fd);
  *child_pid_out = pid;
  return port;
}

static char *read_whole_file(const char *path) {
  FILE *f = fopen(path, "r");
  if (f == NULL) return NULL;
  char *contents = calloc(1, 65536);
  size_t n = fread(contents, 1, 65535, f);
  contents[n] = '\0';
  fclose(f);
  return contents;
}

/* An enabled tracker pointed at `port` (0 = nothing listening), flush interval long enough that no
 * test is ever flushed by the background thread unless it asks for that. */
static forgeops_configuration_t *performance_test_setup(int port) {
  forgeops_tracker_reset_for_testing();
  forgeops_configuration_t *config = forgeops_tracker_configuration();
  char dsn[256];
  snprintf(dsn, sizeof(dsn), "http://key@127.0.0.1:%d/api/v1/events", port == 0 ? 1 : port);
  forgeops_configuration_set_dsn(config, dsn);
  free(config->environment);
  config->environment = strdup("production");
  config->performance_flush_interval_seconds = 3600;
  config->timeout_seconds = 2;
  return config;
}

TEST(performance_record_buckets_by_transaction_name_with_count_sum_and_max) {
  performance_test_setup(0);
  unsigned long count;
  double sum, max;

  forgeops_tracker_record_performance("GET /users/:id", 10.0);
  forgeops_tracker_record_performance("GET /users/:id", 30.0);
  forgeops_tracker_record_performance("POST /orders", 5.0);

  ASSERT_TRUE(forgeops_performance_tally_for_testing("GET /users/:id", &count, &sum, &max));
  ASSERT_TRUE(count == 2 && sum == 40.0 && max == 30.0);
  ASSERT_TRUE(forgeops_performance_tally_for_testing("POST /orders", &count, &sum, &max));
  ASSERT_TRUE(count == 1 && sum == 5.0 && max == 5.0);

  forgeops_tracker_reset_for_testing();
}

TEST(performance_record_does_nothing_when_track_performance_is_off) {
  forgeops_configuration_t *config = performance_test_setup(0);
  config->track_performance = 0;
  unsigned long count;
  double sum, max;

  forgeops_tracker_record_performance("GET /x", 10.0);

  ASSERT_TRUE(!forgeops_performance_tally_for_testing("GET /x", &count, &sum, &max));
  forgeops_tracker_reset_for_testing();
}

TEST(performance_record_does_nothing_when_reporting_is_not_enabled_for_this_environment) {
  forgeops_configuration_t *config = performance_test_setup(0);
  free(config->environment);
  config->environment = strdup("development");
  unsigned long count;
  double sum, max;

  forgeops_tracker_record_performance("GET /x", 10.0);

  ASSERT_TRUE(!forgeops_performance_tally_for_testing("GET /x", &count, &sum, &max));
  forgeops_tracker_reset_for_testing();
}

TEST(performance_a_new_transaction_name_past_the_cap_is_dropped_but_existing_ones_keep_counting) {
  performance_test_setup(0);
  unsigned long count;
  double sum, max;

  for (int i = 0; i < FORGEOPS_PERFORMANCE_MAX_TRANSACTIONS + 25; i++) {
    char name[32];
    snprintf(name, sizeof(name), "name-%d", i);
    forgeops_tracker_record_performance(name, 1.0);
  }
  forgeops_tracker_record_performance("name-0", 1.0);

  ASSERT_TRUE(forgeops_performance_tally_for_testing("name-0", &count, &sum, &max) && count == 2);
  ASSERT_TRUE(forgeops_performance_tally_for_testing("name-499", &count, &sum, &max));
  ASSERT_TRUE(!forgeops_performance_tally_for_testing("name-500", &count, &sum, &max));
  forgeops_tracker_reset_for_testing();
}

TEST(performance_the_timer_records_how_long_the_bracketed_work_took) {
  performance_test_setup(0);
  unsigned long count;
  double sum, max;

  forgeops_performance_timer_t timer = forgeops_tracker_performance_start("timed");
  usleep(30000);
  forgeops_tracker_performance_stop(&timer);
  forgeops_tracker_performance_stop(&timer); /* a second stop on the same timer records nothing */
  forgeops_tracker_performance_stop(NULL);   /* and a NULL timer is safe */

  ASSERT_TRUE(forgeops_performance_tally_for_testing("timed", &count, &sum, &max));
  ASSERT_TRUE(count == 1);
  ASSERT_TRUE(sum >= 25.0 && sum < 1000.0);
  forgeops_tracker_reset_for_testing();
}

TEST(performance_flush_delivers_one_batch_to_performance_samples_and_empties_the_buckets) {
  char body_path[128];
  snprintf(body_path, sizeof(body_path), "/tmp/forgeops-c-perf-body-%d.json", getpid());
  pid_t child;
  const int statuses[] = {202};
  int port = start_capturing_test_server(statuses, 1, body_path, &child);
  forgeops_configuration_t *config = performance_test_setup(port);
  free(config->release);
  config->release = strdup("a1b2c3d");
  unsigned long count;
  double sum, max;

  forgeops_tracker_record_performance("GET /users/:id", 10.0);
  forgeops_tracker_record_performance("GET /users/:id", 30.0);
  forgeops_tracker_flush_performance();
  waitpid(child, NULL, 0);

  char *body = read_whole_file(body_path);
  ASSERT_NOT_NULL(body);
  ASSERT_TRUE(strncmp(body, "{\"samples\":[{", 13) == 0);
  ASSERT_TRUE(strstr(body, "\"transaction_name\":\"GET /users/:id\"") != NULL);
  ASSERT_TRUE(strstr(body, "\"request_count\":2") != NULL);
  ASSERT_TRUE(strstr(body, "\"duration_sum_ms\":40.000") != NULL);
  ASSERT_TRUE(strstr(body, "\"max_duration_ms\":30.000") != NULL);
  ASSERT_TRUE(strstr(body, "\"environment\":\"production\"") != NULL);
  ASSERT_TRUE(strstr(body, "\"release\":\"a1b2c3d\"") != NULL);
  ASSERT_TRUE(!forgeops_performance_tally_for_testing("GET /users/:id", &count, &sum, &max));

  free(body);
  remove(body_path);
  forgeops_tracker_reset_for_testing();
}

TEST(performance_flush_does_nothing_when_there_is_nothing_to_send) {
  performance_test_setup(0);

  forgeops_tracker_flush_performance(); /* nothing is listening: a delivery attempt would only fail, but none should be made */

  forgeops_tracker_reset_for_testing();
}

TEST(performance_a_failed_delivery_keeps_every_bucket_so_the_next_flush_carries_more) {
  char body_path[128];
  snprintf(body_path, sizeof(body_path), "/tmp/forgeops-c-perf-retry-%d.json", getpid());
  pid_t child;
  const int statuses[] = {500, 202};
  int port = start_capturing_test_server(statuses, 2, body_path, &child);
  performance_test_setup(port);
  unsigned long count;
  double sum, max;

  forgeops_tracker_record_performance("GET /x", 10.0);
  forgeops_tracker_flush_performance();
  ASSERT_TRUE(forgeops_performance_tally_for_testing("GET /x", &count, &sum, &max) && count == 1);

  forgeops_tracker_record_performance("GET /x", 20.0);
  forgeops_tracker_flush_performance();
  waitpid(child, NULL, 0);

  char *body = read_whole_file(body_path);
  ASSERT_NOT_NULL(body);
  ASSERT_TRUE(strstr(body, "\"request_count\":2") != NULL);
  ASSERT_TRUE(!forgeops_performance_tally_for_testing("GET /x", &count, &sum, &max));

  free(body);
  remove(body_path);
  forgeops_tracker_reset_for_testing();
}

static void record_during_delivery(void) {
  forgeops_tracker_record_performance("GET /x", 25.0);  /* same transaction, mid-delivery */
  forgeops_tracker_record_performance("GET /new", 7.0); /* a brand-new one, mid-delivery */
}

TEST(performance_a_record_that_lands_during_delivery_is_never_lost) {
  /* Deterministic reproduction of the race forgeops_performance_flush's own comment describes: the
   * before-delivery hook runs strictly between the snapshot and delivery succeeding, exactly where
   * a record from another thread could land. */
  char body_path[128];
  snprintf(body_path, sizeof(body_path), "/tmp/forgeops-c-perf-race-%d.json", getpid());
  pid_t child;
  const int statuses[] = {202};
  int port = start_capturing_test_server(statuses, 1, body_path, &child);
  performance_test_setup(port);
  unsigned long count;
  double sum, max;

  forgeops_tracker_record_performance("GET /x", 10.0);
  forgeops_performance_set_before_delivery_hook_for_testing(record_during_delivery);
  forgeops_tracker_flush_performance();
  waitpid(child, NULL, 0);

  ASSERT_TRUE(forgeops_performance_tally_for_testing("GET /x", &count, &sum, &max));
  ASSERT_TRUE(count == 1 && sum == 25.0 && max == 25.0);
  ASSERT_TRUE(forgeops_performance_tally_for_testing("GET /new", &count, &sum, &max));
  ASSERT_TRUE(count == 1 && sum == 7.0);

  remove(body_path);
  forgeops_tracker_reset_for_testing();
}

TEST(performance_the_background_thread_flushes_on_its_own_interval) {
  char body_path[128];
  snprintf(body_path, sizeof(body_path), "/tmp/forgeops-c-perf-thread-%d.json", getpid());
  pid_t child;
  const int statuses[] = {202};
  int port = start_capturing_test_server(statuses, 1, body_path, &child);
  forgeops_configuration_t *config = performance_test_setup(port);
  config->performance_flush_interval_seconds = 1;

  forgeops_tracker_record_performance("GET /x", 10.0);
  waitpid(child, NULL, 0); /* returns once the server has served the thread's own flush */

  char *body = read_whole_file(body_path);
  ASSERT_NOT_NULL(body);
  ASSERT_TRUE(strstr(body, "\"transaction_name\":\"GET /x\"") != NULL);

  free(body);
  remove(body_path);
  forgeops_tracker_reset_for_testing();
}

TEST(performance_samples_url_swaps_the_trailing_events_segment) {
  forgeops_configuration_t *config = forgeops_configuration_create();
  forgeops_configuration_set_dsn(config, "https://key@tracker.example.com/api/v1/events");

  char *url = forgeops_configuration_performance_samples_url(config);
  ASSERT_NOT_NULL(url);
  ASSERT_STREQ(url, "https://tracker.example.com/api/v1/performance_samples");
  free(url);

  forgeops_configuration_set_dsn(config, NULL);
  ASSERT_NULL(forgeops_configuration_performance_samples_url(config));
  forgeops_configuration_destroy(config);
}

TEST(performance_reset_for_testing_stops_the_thread_and_clears_every_bucket) {
  performance_test_setup(0);
  unsigned long count;
  double sum, max;
  forgeops_tracker_record_performance("GET /x", 10.0);

  forgeops_tracker_reset_for_testing();

  ASSERT_TRUE(!forgeops_performance_tally_for_testing("GET /x", &count, &sum, &max));
}

/* ---- Distributed tracing -------------------------------------------------------------------------- */

/* An enabled tracker pointed at `port` (0 = nothing listening), sending any trace at all (threshold 10ms). */
static forgeops_configuration_t *tracing_test_setup(int port) {
  forgeops_configuration_t *config = performance_test_setup(port);
  config->trace_capture_threshold_ms = 10;
  return config;
}

/* Copies the string value of "key" from the span object named span_name in body into out ("null" for a JSON null). */
static int span_field(const char *body, const char *span_name, const char *key, char *out, size_t out_size) {
  char needle[128];
  snprintf(needle, sizeof(needle), "\"name\":\"%s\"", span_name);
  const char *at = strstr(body, needle);
  if (at == NULL) return 0;
  const char *start = at;
  while (start > body && strncmp(start, "{\"span_id\":", 11) != 0) start--;
  snprintf(needle, sizeof(needle), "\"%s\":", key);
  const char *field = strstr(start, needle);
  if (field == NULL) return 0;
  field += strlen(needle);
  if (*field == '"') {
    field++;
    size_t n = 0;
    while (field[n] != '"' && n + 1 < out_size) { out[n] = field[n]; n++; }
    out[n] = '\0';
  } else {
    snprintf(out, out_size, "null");
  }
  return 1;
}

TEST(tracing_a_slow_trace_is_delivered_to_spans_with_nested_spans_and_the_wire_shape) {
  char body_path[128];
  snprintf(body_path, sizeof(body_path), "/tmp/forgeops-c-spans-body-%d.json", getpid());
  pid_t child;
  const int statuses[] = {202};
  int port = start_capturing_test_server(statuses, 1, body_path, &child);
  forgeops_configuration_t *config = tracing_test_setup(port);
  free(config->release);
  config->release = strdup("a1b2c3d");

  forgeops_trace_t trace = forgeops_tracker_trace_start();
  ASSERT_TRUE(trace.owns);
  forgeops_span_t outer = forgeops_tracker_span_start("charge", "service");
  forgeops_tracker_record_span("SELECT users", "database", 1700000000123LL, 3.0, NULL, NULL, 0);
  usleep(30000);
  const char *keys[] = {"order"};
  const char *values[] = {"42"};
  forgeops_tracker_span_stop_with_data(&outer, keys, values, 1);
  forgeops_tracker_record_span("sibling", "database", 1700000000123LL, 1.0, NULL, NULL, 0);
  forgeops_tracker_trace_stop(&trace, "GET /checkout");
  ASSERT_TRUE(!forgeops_spans_active_for_testing());
  waitpid(child, NULL, 0);

  char *body = read_whole_file(body_path);
  ASSERT_NOT_NULL(body);
  ASSERT_TRUE(strncmp(body, "{\"trace_id\":\"", 13) == 0);
  ASSERT_TRUE(body[13 + 32] == '"');
  char root_id[40], charge_id[40], parent[40], value[64];
  ASSERT_TRUE(span_field(body, "GET /checkout", "span_id", root_id, sizeof(root_id)));
  ASSERT_TRUE(strlen(root_id) == 16);
  ASSERT_TRUE(span_field(body, "GET /checkout", "parent_span_id", parent, sizeof(parent)) && strcmp(parent, "null") == 0);
  ASSERT_TRUE(span_field(body, "GET /checkout", "kind", value, sizeof(value)) && strcmp(value, "controller") == 0);
  ASSERT_TRUE(span_field(body, "charge", "span_id", charge_id, sizeof(charge_id)));
  ASSERT_TRUE(span_field(body, "charge", "parent_span_id", parent, sizeof(parent)) && strcmp(parent, root_id) == 0);
  ASSERT_TRUE(span_field(body, "SELECT users", "parent_span_id", parent, sizeof(parent)) && strcmp(parent, charge_id) == 0);
  ASSERT_TRUE(span_field(body, "sibling", "parent_span_id", parent, sizeof(parent)) && strcmp(parent, root_id) == 0);
  ASSERT_TRUE(span_field(body, "SELECT users", "started_at", value, sizeof(value)) && strcmp(value, "2023-11-14T22:13:20.123Z") == 0);
  ASSERT_TRUE(strstr(body, "\"environment\":\"production\"") != NULL);
  ASSERT_TRUE(strstr(body, "\"release\":\"a1b2c3d\"") != NULL);
  ASSERT_TRUE(strstr(body, "\"data\":{\"order\":\"42\"}") != NULL);

  free(body);
  remove(body_path);
  forgeops_tracker_reset_for_testing();
}

TEST(tracing_an_unknown_or_null_kind_is_sent_as_other_since_the_server_would_reject_the_whole_trace) {
  char body_path[128];
  snprintf(body_path, sizeof(body_path), "/tmp/forgeops-c-spans-kind-%d.json", getpid());
  pid_t child;
  const int statuses[] = {202};
  int port = start_capturing_test_server(statuses, 1, body_path, &child);
  tracing_test_setup(port);

  forgeops_trace_t trace = forgeops_tracker_trace_start();
  forgeops_tracker_record_span("q", "db", 1700000000000LL, 1.0, NULL, NULL, 0);
  forgeops_tracker_record_span("n", NULL, 1700000000000LL, 1.0, NULL, NULL, 0);
  forgeops_tracker_record_span("r", "database", 1700000000000LL, 1.0, NULL, NULL, 0);
  usleep(20000);
  forgeops_tracker_trace_stop(&trace, "root");
  waitpid(child, NULL, 0);

  char *body = read_whole_file(body_path);
  ASSERT_NOT_NULL(body);
  char kind[32];
  ASSERT_TRUE(span_field(body, "q", "kind", kind, sizeof(kind)) && strcmp(kind, "other") == 0);
  ASSERT_TRUE(span_field(body, "n", "kind", kind, sizeof(kind)) && strcmp(kind, "other") == 0);
  ASSERT_TRUE(span_field(body, "r", "kind", kind, sizeof(kind)) && strcmp(kind, "database") == 0);

  free(body);
  remove(body_path);
  forgeops_tracker_reset_for_testing();
}

TEST(tracing_a_trace_under_the_threshold_is_never_queued_and_leaves_nothing_open) {
  forgeops_configuration_t *config = tracing_test_setup(0);
  config->trace_capture_threshold_ms = 60000;

  forgeops_trace_t trace = forgeops_tracker_trace_start();
  ASSERT_TRUE(trace.owns);
  forgeops_tracker_record_span("q", "database", 1700000000000LL, 1.0, NULL, NULL, 0);
  forgeops_tracker_trace_stop(&trace, "GET /fast");

  ASSERT_TRUE(!forgeops_spans_active_for_testing());
  ASSERT_TRUE(!forgeops_spans_worker_started_for_testing());
  forgeops_tracker_reset_for_testing();
}

TEST(tracing_track_tracing_off_still_has_a_trace_id_but_never_sends_and_reporting_disabled_starts_nothing) {
  forgeops_configuration_t *config = tracing_test_setup(0);
  config->track_tracing = 0;

  forgeops_trace_t off = forgeops_tracker_trace_start();
  ASSERT_TRUE(off.owns);
  ASSERT_TRUE(forgeops_spans_active_for_testing());
  ASSERT_NOT_NULL(forgeops_tracker_current_trace_id());
  ASSERT_TRUE(strlen(forgeops_tracker_current_trace_id()) == 32);
  forgeops_span_t span = forgeops_tracker_span_start("x", "service");
  usleep(20000);
  forgeops_tracker_span_stop(&span);
  forgeops_tracker_trace_stop(&off, "root");
  ASSERT_TRUE(!forgeops_spans_active_for_testing());
  ASSERT_NULL(forgeops_tracker_current_trace_id());
  ASSERT_TRUE(!forgeops_spans_worker_started_for_testing());

  config->track_tracing = 1;
  free(config->environment);
  config->environment = strdup("development");
  forgeops_trace_t disabled = forgeops_tracker_trace_start();
  ASSERT_TRUE(!disabled.owns);
  ASSERT_TRUE(!forgeops_spans_active_for_testing());
  forgeops_span_t no_op = forgeops_tracker_span_start("x", "service");
  ASSERT_TRUE(!no_op.state.active);
  forgeops_tracker_span_stop(&no_op);
  forgeops_tracker_record_span("y", "database", 1700000000000LL, 1.0, NULL, NULL, 0);
  forgeops_tracker_trace_stop(&disabled, "root");
  forgeops_tracker_reset_for_testing();
}

TEST(tracing_a_span_outside_a_trace_is_a_harmless_no_op) {
  tracing_test_setup(0);
  forgeops_span_t span = forgeops_tracker_span_start("free", "service");
  ASSERT_TRUE(!span.state.active);
  forgeops_tracker_span_stop(&span);
  forgeops_tracker_span_stop(NULL);
  forgeops_tracker_trace_stop(NULL, "x");
  forgeops_tracker_reset_for_testing();
}

TEST(tracing_a_nested_trace_start_does_not_start_a_second_trace_and_its_stop_does_nothing) {
  tracing_test_setup(0);
  forgeops_trace_t outer = forgeops_tracker_trace_start();
  forgeops_trace_t inner = forgeops_tracker_trace_start();
  ASSERT_TRUE(outer.owns);
  ASSERT_TRUE(!inner.owns);

  forgeops_tracker_trace_stop(&inner, "inner");
  ASSERT_TRUE(forgeops_spans_active_for_testing());
  forgeops_tracker_trace_stop(&outer, "outer");
  ASSERT_TRUE(!forgeops_spans_active_for_testing());
  forgeops_tracker_trace_stop(&outer, "outer"); /* a second stop on the same trace does nothing */
  forgeops_tracker_reset_for_testing();
}

TEST(tracing_a_trace_holds_at_most_500_spans_including_the_root) {
  tracing_test_setup(0);
  forgeops_trace_t trace = forgeops_tracker_trace_start();
  for (int i = 0; i < 700; i++) forgeops_tracker_record_span("q", "database", 1700000000000LL, 1.0, NULL, NULL, 0);
  ASSERT_TRUE(forgeops_spans_count_for_testing() == 499);
  forgeops_tracker_trace_stop(&trace, "root");
  forgeops_tracker_reset_for_testing();
}

static void *check_no_trace_on_this_thread(void *result) {
  *(int *)result = forgeops_spans_active_for_testing() == 0;
  return NULL;
}

TEST(tracing_the_open_trace_is_per_thread) {
  tracing_test_setup(0);
  forgeops_trace_t trace = forgeops_tracker_trace_start();
  int other_thread_saw_no_trace = 0;
  pthread_t thread;
  pthread_create(&thread, NULL, check_no_trace_on_this_thread, &other_thread_saw_no_trace);
  pthread_join(thread, NULL);
  ASSERT_TRUE(other_thread_saw_no_trace);
  forgeops_tracker_trace_stop(&trace, "root");
  forgeops_tracker_reset_for_testing();
}

TEST(tracing_spans_url_swaps_the_trailing_events_segment) {
  tracing_test_setup(0);
  char *url = forgeops_configuration_spans_url(forgeops_tracker_configuration());
  ASSERT_NOT_NULL(url);
  ASSERT_TRUE(strcmp(url, "http://127.0.0.1:1/api/v1/spans") == 0);
  free(url);
  forgeops_tracker_reset_for_testing();
}

TEST(tracing_an_ended_span_state_is_cleared_so_a_second_stop_records_nothing) {
  tracing_test_setup(0);
  forgeops_trace_t trace = forgeops_tracker_trace_start();
  forgeops_span_t span = forgeops_tracker_span_start("once", "service");
  forgeops_tracker_span_stop(&span);
  forgeops_tracker_span_stop(&span);
  ASSERT_TRUE(forgeops_spans_count_for_testing() == 1);
  forgeops_tracker_trace_stop(&trace, "root");
  forgeops_tracker_reset_for_testing();
}

/* ---- Trace context (W3C traceparent) ------------------------------------------------------------ */

#define TP_TRACE_ID "4bf92f3577b34da6a3ce929d0e0e4736"
#define TP_SPAN_ID "00f067aa0ba902b7"

TEST(traceparent_parses_a_valid_version_00_header) {
  char trace_id[33] = {0}, parent[17] = {0};
  ASSERT_TRUE(forgeops_traceparent_parse("00-" TP_TRACE_ID "-" TP_SPAN_ID "-01", trace_id, parent));
  ASSERT_STREQ(trace_id, TP_TRACE_ID);
  ASSERT_STREQ(parent, TP_SPAN_ID);
  ASSERT_TRUE(forgeops_traceparent_parse("  00-" TP_TRACE_ID "-" TP_SPAN_ID "-00 ", trace_id, parent));
}

TEST(traceparent_rejects_anything_malformed) {
  const char *bad[] = {
    "",
    "garbage",
    "00-4BF92F3577B34DA6A3CE929D0E0E4736-" TP_SPAN_ID "-01",
    "00-" TP_TRACE_ID "-00F067AA0BA902B7-01",
    "ff-" TP_TRACE_ID "-" TP_SPAN_ID "-01",
    "00-00000000000000000000000000000000-" TP_SPAN_ID "-01",
    "00-" TP_TRACE_ID "-0000000000000000-01",
    "00-4bf92f3577b34da6a3ce929d0e0e473-" TP_SPAN_ID "-01",
    "00-" TP_TRACE_ID "-00f067aa0ba902b-01",
    "00_" TP_TRACE_ID "-" TP_SPAN_ID "-01",
    "00-" TP_TRACE_ID "-" TP_SPAN_ID "-1",
    "00-" TP_TRACE_ID "-" TP_SPAN_ID "-01-extra",
    "0g-" TP_TRACE_ID "-" TP_SPAN_ID "-01",
    "01-" TP_TRACE_ID "-" TP_SPAN_ID "-01x",
  };
  char trace_id[33] = "untouched", parent[17] = "untouched";
  for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
    if (forgeops_traceparent_parse(bad[i], trace_id, parent)) {
      printf("  accepted \"%s\"\n", bad[i]);
      ASSERT_TRUE(0);
    }
  }
  ASSERT_TRUE(!forgeops_traceparent_parse(NULL, trace_id, parent));
  ASSERT_STREQ(trace_id, "untouched");
}

TEST(traceparent_accepts_a_future_version_with_extra_fields) {
  char trace_id[33] = {0}, parent[17] = {0};
  ASSERT_TRUE(forgeops_traceparent_parse("01-" TP_TRACE_ID "-" TP_SPAN_ID "-01-what-comes-next", trace_id, parent));
  ASSERT_STREQ(trace_id, TP_TRACE_ID);
  ASSERT_TRUE(forgeops_traceparent_parse("01-" TP_TRACE_ID "-" TP_SPAN_ID "-01", trace_id, parent));
}

TEST(traceparent_builds_a_sampled_version_00_header_and_ids_are_lowercase_hex_never_all_zeros) {
  char header[FORGEOPS_TRACEPARENT_SIZE];
  forgeops_traceparent_build(TP_TRACE_ID, TP_SPAN_ID, header);
  ASSERT_STREQ(header, "00-" TP_TRACE_ID "-" TP_SPAN_ID "-01");

  char trace_id[33], span_id[17];
  forgeops_trace_random_id(trace_id, 32);
  forgeops_trace_random_id(span_id, 16);
  ASSERT_TRUE(strlen(trace_id) == 32 && strlen(span_id) == 16);
  ASSERT_TRUE(strspn(trace_id, "0123456789abcdef") == 32);
  ASSERT_TRUE(strspn(span_id, "0123456789abcdef") == 16);
  ASSERT_TRUE(strspn(trace_id, "0") < 32);
}

TEST(traceparent_url_host_extracts_just_the_lowercased_host) {
  char host[64];
  ASSERT_TRUE(forgeops_url_host("https://API.Example.com/orders/42?x=1", host, sizeof(host)));
  ASSERT_STREQ(host, "api.example.com");
  ASSERT_TRUE(forgeops_url_host("http://user:pw@example.com:8080/x", host, sizeof(host)));
  ASSERT_STREQ(host, "example.com");
  ASSERT_TRUE(forgeops_url_host("http://example.com?q=a@b", host, sizeof(host)));
  ASSERT_STREQ(host, "example.com");
  ASSERT_TRUE(forgeops_url_host("http://[::1]:3000/", host, sizeof(host)));
  ASSERT_STREQ(host, "[::1]");
  ASSERT_TRUE(!forgeops_url_host("example.com/no-scheme", host, sizeof(host)));
  ASSERT_TRUE(!forgeops_url_host("http:///path-only", host, sizeof(host)));
  ASSERT_TRUE(!forgeops_url_host(NULL, host, sizeof(host)));
  ASSERT_TRUE(!forgeops_url_host("https://a-host-far-too-long-for-the-buffer.example.com/", host, 8));
  ASSERT_STREQ(host, "");
}

TEST(trace_propagation_goes_to_every_host_by_default_and_nowhere_when_off) {
  forgeops_configuration_t *config = forgeops_configuration_create();
  ASSERT_TRUE(config->propagate_traces == 1);
  ASSERT_NULL(config->trace_propagation_targets);
  ASSERT_TRUE(forgeops_configuration_should_propagate_trace(config, "anything.example"));
  ASSERT_TRUE(forgeops_configuration_should_propagate_trace(config, NULL));
  config->propagate_traces = 0;
  ASSERT_TRUE(!forgeops_configuration_should_propagate_trace(config, "anything.example"));
  forgeops_configuration_destroy(config);
}

TEST(trace_propagation_targets_match_on_a_dot_boundary_ignoring_case_and_a_leading_dot) {
  forgeops_configuration_t *config = forgeops_configuration_create();
  char first[] = "Example.com";
  const char *targets[] = {first, ".internal.corp", ""};
  forgeops_configuration_set_trace_propagation_targets(config, targets, 3);
  first[0] = 'X'; /* copied: the caller's own strings don't matter after the call */
  ASSERT_TRUE(forgeops_configuration_should_propagate_trace(config, "example.com"));
  ASSERT_TRUE(forgeops_configuration_should_propagate_trace(config, "API.example.COM"));
  ASSERT_TRUE(forgeops_configuration_should_propagate_trace(config, "internal.corp"));
  ASSERT_TRUE(forgeops_configuration_should_propagate_trace(config, "db.internal.corp"));
  ASSERT_TRUE(!forgeops_configuration_should_propagate_trace(config, "badexample.com"));
  ASSERT_TRUE(!forgeops_configuration_should_propagate_trace(config, "example.com.evil.net"));
  ASSERT_TRUE(!forgeops_configuration_should_propagate_trace(config, "other.net"));
  ASSERT_TRUE(!forgeops_configuration_should_propagate_trace(config, "examplf.com")); /* same length as a target, not equal */
  ASSERT_TRUE(!forgeops_configuration_should_propagate_trace(config, NULL));

  forgeops_configuration_set_trace_propagation_targets(config, targets, 0);
  ASSERT_NOT_NULL(config->trace_propagation_targets);
  ASSERT_TRUE(!forgeops_configuration_should_propagate_trace(config, "example.com"));

  forgeops_configuration_set_trace_propagation_targets(config, NULL, 0);
  ASSERT_TRUE(forgeops_configuration_should_propagate_trace(config, "other.net"));
  forgeops_configuration_destroy(config);
}

TEST(trace_context_continuing_a_traceparent_keeps_its_id_and_the_http_span_names_itself_in_the_header) {
  char body_path[128];
  snprintf(body_path, sizeof(body_path), "/tmp/forgeops-c-traceparent-body-%d.json", getpid());
  pid_t child;
  const int statuses[] = {202};
  int port = start_capturing_test_server(statuses, 1, body_path, &child);
  tracing_test_setup(port);

  forgeops_trace_t trace = forgeops_tracker_trace_start_with_traceparent("00-" TP_TRACE_ID "-" TP_SPAN_ID "-01");
  ASSERT_TRUE(trace.owns);
  ASSERT_STREQ(forgeops_tracker_current_trace_id(), TP_TRACE_ID);
  forgeops_http_span_t http = forgeops_tracker_http_span_start("post", "https://Payments.example.com/charges/42?token=secret");
  ASSERT_TRUE(strncmp(http.traceparent, "00-" TP_TRACE_ID "-", 36) == 0);
  ASSERT_TRUE(strncmp(http.traceparent + 36, http.state.id, 16) == 0); /* the span's own id, then "-01" */
  ASSERT_STREQ(http.traceparent + 52, "-01");
  char expected_header[FORGEOPS_TRACEPARENT_HEADER_LINE_SIZE];
  snprintf(expected_header, sizeof(expected_header), "traceparent: %s", http.traceparent);
  ASSERT_STREQ(http.header, expected_header);
  forgeops_http_span_t copy = http; /* a copied struct stops the same span */
  usleep(20000);
  forgeops_tracker_http_span_stop(&copy);
  forgeops_tracker_trace_stop(&trace, "POST /orders");
  waitpid(child, NULL, 0);

  char *body = read_whole_file(body_path);
  ASSERT_NOT_NULL(body);
  ASSERT_TRUE(strncmp(body, "{\"trace_id\":\"" TP_TRACE_ID "\"", 13 + 32 + 1) == 0);
  char value[64], root_id[40];
  ASSERT_TRUE(span_field(body, "POST /orders", "parent_span_id", value, sizeof(value)) && strcmp(value, TP_SPAN_ID) == 0);
  ASSERT_TRUE(span_field(body, "POST /orders", "span_id", root_id, sizeof(root_id)));
  ASSERT_TRUE(span_field(body, "POST payments.example.com", "span_id", value, sizeof(value)) && strcmp(value, http.state.id) == 0);
  ASSERT_TRUE(span_field(body, "POST payments.example.com", "parent_span_id", value, sizeof(value)) && strcmp(value, root_id) == 0);
  ASSERT_TRUE(span_field(body, "POST payments.example.com", "kind", value, sizeof(value)) && strcmp(value, "http") == 0);
  ASSERT_TRUE(strstr(body, "secret") == NULL && strstr(body, "/charges") == NULL);

  free(body);
  remove(body_path);
  forgeops_tracker_reset_for_testing();
}

TEST(trace_context_a_missing_or_malformed_traceparent_starts_a_fresh_trace) {
  tracing_test_setup(0);
  forgeops_trace_t trace = forgeops_tracker_trace_start_with_traceparent("00-nope");
  ASSERT_TRUE(trace.owns);
  ASSERT_NOT_NULL(forgeops_tracker_current_trace_id());
  ASSERT_TRUE(strcmp(forgeops_tracker_current_trace_id(), TP_TRACE_ID) != 0);
  ASSERT_TRUE(strlen(forgeops_tracker_current_trace_id()) == 32);
  /* ignored inside an already-open trace */
  forgeops_trace_t inner = forgeops_tracker_trace_start_with_traceparent("00-" TP_TRACE_ID "-" TP_SPAN_ID "-01");
  ASSERT_TRUE(!inner.owns);
  ASSERT_TRUE(strcmp(forgeops_tracker_current_trace_id(), TP_TRACE_ID) != 0);
  forgeops_tracker_trace_stop(&trace, "root");
  forgeops_tracker_reset_for_testing();
}

TEST(trace_context_no_header_outside_a_trace_off_target_or_with_propagation_off_but_the_span_still_records) {
  forgeops_configuration_t *config = tracing_test_setup(0);
  forgeops_http_span_t outside = forgeops_tracker_http_span_start("GET", "https://api.example.com/");
  ASSERT_STREQ(outside.traceparent, "");
  ASSERT_STREQ(outside.header, "");
  ASSERT_TRUE(!outside.state.active);
  forgeops_tracker_http_span_stop(&outside);
  forgeops_tracker_http_span_stop(NULL);

  const char *targets[] = {"example.com"};
  forgeops_configuration_set_trace_propagation_targets(config, targets, 1);
  forgeops_trace_t trace = forgeops_tracker_trace_start();
  forgeops_http_span_t off_target = forgeops_tracker_http_span_start("GET", "https://badexample.com/");
  ASSERT_STREQ(off_target.traceparent, "");
  ASSERT_TRUE(off_target.state.active);
  forgeops_tracker_http_span_stop(&off_target);
  forgeops_http_span_t on_target = forgeops_tracker_http_span_start("GET", "https://api.example.com/");
  ASSERT_TRUE(on_target.traceparent[0] != '\0');
  forgeops_tracker_http_span_stop(&on_target);
  forgeops_http_span_t no_host = forgeops_tracker_http_span_start(NULL, "not a url");
  ASSERT_STREQ(no_host.name, "GET unknown");
  ASSERT_STREQ(no_host.traceparent, "");
  forgeops_tracker_http_span_stop(&no_host);

  config->propagate_traces = 0;
  forgeops_configuration_set_trace_propagation_targets(config, NULL, 0);
  forgeops_http_span_t off = forgeops_tracker_http_span_start("GET", "https://api.example.com/");
  ASSERT_STREQ(off.traceparent, "");
  forgeops_tracker_http_span_stop(&off);
  ASSERT_TRUE(forgeops_spans_count_for_testing() == 4);
  forgeops_tracker_trace_stop(&trace, "root");
  forgeops_tracker_reset_for_testing();
}

TEST(trace_context_an_error_captured_inside_a_trace_carries_its_id_even_with_track_tracing_off) {
  char dir[256];
  forgeops_configuration_t *config = breadcrumb_test_setup("trace-id", dir, sizeof(dir));
  config->track_tracing = 0;

  forgeops_trace_t trace = forgeops_tracker_trace_start_with_traceparent("00-" TP_TRACE_ID "-" TP_SPAN_ID "-01");
  forgeops_tracker_capture_error("Boom", "bad", NULL, NULL, 0, NULL, NULL, 0);
  forgeops_tracker_trace_stop(&trace, "POST /orders");

  char *contents = read_only_pending_report(config);
  ASSERT_NOT_NULL(contents);
  ASSERT_TRUE(strstr(contents, ",\"trace_id\":\"" TP_TRACE_ID "\"}") != NULL);
  free(contents);
  remove_directory_recursive(dir);

  /* outside a trace, no trace_id key at all */
  config = breadcrumb_test_setup("no-trace-id", dir, sizeof(dir));
  forgeops_tracker_capture_error("Boom", "bad", NULL, NULL, 0, NULL, NULL, 0);
  contents = read_only_pending_report(config);
  ASSERT_NOT_NULL(contents);
  ASSERT_TRUE(strstr(contents, "\"trace_id\"") == NULL);
  free(contents);
  remove_directory_recursive(dir);
  forgeops_tracker_reset_for_testing();
}

TEST(trace_context_a_fatal_signal_inside_a_trace_carries_its_id) {
  char dir[256];
  forgeops_configuration_t *config = breadcrumb_test_setup("signal-trace", dir, sizeof(dir));
  forgeops_signal_handler_install(dir);

  forgeops_trace_t trace = forgeops_tracker_trace_start_with_traceparent("00-" TP_TRACE_ID "-" TP_SPAN_ID "-01");
  forgeops_tracker_add_breadcrumb("about to crash", NULL, NULL, NULL, NULL, 0);
  forgeops_signal_handler_write_report(11);
  forgeops_tracker_trace_stop(&trace, "root");

  DIR *directory = opendir(dir);
  ASSERT_NOT_NULL(directory);
  char raw_path[512] = {0};
  struct dirent *entry;
  while ((entry = readdir(directory)) != NULL) {
    if (strncmp(entry->d_name, "signal-11-", 10) == 0) snprintf(raw_path, sizeof(raw_path), "%s/%s", dir, entry->d_name);
  }
  closedir(directory);
  ASSERT_TRUE(raw_path[0] != '\0');

  char *json = forgeops_signal_handler_complete_json(config, raw_path);
  ASSERT_NOT_NULL(json);
  ASSERT_TRUE(strstr(json, ",\"trace_id\":\"" TP_TRACE_ID "\"}") != NULL);
  ASSERT_TRUE(strstr(json, "\"message\":\"about to crash\"") != NULL);
  /* The trace id line is its own field, never mistaken for a backtrace frame. */
  ASSERT_TRUE(strstr(json, "\"method\":\"#trace_id") == NULL);

  free(json);
  remove_directory_recursive(dir);
  forgeops_tracker_reset_for_testing();
}

TEST(trace_context_a_cut_off_trace_id_line_in_a_raw_report_is_dropped) {
  char dir[256];
  forgeops_configuration_t *config = breadcrumb_test_setup("signal-trace-cut", dir, sizeof(dir));
  mkdir(dir, 0755);
  char raw_path[512];
  snprintf(raw_path, sizeof(raw_path), "%s/signal-11-1.txt", dir);
  FILE *f = fopen(raw_path, "w");
  ASSERT_NOT_NULL(f);
  fputs("Segmentation fault\n0 app 0x1 main + 1\n#trace_id 4bf92f3577b34da6\n", f);
  fclose(f);

  char *json = forgeops_signal_handler_complete_json(config, raw_path);
  ASSERT_NOT_NULL(json);
  ASSERT_TRUE(strstr(json, "\"trace_id\"") == NULL);
  ASSERT_TRUE(strstr(json, "#trace_id") == NULL);

  free(json);
  remove_directory_recursive(dir);
  forgeops_tracker_reset_for_testing();
}

/* ---- Custom metrics and infrastructure monitoring ------------------------------------------------- */

static forgeops_configuration_t *metrics_test_setup(int port) {
  forgeops_configuration_t *config = performance_test_setup(port);
  config->metric_flush_interval_seconds = 3600;
  config->infrastructure_metric_flush_interval_seconds = 3600;
  free(config->server_name);
  config->server_name = strdup("web-1");
  free(config->release);
  config->release = strdup("a1b2c3d");
  return config;
}

TEST(metrics_flush_delivers_every_entry_as_one_batch_to_custom_metrics_with_the_wire_shape) {
  char body_path[128];
  snprintf(body_path, sizeof(body_path), "/tmp/forgeops-c-metrics-body-%d.json", getpid());
  pid_t child;
  const int statuses[] = {202};
  int port = start_capturing_test_server(statuses, 1, body_path, &child);
  metrics_test_setup(port);

  forgeops_tracker_capture_metric("signup", 1.0);
  forgeops_tracker_capture_metric("payment", 49.5);
  forgeops_tracker_capture_metric("refund", -12.0);
  ASSERT_TRUE(forgeops_metrics_count_for_testing(FORGEOPS_METRIC_CUSTOM) == 3);
  forgeops_tracker_flush_metrics();
  waitpid(child, NULL, 0);

  char *body = read_whole_file(body_path);
  ASSERT_NOT_NULL(body);
  ASSERT_TRUE(strncmp(body, "{\"metrics\":[{\"metric_name\":\"signup\",\"value\":1,", 44) == 0);
  ASSERT_TRUE(strstr(body, "\"metric_name\":\"payment\",\"value\":49.5,") != NULL);
  ASSERT_TRUE(strstr(body, "\"value\":-12,") != NULL);
  ASSERT_TRUE(strstr(body, "\"environment\":\"production\"") != NULL);
  ASSERT_TRUE(strstr(body, "\"release\":\"a1b2c3d\"") != NULL);
  const char *stamp = strstr(body, "\"recorded_at\":\"");
  ASSERT_NOT_NULL(stamp);
  ASSERT_TRUE(stamp[15 + 19] == 'Z' && stamp[15 + 10] == 'T');
  ASSERT_TRUE(forgeops_metrics_count_for_testing(FORGEOPS_METRIC_CUSTOM) == 0);

  free(body);
  remove(body_path);
  forgeops_tracker_reset_for_testing();
}

TEST(metrics_infrastructure_readings_go_to_their_own_endpoint_with_an_explicit_or_default_hostname) {
  char body_path[128];
  snprintf(body_path, sizeof(body_path), "/tmp/forgeops-c-infra-body-%d.json", getpid());
  pid_t child;
  const int statuses[] = {202};
  int port = start_capturing_test_server(statuses, 1, body_path, &child);
  metrics_test_setup(port);

  forgeops_tracker_capture_infrastructure_metric("cpu", 0.42, "db-1");
  forgeops_tracker_capture_infrastructure_metric("memory", 0.7, NULL);
  ASSERT_TRUE(forgeops_metrics_count_for_testing(FORGEOPS_METRIC_CUSTOM) == 0);
  forgeops_tracker_flush_metrics();
  waitpid(child, NULL, 0);

  char *body = read_whole_file(body_path);
  ASSERT_NOT_NULL(body);
  ASSERT_TRUE(strstr(body, "\"metric_name\":\"cpu\",\"value\":0.41999999999999998,\"hostname\":\"db-1\"") != NULL || strstr(body, "\"metric_name\":\"cpu\",\"value\":0.42,\"hostname\":\"db-1\"") != NULL);
  ASSERT_TRUE(strstr(body, "\"hostname\":\"web-1\"") != NULL);

  free(body);
  remove(body_path);
  forgeops_tracker_reset_for_testing();
}

TEST(metrics_a_nan_or_infinite_value_is_dropped_and_a_null_name_is_ignored) {
  metrics_test_setup(0);
  forgeops_tracker_capture_metric("nan", NAN);
  forgeops_tracker_capture_metric("inf", INFINITY);
  forgeops_tracker_capture_metric(NULL, 1.0);
  ASSERT_TRUE(forgeops_metrics_count_for_testing(FORGEOPS_METRIC_CUSTOM) == 0);
  forgeops_tracker_capture_metric("ok", 3.0);
  ASSERT_TRUE(forgeops_metrics_count_for_testing(FORGEOPS_METRIC_CUSTOM) == 1);
  forgeops_tracker_reset_for_testing();
}

TEST(metrics_a_failed_delivery_keeps_every_entry_so_the_next_flush_carries_more) {
  char body_path[128];
  snprintf(body_path, sizeof(body_path), "/tmp/forgeops-c-metrics-retry-%d.json", getpid());
  pid_t child;
  const int statuses[] = {500, 202};
  int port = start_capturing_test_server(statuses, 2, body_path, &child);
  metrics_test_setup(port);

  forgeops_tracker_capture_metric("a", 1.0);
  forgeops_tracker_flush_metrics();
  ASSERT_TRUE(forgeops_metrics_count_for_testing(FORGEOPS_METRIC_CUSTOM) == 1);
  forgeops_tracker_capture_metric("b", 2.0);
  forgeops_tracker_flush_metrics();
  waitpid(child, NULL, 0);

  char *body = read_whole_file(body_path);
  ASSERT_NOT_NULL(body);
  ASSERT_TRUE(strstr(body, "\"metric_name\":\"a\"") != NULL && strstr(body, "\"metric_name\":\"b\"") != NULL);
  ASSERT_TRUE(forgeops_metrics_count_for_testing(FORGEOPS_METRIC_CUSTOM) == 0);

  free(body);
  remove(body_path);
  forgeops_tracker_reset_for_testing();
}

static void capture_during_delivery(void) {
  forgeops_tracker_capture_metric("during", 2.0);
}

TEST(metrics_an_entry_captured_while_delivery_is_in_flight_is_never_lost) {
  char body_path[128];
  snprintf(body_path, sizeof(body_path), "/tmp/forgeops-c-metrics-inflight-%d.json", getpid());
  pid_t child;
  const int statuses[] = {202};
  int port = start_capturing_test_server(statuses, 1, body_path, &child);
  metrics_test_setup(port);

  forgeops_tracker_capture_metric("first", 1.0);
  forgeops_metrics_set_before_delivery_hook_for_testing(capture_during_delivery);
  forgeops_tracker_flush_metrics();
  waitpid(child, NULL, 0);

  char *body = read_whole_file(body_path);
  ASSERT_NOT_NULL(body);
  ASSERT_TRUE(strstr(body, "\"metric_name\":\"first\"") != NULL && strstr(body, "\"metric_name\":\"during\"") == NULL);
  ASSERT_TRUE(forgeops_metrics_count_for_testing(FORGEOPS_METRIC_CUSTOM) == 1);

  free(body);
  remove(body_path);
  forgeops_tracker_reset_for_testing();
}

TEST(metrics_a_buffer_is_capped_and_drops_further_entries_until_a_flush_succeeds) {
  metrics_test_setup(0);
  for (int i = 0; i < FORGEOPS_METRICS_MAX_ENTRIES + 50; i++) forgeops_tracker_capture_metric("m", 1.0);
  ASSERT_TRUE(forgeops_metrics_count_for_testing(FORGEOPS_METRIC_CUSTOM) == FORGEOPS_METRICS_MAX_ENTRIES);
  forgeops_tracker_reset_for_testing();
}

TEST(metrics_captures_are_a_no_op_when_reporting_is_not_enabled_for_this_environment) {
  forgeops_configuration_t *config = metrics_test_setup(0);
  free(config->environment);
  config->environment = strdup("development");
  forgeops_tracker_capture_metric("signup", 1.0);
  forgeops_tracker_capture_infrastructure_metric("cpu", 1.0, NULL);
  ASSERT_TRUE(forgeops_metrics_count_for_testing(FORGEOPS_METRIC_CUSTOM) == 0);
  ASSERT_TRUE(forgeops_metrics_count_for_testing(FORGEOPS_METRIC_INFRASTRUCTURE) == 0);
  forgeops_tracker_reset_for_testing();
}

TEST(metrics_urls_swap_the_trailing_events_segment) {
  metrics_test_setup(0);
  char *custom = forgeops_configuration_custom_metrics_url(forgeops_tracker_configuration());
  char *infrastructure = forgeops_configuration_infrastructure_metrics_url(forgeops_tracker_configuration());
  ASSERT_TRUE(custom != NULL && strcmp(custom, "http://127.0.0.1:1/api/v1/custom_metrics") == 0);
  ASSERT_TRUE(infrastructure != NULL && strcmp(infrastructure, "http://127.0.0.1:1/api/v1/infrastructure_metrics") == 0);
  free(custom);
  free(infrastructure);
  forgeops_tracker_reset_for_testing();
}

TEST(metrics_a_program_that_captures_a_reading_and_just_exits_still_delivers_it_from_its_atexit_hook) {
#if defined(__SANITIZE_THREAD__) || (defined(__has_feature) && __has_feature(thread_sanitizer))
  /* ThreadSanitizer's fork() support in a process that has run threads before hangs the forked child
   * (a documented TSan limitation, not a defect here); the same test passes under ASan/UBSan and
   * without a sanitizer. */
  return;
#endif
  char body_path[128];
  snprintf(body_path, sizeof(body_path), "/tmp/forgeops-c-metrics-exit-%d.json", getpid());
  pid_t server;
  const int statuses[] = {202};
  int port = start_capturing_test_server(statuses, 1, body_path, &server);

  fflush(NULL);
  pid_t child = fork();
  if (child == 0) {
    metrics_test_setup(port);
    forgeops_tracker_capture_infrastructure_metric("cpu", 0.5, "cron-1");
    exit(0); /* not _exit: the atexit hook is the thing under test */
  }
  waitpid(child, NULL, 0);
  waitpid(server, NULL, 0);

  char *body = read_whole_file(body_path);
  ASSERT_NOT_NULL(body);
  ASSERT_TRUE(strstr(body, "\"hostname\":\"cron-1\"") != NULL);
  free(body);
  remove(body_path);
}


/* ---- SQL capture ---------------------------------------------------------------------------- */

#include "forgeops_tracker/sql_statement.h"

static void assert_masks_to(const char *input, const char *expected) {
  char *masked = forgeops_sql_mask(input);
  if (masked == NULL || strcmp(masked, expected) != 0) {
    printf("  mask(%s) = %s, expected %s\n", input, masked == NULL ? "(null)" : masked, expected);
    g_current_test_failed = 1;
  }
  free(masked);
}

static void assert_objects_are(const char *masked, const char *expected_json) {
  char *json = forgeops_sql_objects_json(masked);
  if (expected_json == NULL) {
    if (json != NULL) {
      printf("  objects(%s) = %s, expected NULL\n", masked, json);
      g_current_test_failed = 1;
    }
  } else if (json == NULL || strcmp(json, expected_json) != 0) {
    printf("  objects(%s) = %s, expected %s\n", masked, json == NULL ? "(null)" : json, expected_json);
    g_current_test_failed = 1;
  }
  free(json);
}

TEST(sql_mask_replaces_strings_and_numbers_but_not_identifiers_or_placeholders) {
  assert_masks_to("SELECT * FROM orders2 WHERE email = 'a@b.co' AND id = 42 AND x = $1", "SELECT * FROM orders2 WHERE email = ? AND id = ? AND x = $1");
  assert_masks_to("SELECT price * 1.5 FROM t WHERE a IN (1,2,3)", "SELECT price * ? FROM t WHERE a IN (?,?,?)");
  assert_masks_to("SELECT 1.5x FROM t", "SELECT ?.5x FROM t");
}

TEST(sql_mask_handles_an_escaped_quote_a_cut_off_string_and_a_dollar_quoted_body) {
  assert_masks_to("EXEC sp_x @t = 'it''s'", "EXEC sp_x @t = ?");
  assert_masks_to("SELECT 1 WHERE n = 'oops", "SELECT ? WHERE n = ?");
  assert_masks_to("DO $b$ BEGIN PERFORM 1; END $b$", "DO ?");
}

TEST(sql_mask_is_idempotent_truncates_and_returns_null_for_blank) {
  char *once = forgeops_sql_mask("SELECT * FROM t WHERE a = 'x' AND b = 9");
  ASSERT_NOT_NULL(once);
  char *twice = forgeops_sql_mask(once);
  ASSERT_TRUE(twice != NULL && strcmp(once, twice) == 0);
  free(once);
  free(twice);

  size_t n = 3000;
  char *long_sql = malloc(n * 3 + 16);
  strcpy(long_sql, "SELECT ");
  for (size_t i = 0; i < n; i++) strcat(long_sql, "a, ");
  strcat(long_sql, " b");
  char *masked = forgeops_sql_mask(long_sql);
  ASSERT_TRUE(masked != NULL && strlen(masked) == 4003);
  free(masked);
  free(long_sql);

  ASSERT_TRUE(forgeops_sql_mask("  ") == NULL);
  ASSERT_TRUE(forgeops_sql_mask(NULL) == NULL);
}

TEST(sql_objects_finds_a_stored_procedure_with_its_schema) {
  assert_objects_are("EXEC dbo.sp_refund_order @id = ?", "{\"operation\":\"EXEC\",\"procedures\":[\"dbo.sp_refund_order\"],\"relations\":[]}");
  assert_objects_are("CALL refund_order(?, ?)", "{\"operation\":\"CALL\",\"procedures\":[\"refund_order\"],\"relations\":[]}");
  assert_objects_are("SELECT refund_order(?, ?)", "{\"operation\":\"SELECT\",\"procedures\":[\"refund_order\"],\"relations\":[]}");
}

TEST(sql_objects_finds_views_joined_tables_and_table_functions) {
  assert_objects_are("SELECT * FROM v_totals t JOIN public.customers c ON c.id = t.id", "{\"operation\":\"SELECT\",\"procedures\":[],\"relations\":[\"v_totals\",\"public.customers\"]}");
  assert_objects_are("SELECT * FROM get_open_orders(?) o", "{\"operation\":\"SELECT\",\"procedures\":[\"get_open_orders\"],\"relations\":[]}");
  assert_objects_are("UPDATE \"Order Items\" SET qty = ?", "{\"operation\":\"UPDATE\",\"procedures\":[],\"relations\":[\"\\\"Order Items\\\"\"]}");
}

TEST(sql_objects_does_not_misread_column_lists_builtins_or_from_inside_extract) {
  assert_objects_are("INSERT INTO audit_log (a) VALUES (?)", "{\"operation\":\"INSERT\",\"procedures\":[],\"relations\":[\"audit_log\"]}");
  assert_objects_are("SELECT count(*) FROM orders", "{\"operation\":\"SELECT\",\"procedures\":[],\"relations\":[\"orders\"]}");
  assert_objects_are("SELECT 1 FROM orders WHERE extract(year FROM created_at) = ?", "{\"operation\":\"SELECT\",\"procedures\":[],\"relations\":[\"orders\"]}");
  assert_objects_are("garbage", NULL);
}

TEST(sql_event_builder_sends_the_procedure_name_by_default_and_the_statement_only_when_opted_in) {
  forgeops_configuration_t *config = forgeops_configuration_create();
  const char *sql = "EXEC dbo.sp_refund_order @order_id = 8814, @note = 'a@b.co'";

  char *json = forgeops_build_event_json_with_sql(config, "MyError", "boom", NULL, NULL, 0, NULL, NULL, 0, NULL, 0, sql);
  ASSERT_NOT_NULL(json);
  ASSERT_TRUE(strstr(json, "\"sql_objects\":{\"operation\":\"EXEC\",\"procedures\":[\"dbo.sp_refund_order\"]") != NULL);
  ASSERT_TRUE(strstr(json, "sql_statement") == NULL);
  ASSERT_TRUE(strstr(json, "8814") == NULL && strstr(json, "a@b.co") == NULL);
  free(json);

  config->capture_sql_statement = 1;
  json = forgeops_build_event_json_with_sql(config, "MyError", "boom", NULL, NULL, 0, NULL, NULL, 0, NULL, 0, sql);
  ASSERT_TRUE(strstr(json, "\"sql_statement\":\"EXEC dbo.sp_refund_order @order_id = ?, @note = ?\"") != NULL);
  free(json);

  config->capture_sql_objects = 0;
  config->capture_sql_statement = 0;
  json = forgeops_build_event_json_with_sql(config, "MyError", "boom", NULL, NULL, 0, NULL, NULL, 0, NULL, 0, sql);
  ASSERT_TRUE(strstr(json, "\"sql_objects\"") == NULL && strstr(json, "\"sql_statement\"") == NULL);
  free(json);

  config->capture_sql_objects = 1;
  json = forgeops_build_event_json_with_sql(config, "MyError", "boom", NULL, NULL, 0, NULL, NULL, 0, NULL, 0, NULL);
  ASSERT_TRUE(strstr(json, "\"sql_objects\"") == NULL && strstr(json, "\"sql_statement\"") == NULL);
  free(json);

  forgeops_configuration_destroy(config);
}

/* ---- Change tracking ------------------------------------------------------------------------------ */

TEST(changes_build_sends_the_documented_shape_with_every_optional_field) {
  forgeops_configuration_t *config = forgeops_configuration_create();
  free(config->environment);
  config->environment = strdup("production");
  const char *keys[] = {"flag", "to"};
  const char *values[] = {"new_checkout", "true"};
  forgeops_change_options_t options = {.service = "firmware", .actor = "luke", .url = "https://example.com/flags/1", .id = "change-1", .occurred_at_unix_ms = 1790337600123LL};

  char *body = forgeops_changes_build(config, "feature_flag", "Enabled new checkout", keys, values, 2, &options);
  ASSERT_STREQ(body, "{\"kind\":\"feature_flag\",\"title\":\"Enabled new checkout\",\"environment\":\"production\",\"occurred_at\":\"2026-09-25T12:00:00.123Z\",\"details\":{\"flag\":\"new_checkout\",\"to\":\"true\"},\"service\":\"firmware\",\"actor\":\"luke\",\"url\":\"https://example.com/flags/1\",\"id\":\"change-1\"}");
  free(body);

  options = (forgeops_change_options_t){.environment = "staging"};
  body = forgeops_changes_build(config, "config", "x", NULL, NULL, 0, &options);
  ASSERT_TRUE(strstr(body, "\"environment\":\"staging\"") != NULL);
  free(body);

  forgeops_configuration_destroy(config);
}

TEST(changes_build_defaults_environment_and_occurred_at_and_leaves_unset_keys_out) {
  forgeops_configuration_t *config = forgeops_configuration_create();
  char *body = forgeops_changes_build(config, "config", "  Raised the upload limit\n", NULL, NULL, 0, NULL);
  ASSERT_NOT_NULL(body);
  ASSERT_TRUE(strncmp(body, "{\"kind\":\"config\",\"title\":\"Raised the upload limit\",\"environment\":\"development\",\"occurred_at\":\"20", 95) == 0);
  ASSERT_TRUE(strstr(body, "Z\"}") != NULL && body[strlen(body) - 1] == '}');
  ASSERT_TRUE(strstr(body, "details") == NULL && strstr(body, "service") == NULL && strstr(body, "actor") == NULL && strstr(body, "\"url\"") == NULL && strstr(body, "\"id\"") == NULL);
  free(body);
  forgeops_configuration_destroy(config);
}

TEST(changes_an_unknown_or_null_kind_is_sent_as_other_and_every_known_kind_is_kept) {
  forgeops_configuration_t *config = forgeops_configuration_create();
  const char *known[] = {"feature_flag", "config", "migration", "dependency", "infrastructure", "other"};
  for (size_t i = 0; i < 6; i++) {
    char *body = forgeops_changes_build(config, known[i], "t", NULL, NULL, 0, NULL);
    char expected[64];
    snprintf(expected, sizeof(expected), "{\"kind\":\"%s\",", known[i]);
    ASSERT_TRUE(strncmp(body, expected, strlen(expected)) == 0);
    free(body);
  }
  char *body = forgeops_changes_build(config, "deploy", "t", NULL, NULL, 0, NULL);
  ASSERT_TRUE(strncmp(body, "{\"kind\":\"other\",", 16) == 0);
  free(body);
  body = forgeops_changes_build(config, NULL, "t", NULL, NULL, 0, NULL);
  ASSERT_TRUE(strncmp(body, "{\"kind\":\"other\",", 16) == 0);
  free(body);
  forgeops_configuration_destroy(config);
}

TEST(changes_a_long_title_is_cut_to_200_characters_never_mid_character_and_a_blank_one_builds_nothing) {
  forgeops_configuration_t *config = forgeops_configuration_create();
  char title[512];
  memset(title, 'a', 199);
  strcpy(title + 199, "\xc3\xa9" "bcd"); /* 199 ASCII, then a two-byte e-acute as character 200 */
  char *body = forgeops_changes_build(config, "other", title, NULL, NULL, 0, NULL);
  char expected[256];
  memset(expected, 'a', 199);
  strcpy(expected + 199, "\xc3\xa9\"");
  ASSERT_TRUE(strstr(body, expected) != NULL);
  ASSERT_TRUE(strstr(body, "\xc3\xa9" "b") == NULL);
  free(body);

  ASSERT_NULL(forgeops_changes_build(config, "other", "   ", NULL, NULL, 0, NULL));
  ASSERT_NULL(forgeops_changes_build(config, "other", NULL, NULL, NULL, 0, NULL));
  forgeops_configuration_destroy(config);
}

TEST(changes_escape_quotes_and_control_characters_into_valid_json) {
  forgeops_configuration_t *config = forgeops_configuration_create();
  const char *keys[] = {"note"};
  const char *values[] = {"say \"hi\"\n"};
  char *body = forgeops_changes_build(config, "other", "a\\b", keys, values, 1, NULL);
  ASSERT_TRUE(strstr(body, "\"title\":\"a\\\\b\"") != NULL);
  ASSERT_TRUE(strstr(body, "\"note\":\"say \\\"hi\\\"\\n\"") != NULL);
  free(body);
  forgeops_configuration_destroy(config);
}

TEST(changes_record_change_delivers_to_the_changes_endpoint_and_is_a_no_op_when_disabled) {
  char body_path[128];
  snprintf(body_path, sizeof(body_path), "/tmp/forgeops-c-changes-body-%d.json", getpid());
  pid_t child;
  const int statuses[] = {202};
  int port = start_capturing_test_server(statuses, 1, body_path, &child);
  forgeops_configuration_t *config = performance_test_setup(port);

  char *url = forgeops_configuration_changes_url(config);
  char expected_url[128];
  snprintf(expected_url, sizeof(expected_url), "http://127.0.0.1:%d/api/v1/changes", port);
  ASSERT_STREQ(url, expected_url);
  free(url);

  /* The server serves one request: had the disabled call sent anything, that is what it would hold. */
  free(config->environment);
  config->environment = strdup("development");
  forgeops_tracker_record_change("config", "Ignored while disabled", NULL, NULL, 0);
  free(config->environment);
  config->environment = strdup("production");
  forgeops_change_options_t options = {.actor = "luke"};
  forgeops_tracker_record_change_with_options("migration", "Added the orders index", NULL, NULL, 0, &options);
  waitpid(child, NULL, 0);

  char *body = read_whole_file(body_path);
  ASSERT_NOT_NULL(body);
  ASSERT_TRUE(strstr(body, "\"kind\":\"migration\",\"title\":\"Added the orders index\",\"environment\":\"production\"") != NULL);
  ASSERT_TRUE(strstr(body, "\"actor\":\"luke\"") != NULL);
  free(body);
  remove(body_path);
  forgeops_tracker_reset_for_testing();
}

TEST(changes_record_change_never_fails_the_caller_on_a_403_or_an_unreachable_host) {
  char body_path[128];
  snprintf(body_path, sizeof(body_path), "/tmp/forgeops-c-changes-403-%d.json", getpid());
  pid_t child;
  const int statuses[] = {403};
  int port = start_capturing_test_server(statuses, 1, body_path, &child);
  performance_test_setup(port);
  forgeops_tracker_record_change("config", "Plan without change tracking", NULL, NULL, 0);
  waitpid(child, NULL, 0);
  char *body = read_whole_file(body_path);
  ASSERT_NOT_NULL(body);
  ASSERT_TRUE(strstr(body, "Plan without change tracking") != NULL);
  free(body);
  remove(body_path);

  performance_test_setup(0); /* nothing listening */
  forgeops_tracker_record_change("config", "Nobody listening", NULL, NULL, 0);
  forgeops_tracker_reset_for_testing(); /* joins the delivery thread: reaching here is the assertion */
  ASSERT_TRUE(1);
}

int main(void) {
  RUN(sql_mask_replaces_strings_and_numbers_but_not_identifiers_or_placeholders);
  RUN(sql_mask_handles_an_escaped_quote_a_cut_off_string_and_a_dollar_quoted_body);
  RUN(sql_mask_is_idempotent_truncates_and_returns_null_for_blank);
  RUN(sql_objects_finds_a_stored_procedure_with_its_schema);
  RUN(sql_objects_finds_views_joined_tables_and_table_functions);
  RUN(sql_objects_does_not_misread_column_lists_builtins_or_from_inside_extract);
  RUN(sql_event_builder_sends_the_procedure_name_by_default_and_the_statement_only_when_opted_in);
  RUN(configuration_defaults);
  RUN(configuration_api_key_and_ingestion_url);
  RUN(configuration_api_key_percent_decodes);
  RUN(configuration_empty_or_malformed_dsn);
  RUN(configuration_dsn_with_no_userinfo);
  RUN(configuration_is_enabled);

  RUN(pii_scrub_email);
  RUN(pii_scrub_credit_card);
  RUN(pii_leaves_ordinary_numeric_id_alone);
  RUN(pii_scrub_ssn);
  RUN(pii_scrub_known_token_formats);
  RUN(pii_is_sensitive_key_ignores_case_and_punctuation);

  RUN(event_builder_basic_fields);
  RUN(event_builder_scrubs_message_and_context_by_default);
  RUN(event_builder_leaves_payload_untouched_when_scrub_pii_disabled);
  RUN(event_builder_never_attaches_source_context_in_practice);
  RUN(event_builder_includes_the_user_when_given_one_never_scrubbed_even_though_its_an_email);
  RUN(source_context_attaches_window_around_the_culprit_line_by_default);
  RUN(source_context_clamps_at_file_boundaries_rather_than_crashing);
  RUN(source_context_truncates_a_line_longer_than_max_context_line_length);
  RUN(source_context_returns_null_when_not_in_app);
  RUN(source_context_returns_null_when_capture_source_context_disabled);
  RUN(source_context_returns_null_when_the_file_cannot_be_read);

  RUN(crash_store_write_and_read_round_trip);
  RUN(crash_store_delete_removes_it);
  RUN(crash_store_pending_paths_is_null_for_missing_directory);

  RUN(client_delivers_on_2xx_response);
  RUN(client_returns_false_on_non_2xx_response);
  RUN(client_returns_false_with_no_dsn);
  RUN(client_returns_false_when_unreachable);

  RUN(reporter_report_does_nothing_when_disabled);
  RUN(reporter_report_writes_a_pending_report_when_enabled);
  RUN(reporter_report_includes_the_given_user_never_scrubbed_even_though_its_an_email);
  RUN(reporter_upload_pending_reports_delivers_and_deletes_on_success);
  RUN(reporter_upload_pending_reports_leaves_file_on_failure);

  RUN(tracker_capture_error_delivers_through_the_full_stack);
  RUN(tracker_set_user_attaches_the_user_to_a_later_capture_error_call);
  RUN(tracker_an_explicit_user_argument_overrides_whatever_set_user_last_set);
  RUN(tracker_reset_for_testing_clears_the_current_user);
  RUN(tracker_install_handlers_is_idempotent);

  RUN(performance_record_buckets_by_transaction_name_with_count_sum_and_max);
  RUN(performance_record_does_nothing_when_track_performance_is_off);
  RUN(performance_record_does_nothing_when_reporting_is_not_enabled_for_this_environment);
  RUN(performance_a_new_transaction_name_past_the_cap_is_dropped_but_existing_ones_keep_counting);
  RUN(performance_the_timer_records_how_long_the_bracketed_work_took);
  RUN(performance_flush_delivers_one_batch_to_performance_samples_and_empties_the_buckets);
  RUN(performance_flush_does_nothing_when_there_is_nothing_to_send);
  RUN(performance_a_failed_delivery_keeps_every_bucket_so_the_next_flush_carries_more);
  RUN(performance_a_record_that_lands_during_delivery_is_never_lost);
  RUN(performance_the_background_thread_flushes_on_its_own_interval);
  RUN(performance_samples_url_swaps_the_trailing_events_segment);
  RUN(performance_reset_for_testing_stops_the_thread_and_clears_every_bucket);

  RUN(breadcrumbs_add_attaches_the_trail_to_a_later_capture_error_call);
  RUN(breadcrumbs_null_category_and_level_default_to_custom_and_info);
  RUN(breadcrumbs_keep_only_the_most_recent_max_breadcrumbs_dropping_the_oldest);
  RUN(breadcrumbs_wrap_around_the_ring_many_times_and_stay_in_order);
  RUN(breadcrumbs_record_nothing_when_track_breadcrumbs_is_off);
  RUN(breadcrumbs_clear_empties_the_trail_and_the_report_carries_no_breadcrumbs_key);
  RUN(breadcrumbs_scrub_message_and_data_when_added_but_not_category_or_level);
  RUN(breadcrumbs_leave_values_untouched_when_scrub_pii_is_off);
  RUN(breadcrumbs_escape_quotes_and_control_characters_into_valid_json);
  RUN(breadcrumbs_an_oversized_entry_is_shrunk_to_fit_its_slot_never_overflowing_it);
  RUN(breadcrumbs_truncation_never_cuts_a_multibyte_utf8_character_in_half);
  RUN(breadcrumbs_are_isolated_per_thread);
  RUN(breadcrumbs_reset_for_testing_clears_the_trail);
  RUN(breadcrumbs_event_builder_includes_the_given_trail_and_omits_the_key_when_empty);
  RUN(breadcrumbs_a_fatal_signals_raw_report_carries_the_crashing_threads_trail);
  RUN(breadcrumbs_a_raw_signal_report_with_no_trail_has_no_breadcrumbs_key);
  RUN(breadcrumbs_a_truncated_breadcrumb_line_in_a_raw_report_is_dropped_not_spliced_into_the_json);


  RUN(tracing_a_slow_trace_is_delivered_to_spans_with_nested_spans_and_the_wire_shape);
  RUN(tracing_an_unknown_or_null_kind_is_sent_as_other_since_the_server_would_reject_the_whole_trace);
  RUN(tracing_a_trace_under_the_threshold_is_never_queued_and_leaves_nothing_open);
  RUN(tracing_track_tracing_off_still_has_a_trace_id_but_never_sends_and_reporting_disabled_starts_nothing);
  RUN(tracing_a_span_outside_a_trace_is_a_harmless_no_op);
  RUN(tracing_a_nested_trace_start_does_not_start_a_second_trace_and_its_stop_does_nothing);
  RUN(tracing_a_trace_holds_at_most_500_spans_including_the_root);
  RUN(tracing_the_open_trace_is_per_thread);
  RUN(tracing_spans_url_swaps_the_trailing_events_segment);
  RUN(tracing_an_ended_span_state_is_cleared_so_a_second_stop_records_nothing);

  RUN(traceparent_parses_a_valid_version_00_header);
  RUN(traceparent_rejects_anything_malformed);
  RUN(traceparent_accepts_a_future_version_with_extra_fields);
  RUN(traceparent_builds_a_sampled_version_00_header_and_ids_are_lowercase_hex_never_all_zeros);
  RUN(traceparent_url_host_extracts_just_the_lowercased_host);
  RUN(trace_propagation_goes_to_every_host_by_default_and_nowhere_when_off);
  RUN(trace_propagation_targets_match_on_a_dot_boundary_ignoring_case_and_a_leading_dot);
  RUN(trace_context_continuing_a_traceparent_keeps_its_id_and_the_http_span_names_itself_in_the_header);
  RUN(trace_context_a_missing_or_malformed_traceparent_starts_a_fresh_trace);
  RUN(trace_context_no_header_outside_a_trace_off_target_or_with_propagation_off_but_the_span_still_records);
  RUN(trace_context_an_error_captured_inside_a_trace_carries_its_id_even_with_track_tracing_off);
  RUN(trace_context_a_fatal_signal_inside_a_trace_carries_its_id);
  RUN(trace_context_a_cut_off_trace_id_line_in_a_raw_report_is_dropped);


  RUN(metrics_flush_delivers_every_entry_as_one_batch_to_custom_metrics_with_the_wire_shape);
  RUN(metrics_infrastructure_readings_go_to_their_own_endpoint_with_an_explicit_or_default_hostname);
  RUN(metrics_a_nan_or_infinite_value_is_dropped_and_a_null_name_is_ignored);
  RUN(metrics_a_failed_delivery_keeps_every_entry_so_the_next_flush_carries_more);
  RUN(metrics_an_entry_captured_while_delivery_is_in_flight_is_never_lost);
  RUN(metrics_a_buffer_is_capped_and_drops_further_entries_until_a_flush_succeeds);
  RUN(metrics_captures_are_a_no_op_when_reporting_is_not_enabled_for_this_environment);
  RUN(metrics_urls_swap_the_trailing_events_segment);
  RUN(metrics_a_program_that_captures_a_reading_and_just_exits_still_delivers_it_from_its_atexit_hook);

  RUN(changes_build_sends_the_documented_shape_with_every_optional_field);
  RUN(changes_build_defaults_environment_and_occurred_at_and_leaves_unset_keys_out);
  RUN(changes_an_unknown_or_null_kind_is_sent_as_other_and_every_known_kind_is_kept);
  RUN(changes_a_long_title_is_cut_to_200_characters_never_mid_character_and_a_blank_one_builds_nothing);
  RUN(changes_escape_quotes_and_control_characters_into_valid_json);
  RUN(changes_record_change_delivers_to_the_changes_endpoint_and_is_a_no_op_when_disabled);
  RUN(changes_record_change_never_fails_the_caller_on_a_403_or_an_unreachable_host);

  printf("\n%d run, %d failed\n", g_tests_run, g_tests_failed);
  return g_tests_failed == 0 ? 0 : 1;
}
