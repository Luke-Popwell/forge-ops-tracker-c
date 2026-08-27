/*
 * A minimal, hand-rolled test runner rather than an external framework (Unity/CMocka/Criterion)
 * -- this SDK has exactly one real dependency (libcurl, for HTTP -- see client.h's own comment
 * on why that one's unavoidable) and a test framework isn't, the same "only depend on what's
 * genuinely necessary" line every client in this repo draws.
 */
#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "forgeops_tracker/client.h"
#include "forgeops_tracker/configuration.h"
#include "forgeops_tracker/crash_store.h"
#include "forgeops_tracker/event_builder.h"
#include "forgeops_tracker/forgeops_tracker.h"
#include "forgeops_tracker/pii_scrubber.h"
#include "forgeops_tracker/reporter.h"

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
   * contiguous literal -- none of these were ever real, but GitHub's push protection flags the
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
  char *json = forgeops_build_event_json(config, "MyError", "boom", keys, values, 1);

  ASSERT_NOT_NULL(json);
  ASSERT_TRUE(strstr(json, "\"exception_class\":\"MyError\"") != NULL);
  ASSERT_TRUE(strstr(json, "\"message\":\"boom\"") != NULL);
  ASSERT_TRUE(strstr(json, "\"environment\":\"production\"") != NULL);
  ASSERT_TRUE(strstr(json, "\"release\":\"abc123\"") != NULL);
  ASSERT_TRUE(strstr(json, "\"server_name\":\"web-1\"") != NULL);
  ASSERT_TRUE(strstr(json, "\"order_id\":\"42\"") != NULL);
  ASSERT_TRUE(strstr(json, "\"backtrace\":[{") != NULL); /* a real, non-empty backtrace */

  free(json);
  forgeops_configuration_destroy(config);
}

TEST(event_builder_scrubs_message_and_context_by_default) {
  forgeops_configuration_t *config = forgeops_configuration_create();

  const char *keys[] = {"api_key"};
  const char *values[] = {"shh-secret"};
  char *json = forgeops_build_event_json(config, "MyError", "failed for user@example.com", keys, values, 1);

  ASSERT_TRUE(strstr(json, "failed for [EMAIL FILTERED]") != NULL);
  ASSERT_TRUE(strstr(json, "\"api_key\":\"[FILTERED]\"") != NULL);
  ASSERT_TRUE(strstr(json, "shh-secret") == NULL);

  free(json);
  forgeops_configuration_destroy(config);
}

TEST(event_builder_leaves_payload_untouched_when_scrub_pii_disabled) {
  forgeops_configuration_t *config = forgeops_configuration_create();
  config->scrub_pii = 0;

  char *json = forgeops_build_event_json(config, "MyError", "contact user@example.com", NULL, NULL, 0);

  ASSERT_TRUE(strstr(json, "contact user@example.com") != NULL);

  free(json);
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
      /* Must read the full request -- headers *and* body -- before responding: closing the
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

  forgeops_report_error(config, "Boom", "bad", NULL, NULL, 0);

  ASSERT_NULL(forgeops_crash_store_pending_paths(config));
  remove_directory_recursive(config->crash_reports_directory);
  forgeops_configuration_destroy(config);
}

TEST(reporter_report_writes_a_pending_report_when_enabled) {
  forgeops_configuration_t *config = new_config_with_temp_crash_dir();
  forgeops_configuration_set_dsn(config, "https://key@host/events");
  free(config->environment);
  config->environment = strdup("production");

  forgeops_report_error(config, "Boom", "bad", NULL, NULL, 0);

  char **paths = forgeops_crash_store_pending_paths(config);
  ASSERT_NOT_NULL(paths);
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

  forgeops_report_error(config, "Boom", "bad", NULL, NULL, 0);
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

  forgeops_report_error(config, "Boom", "bad", NULL, NULL, 0);
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

  forgeops_tracker_capture_error("Boom", "bad", NULL, NULL, 0);
  forgeops_tracker_upload_pending_reports();

  ASSERT_NULL(forgeops_crash_store_pending_paths(config));

  waitpid(child, NULL, 0);
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

int main(void) {
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

  RUN(crash_store_write_and_read_round_trip);
  RUN(crash_store_delete_removes_it);
  RUN(crash_store_pending_paths_is_null_for_missing_directory);

  RUN(client_delivers_on_2xx_response);
  RUN(client_returns_false_on_non_2xx_response);
  RUN(client_returns_false_with_no_dsn);
  RUN(client_returns_false_when_unreachable);

  RUN(reporter_report_does_nothing_when_disabled);
  RUN(reporter_report_writes_a_pending_report_when_enabled);
  RUN(reporter_upload_pending_reports_delivers_and_deletes_on_success);
  RUN(reporter_upload_pending_reports_leaves_file_on_failure);

  RUN(tracker_capture_error_delivers_through_the_full_stack);
  RUN(tracker_install_handlers_is_idempotent);

  printf("\n%d run, %d failed\n", g_tests_run, g_tests_failed);
  return g_tests_failed == 0 ? 0 : 1;
}
