#include "forgeops_tracker/configuration.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static char *dup_or_null(const char *s) {
  if (s == NULL) return NULL;
  size_t len = strlen(s);
  char *copy = malloc(len + 1);
  if (copy == NULL) return NULL;
  memcpy(copy, s, len + 1);
  return copy;
}

static char *dup_env_or(const char *name, const char *fallback) {
  const char *value = getenv(name);
  if (value == NULL || value[0] == '\0') return dup_or_null(fallback);
  return dup_or_null(value);
}

static char *safe_hostname(void) {
  char buf[256];
  if (gethostname(buf, sizeof(buf)) != 0) return NULL;
  buf[sizeof(buf) - 1] = '\0';
  return dup_or_null(buf);
}

forgeops_configuration_t *forgeops_configuration_create(void) {
  forgeops_configuration_t *config = calloc(1, sizeof(forgeops_configuration_t));
  if (config == NULL) return NULL;

  config->dsn = dup_env_or("FORGE_OPS_DSN", NULL);
  config->environment = dup_env_or("FORGE_OPS_ENVIRONMENT", "development");
  config->release = dup_env_or("FORGE_OPS_RELEASE", NULL);
  config->server_name = safe_hostname();

  const char *tmp_dir = getenv("TMPDIR");
  if (tmp_dir == NULL || tmp_dir[0] == '\0') tmp_dir = "/tmp";
  size_t dir_len = strlen(tmp_dir) + strlen("forgeops-tracker/pending-crash-reports") + 2;
  config->crash_reports_directory = malloc(dir_len);
  if (config->crash_reports_directory != NULL) {
    snprintf(config->crash_reports_directory, dir_len, "%s/forgeops-tracker/pending-crash-reports", tmp_dir);
  }

  config->scrub_pii = 1;
  config->timeout_seconds = 5; /* longer than the request-based clients' ~2s -- see the Objective-C/Swift clients' own identical reasoning: this fires on the *next* launch after a crash, not inline with a live request */

  config->enabled_environment_count = 2;
  config->enabled_environments = calloc(2, sizeof(char *));
  if (config->enabled_environments != NULL) {
    config->enabled_environments[0] = dup_or_null("production");
    config->enabled_environments[1] = dup_or_null("staging");
  }

  return config;
}

void forgeops_configuration_destroy(forgeops_configuration_t *config) {
  if (config == NULL) return;
  free(config->dsn);
  free(config->environment);
  free(config->release);
  free(config->server_name);
  free(config->crash_reports_directory);
  for (int i = 0; i < config->enabled_environment_count; i++) {
    free(config->enabled_environments[i]);
  }
  free(config->enabled_environments);
  free(config);
}

void forgeops_configuration_set_dsn(forgeops_configuration_t *config, const char *dsn) {
  free(config->dsn);
  config->dsn = dup_or_null(dsn);
}

/* Hand-parses a DSN of the form "scheme://api_key@host[:port]/path[?query]" -- the shape is fixed
 * and simple enough that a small dependency-free parser is clearer here than pulling in a URL
 * library, the same spirit as the Perl/Rust clients' own dependency-free DSN parsing.
 *
 * On success, the userinfo_start/userinfo_end out-parameters delimit the userinfo substring (an
 * empty range if there's no "@"), and host_start points at the first character after "://" (or
 * after "user@" if present) through the end of the string. Returns 0 on success, -1 if dsn has
 * no "://" or no host at all.
 */
static int split_dsn(const char *dsn, const char **scheme_end, const char **userinfo_start, const char **userinfo_end, const char **host_start) {
  const char *scheme_sep = strstr(dsn, "://");
  if (scheme_sep == NULL || scheme_sep == dsn) return -1;
  *scheme_end = scheme_sep;

  const char *rest = scheme_sep + 3;
  const char *at = strchr(rest, '@');
  if (at != NULL) {
    *userinfo_start = rest;
    *userinfo_end = at;
    *host_start = at + 1;
  } else {
    *userinfo_start = rest;
    *userinfo_end = rest; /* empty range: no userinfo */
    *host_start = rest;
  }

  if (**host_start == '\0') return -1; /* nothing after the "@", or nothing after "://" */
  return 0;
}

static int hex_digit(char c) {
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  return -1;
}

/* Minimal percent-decoding for a DSN's userinfo component -- the only place this client ever
 * needs it, not a general-purpose URL decoder. */
static char *percent_decode(const char *start, const char *end) {
  size_t len = (size_t)(end - start);
  char *out = malloc(len + 1);
  if (out == NULL) return NULL;

  size_t out_len = 0;
  for (size_t i = 0; i < len; i++) {
    if (start[i] == '%' && i + 2 < len) {
      int hi = hex_digit(start[i + 1]);
      int lo = hex_digit(start[i + 2]);
      if (hi >= 0 && lo >= 0) {
        out[out_len++] = (char)((hi << 4) | lo);
        i += 2;
        continue;
      }
    }
    out[out_len++] = start[i];
  }
  out[out_len] = '\0';
  return out;
}

char *forgeops_configuration_api_key(const forgeops_configuration_t *config) {
  if (config->dsn == NULL || config->dsn[0] == '\0') return NULL;

  const char *scheme_end, *userinfo_start, *userinfo_end, *host_start;
  if (split_dsn(config->dsn, &scheme_end, &userinfo_start, &userinfo_end, &host_start) != 0) return NULL;
  if (userinfo_start == userinfo_end) return NULL; /* no "@" -- no userinfo at all */

  char *decoded = percent_decode(userinfo_start, userinfo_end);
  if (decoded != NULL && decoded[0] == '\0') {
    free(decoded);
    return NULL;
  }
  return decoded;
}

char *forgeops_configuration_ingestion_url(const forgeops_configuration_t *config) {
  if (config->dsn == NULL || config->dsn[0] == '\0') return NULL;

  const char *scheme_end, *userinfo_start, *userinfo_end, *host_start;
  if (split_dsn(config->dsn, &scheme_end, &userinfo_start, &userinfo_end, &host_start) != 0) return NULL;

  size_t scheme_len = (size_t)(scheme_end - config->dsn);
  size_t rest_len = strlen(host_start);
  char *url = malloc(scheme_len + 3 /* "://" */ + rest_len + 1);
  if (url == NULL) return NULL;

  memcpy(url, config->dsn, scheme_len);
  memcpy(url + scheme_len, "://", 3);
  memcpy(url + scheme_len + 3, host_start, rest_len + 1); /* +1 copies the trailing NUL too */
  return url;
}

int forgeops_configuration_is_enabled(const forgeops_configuration_t *config) {
  if (config->dsn == NULL || config->dsn[0] == '\0') return 0;

  char *api_key = forgeops_configuration_api_key(config);
  if (api_key == NULL) return 0;
  free(api_key);

  for (int i = 0; i < config->enabled_environment_count; i++) {
    if (config->environment != NULL && strcmp(config->environment, config->enabled_environments[i]) == 0) {
      return 1;
    }
  }
  return 0;
}
