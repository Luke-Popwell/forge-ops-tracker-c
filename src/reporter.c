#include "forgeops_tracker/reporter.h"

#include <stdlib.h>
#include <string.h>

#include "forgeops_tracker/client.h"
#include "forgeops_tracker/crash_store.h"
#include "forgeops_tracker/event_builder.h"
#include "forgeops_tracker/signal_handler.h"

static int has_suffix(const char *s, const char *suffix) {
  size_t s_len = strlen(s);
  size_t suffix_len = strlen(suffix);
  if (suffix_len > s_len) return 0;
  return strcmp(s + (s_len - suffix_len), suffix) == 0;
}

void forgeops_report_error(const forgeops_configuration_t *config, const char *exception_class, const char *message, const char **context_keys, const char **context_values, size_t context_count) {
  if (!forgeops_configuration_is_enabled(config)) return;

  char *json = forgeops_build_event_json(config, exception_class, message, context_keys, context_values, context_count);
  if (json == NULL) return;

  forgeops_crash_store_write(config, json);
  free(json);
}

void forgeops_upload_pending_reports(const forgeops_configuration_t *config) {
  if (!forgeops_configuration_is_enabled(config)) return;

  char **paths = forgeops_crash_store_pending_paths(config);
  if (paths == NULL) return;

  for (char **p = paths; *p != NULL; p++) {
    char *payload;
    if (has_suffix(*p, ".txt")) {
      /* A raw signal-crash report -- fill in the standard fields the signal handler couldn't
       * safely build inline (see signal_handler.h's own comment), now that it's safe to call
       * ordinary functions again. */
      payload = forgeops_signal_handler_complete_json(config, *p);
    } else {
      payload = forgeops_crash_store_read(*p);
    }

    if (payload == NULL) {
      /* Unreadable/corrupt file -- delete rather than retry forever. */
      forgeops_crash_store_delete(*p);
      continue;
    }

    if (forgeops_client_deliver(config, payload)) {
      forgeops_crash_store_delete(*p);
    }
    /* On failure, leave it in place; the next call retries it. */
    free(payload);
  }

  forgeops_crash_store_free_paths(paths);
}
