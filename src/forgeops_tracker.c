#include "forgeops_tracker/forgeops_tracker.h"

#include "forgeops_tracker/reporter.h"
#include "forgeops_tracker/signal_handler.h"

static forgeops_configuration_t *shared_configuration = NULL;
static int handlers_installed = 0;

forgeops_configuration_t *forgeops_tracker_configuration(void) {
  if (shared_configuration == NULL) {
    shared_configuration = forgeops_configuration_create();
  }
  return shared_configuration;
}

void forgeops_tracker_install_handlers(void) {
  if (handlers_installed) return;
  handlers_installed = 1;

  forgeops_configuration_t *config = forgeops_tracker_configuration();
  forgeops_signal_handler_install(config->crash_reports_directory);
  forgeops_tracker_upload_pending_reports();
}

void forgeops_tracker_capture_error(const char *exception_class, const char *message, const char **context_keys, const char **context_values, size_t context_count) {
  forgeops_report_error(forgeops_tracker_configuration(), exception_class, message, context_keys, context_values, context_count);
}

void forgeops_tracker_upload_pending_reports(void) {
  forgeops_upload_pending_reports(forgeops_tracker_configuration());
}

void forgeops_tracker_reset_for_testing(void) {
  forgeops_configuration_destroy(shared_configuration);
  shared_configuration = NULL;
  handlers_installed = 0;
  /* Deliberately not touching the real signal dispositions here -- resetting those between test
   * runs would risk leaving the *test process itself* without a safety net if a later, unrelated
   * test genuinely crashes. Same reasoning as this repo's own Objective-C/Swift clients' own
   * _resetForTesting. */
}
