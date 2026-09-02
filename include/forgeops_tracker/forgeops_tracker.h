#ifndef FORGEOPS_TRACKER_H
#define FORGEOPS_TRACKER_H

#include <stddef.h>

#include "forgeops_tracker/configuration.h"

/*
 * Public entry point. Typical usage, as early as possible in main():
 *
 *     forgeops_configuration_t *config = forgeops_tracker_configuration();
 *     forgeops_configuration_set_dsn(config, "https://<api_key>@your-forgeops-host/api/v1/events");
 *     forgeops_tracker_install_handlers();
 *
 * There's no configure-block style API here the way the higher-level clients in this repo have --
 * plain C has no closures to pass one as, so forgeops_tracker_configuration() just hands back the
 * shared Configuration struct directly for you to set fields on (config->environment = "production";
 * or via forgeops_configuration_set_dsn for the one field that needs to invalidate cached parsing).
 *
 * See README.md for what forgeops_tracker_install_handlers actually covers (an uncaught fatal
 * signal, the only "automatic capture" story that exists for plain C -- there's no equivalent to
 * an uncaught-exception hook, because C has no exceptions at all) and why a crash report always
 * uploads on the *next* call to forgeops_tracker_upload_pending_reports (typically your own next
 * startup) rather than live during the crash itself.
 */

forgeops_configuration_t *forgeops_tracker_configuration(void);

/*
 * Installs the fatal-signal handlers, then uploads any reports left over from a previous crash or
 * process run. Call once, after configuring. Safe to call more than once -- later calls are a
 * no-op.
 */
void forgeops_tracker_install_handlers(void);

/* Report an error you've already detected explicitly, e.g. from your own error-handling code. */
void forgeops_tracker_capture_error(const char *exception_class, const char *message, const char **context_keys, const char **context_values, size_t context_count);

/* Uploads every pending report (from a past crash, or a past forgeops_tracker_capture_error call
 * whose upload hasn't happened yet). Synchronous -- call it from your own background thread if
 * you don't want it blocking the caller. forgeops_tracker_install_handlers already calls this
 * once; call it again yourself whenever else makes sense for your app (periodically, or right
 * after a forgeops_tracker_capture_error call, since that case -- unlike a crash -- didn't just
 * terminate the process and has no particular reason to wait for the next launch). */
void forgeops_tracker_upload_pending_reports(void);

/* Not part of the public API -- resets module state between test cases. */
void forgeops_tracker_reset_for_testing(void);

#endif
