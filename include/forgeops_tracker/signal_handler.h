#ifndef FORGEOPS_TRACKER_SIGNAL_HANDLER_H
#define FORGEOPS_TRACKER_SIGNAL_HANDLER_H

#include "forgeops_tracker/configuration.h"

/*
 * Installs handlers for the common fatal signals (SIGABRT, SIGILL, SIGSEGV, SIGFPE, SIGBUS,
 * SIGTRAP) that write a raw backtrace to disk -- the same approach, and largely the same code, as
 * this repo's own Objective-C/Swift clients' own signal handlers (sdks/objc/.../FOTSignalHandler.m,
 * sdks/swift/Sources/CFOTSignal/cfot_signal.c -- this file and that one are close enough to be the
 * same implementation ported back into this repo's plain-C client, not independently written).
 * Inside an actual signal handler, only async-signal-safe functions are safe to call at all
 * (POSIX is explicit about this) -- no malloc, nothing that could allocate or take a lock another
 * thread might already hold. Everything this handler touches (the target directory, a stack
 * buffer) is prepared *before* installation, not inside the handler, and backtrace capture uses
 * backtrace_symbols_fd() specifically because -- unlike backtrace_symbols() -- it writes directly
 * to a file descriptor without allocating a string array first.
 *
 * crash_reports_directory must already exist (forgeops_signal_handler_install creates it) and
 * outlive the handler installation.
 *
 * This path isn't exercised by this SDK's own automated test suite -- deliberately: actually
 * raising a fatal signal to test it would crash the test process itself, the same reason every
 * real crash reporter's signal path is validated by manual/integration crash testing, not a unit
 * test. Installation succeeding is tested; the handler's own body is not.
 */
void forgeops_signal_handler_install(const char *crash_reports_directory);

/*
 * Reads a raw signal-crash text file (written by the handler above) and turns it into a complete
 * JSON event payload -- filling in the fields the signal handler itself couldn't safely build
 * (occurred_at, environment, release, server_name), now that it's safe to call ordinary
 * (non-async-signal-safe) functions again. Returns a newly-allocated string the caller must free,
 * or NULL if path couldn't be read.
 */
char *forgeops_signal_handler_complete_json(const forgeops_configuration_t *config, const char *path);

#endif
