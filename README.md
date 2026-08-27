# forgeops_tracker (C)

Plain C error/crash reporting client for a private, self-hosted [ForgeOps](../../) tracker
instance. Requires a POSIX platform (macOS, Linux) -- see "Platform" below. Targets C11.

Shaped like this repo's own Objective-C/Swift clients (a crash reporter, not a web-framework
middleware -- there's no equivalent to the Django/Express/Servlet-style integrations elsewhere in
this repo, since C has neither exceptions nor a web framework of its own to hook), not the Ruby
gem's request-exception model. Plain C has no exceptions at all, so the only "automatic capture"
story that actually exists here is a fatal-signal handler -- see "What gets reported automatically"
below.

## Installation

There's no package registry for C the way npm/PyPI/etc. work for other languages -- CMake's own
`FetchContent`, pointed at a real tagged release, is the closest equivalent:

```cmake
# your own CMakeLists.txt
include(FetchContent)
FetchContent_Declare(
  forgeops_tracker
  GIT_REPOSITORY https://github.com/Luke-Popwell/forge-ops-tracker-c.git
  GIT_TAG v0.1.0
)
FetchContent_MakeAvailable(forgeops_tracker)
target_link_libraries(your_app PRIVATE forgeops_tracker)
```

That's a mirror, kept in sync automatically from `sdks/c` in the main `forge_ops` repo (which is
private, so isn't itself something `FetchContent` could ever pull directly) -- develop against
that repo, not this one. To build and run this SDK's own tests directly instead:

```bash
cd sdks/c
cmake -B build
cmake --build build
./build/forgeops_tracker_tests
```

### Dependencies

One real dependency: **libcurl**, for HTTP delivery -- the same reasoning as this repo's own C++
client's own libcurl dependency (see `client.h`'s own comment): plain C has no HTTP client
anywhere in its standard library, and hand-rolling raw HTTP/1.1-over-TLS from a bare socket is a
security-sensitive undertaking no reasonable client should attempt from scratch.

Everything else reaches for POSIX rather than a third-party library: `<regex.h>` for PII-pattern
matching (see "PII scrubbing" below for what adapting to POSIX ERE syntax actually changes),
`<execinfo.h>`'s `backtrace()`/`backtrace_symbols()` for stack capture, plain `<dirent.h>`/
`<sys/stat.h>` file I/O for the crash store. JSON encoding is hand-rolled (~150 lines across
`event_builder.c`/`signal_handler.c`) -- plain C has no JSON support at all, the same genuine gap
this repo's own Java/Kotlin/Rust clients each have their own version of, for their own languages.

### Platform

POSIX only (verified on macOS; Linux/glibc should work identically -- `<execinfo.h>`,
`<regex.h>`, and `sigaction` are all standard there too, though the exact
`backtrace_symbols()` line format is confirmed on Darwin specifically, see `event_builder.c`'s own
comment). Not Windows: no `<execinfo.h>`, no POSIX signal handling, no POSIX `<regex.h>` without
extra tooling.

## Configuration

Set a DSN (from a project's settings page in ForgeOps), either via the `FORGE_OPS_DSN` environment
variable or explicitly. There's no configure-block API the way the higher-level clients in this
repo have -- plain C has no closures to pass one as -- so `forgeops_tracker_configuration()` just
hands back the shared `Configuration` struct directly:

```c
#include <forgeops_tracker/forgeops_tracker.h>

forgeops_configuration_t *config = forgeops_tracker_configuration();
forgeops_configuration_set_dsn(config, "https://<api_key>@your-forgeops-host/api/v1/events");
config->environment = "production"; /* a plain field write is fine for anything except dsn, which
                                        needs forgeops_configuration_set_dsn to invalidate its own
                                        cached parsing */
forgeops_tracker_install_handlers();
```

## What gets reported automatically, and what doesn't

**A fatal signal (SIGABRT, SIGILL, SIGSEGV, SIGFPE, SIGBUS, SIGTRAP) needs no further wiring at
all**, once `forgeops_tracker_install_handlers()` has run. This is the *only* automatic-capture
story plain C has -- there's nothing resembling an uncaught-exception hook, because C has no
exceptions to begin with. Installed via a small signal handler (`signal_handler.c`) that's close
enough to this repo's own Objective-C/Swift signal handlers to be considered the same
implementation ported into this client, not independently written -- see that file's own comment
for why the handler itself has to stay this minimal (only async-signal-safe calls are safe inside
a real signal handler) and can't build a full JSON payload inline. It restores the default signal
disposition and re-raises after writing its report, so the process still actually crashes (and
produces a real OS-level crash log) exactly as it would without this client installed -- the same
"report, then don't change program behavior" rule every other client in this repo follows.

**An error you've already detected yourself is different** -- report it explicitly:

```c
const char *keys[] = {"order_id"};
const char *values[] = {"42"};
forgeops_tracker_capture_error("ChargeDeclined", "the card was declined", keys, values, 1);
```

Context here is always string-valued (`const char **keys`/`const char **values`, parallel arrays)
-- there's no dynamically-typed value type in C to build an arbitrary nested-map context out of
the way the higher-level clients in this repo support.

## Why a report always uploads on the *next* call, not live during the error itself

Same reasoning as this repo's own Objective-C/Swift clients: a fatal signal means the process is
about to terminate, possibly abnormally -- there's no safe way to make a live network call from
inside that handler. Instead, every report (crash or explicit) is written to disk first
(`crash_store.c`, a small durable "queue" that survives the process dying, unlike a live in-memory
delivery queue) and only actually sent over the network by
`forgeops_tracker_upload_pending_reports()` -- called once automatically by
`forgeops_tracker_install_handlers()` (covering whatever crashed on a *previous* run), and safe to
call again yourself whenever else makes sense for your app (a periodic timer; right after an
explicit `forgeops_tracker_capture_error` call, since that case didn't just terminate the process
and has no particular reason to wait). A failed upload leaves the file in place for the next call
to retry.

There is no background thread doing this automatically -- unlike the higher-level clients in this
repo, plain C has no runtime event loop or built-in async story to hang one off of. If you want
uploads to happen off your main thread, spawn one yourself (pthreads, or whatever your platform's
own threading story is) and call `forgeops_tracker_upload_pending_reports()` from it.

## Backtrace frames: image + symbol, never file/line

Same situation as this repo's own Objective-C/Swift clients: a compiled, stripped C binary has no
source file/line information left in it at runtime. `backtrace_symbols()` gives a binary image
name (closest available analog to "file") and a resolved symbol (closest analog to "method");
`line` is always JSON `null`. `in_app` is always `false` for every frame -- unlike those two
clients (which can compare against the running app's own executable name), a C backtrace's image
name for the main executable isn't reliably distinguishable from a system library's by name alone
across platforms, so this client doesn't attempt a heuristic that could be wrong more often than
it's right.

Real line-level symbolication needs an offline pass against the binary's own debug symbols after
the fact (how Crashlytics/Sentry-native-style crash reporters work) -- out of scope for a client
that has to work standalone, with no external symbolication service to call.

## PII scrubbing

Same behavior as every other client in this repo, adapted to POSIX Extended Regular Expressions
(`<regex.h>`) rather than the PCRE syntax the Ruby original (and every other client's own regex
engine) accepts unmodified: `\d`/`\s` translate directly (`[0-9]`/`[[:space:]]`); `\b` (word
boundary) has no POSIX equivalent at all, so the boundary-sensitive patterns (JWT, AWS key, Stripe
key, GitHub token, bearer token, SSN) simply don't require one here. Verified directly during
development that this doesn't cause false negatives against any of this client's own test inputs --
every pattern still requires its own literal delimiters (a leading `"AKIA"`, a `"-"` between SSN
groups, and so on), so dropping `\b` only risks a slightly *wider* match, never a narrower one that
misses real PII. See `pii_scrubber.c`'s own top comment for the full reasoning.

The message, backtrace, and any context you attach are scanned for likely personal data -- email
addresses, formatted SSNs/credit cards, known API key/token formats, and anything under a
suspiciously-named key (`password`, `api_key`, `ssn`, and similar) -- and redacted before the
payload ever leaves this process. ForgeOps itself scrubs again on arrival regardless, so this is a
second, earlier layer, not the only one.

To disable it: `config->scrub_pii = 0;`

## Running the tests

```bash
cd sdks/c
cmake -B build
cmake --build build
./build/forgeops_tracker_tests
```

A hand-rolled test runner, not an external framework (Unity/CMocka/Criterion) -- this client has
exactly one real dependency (libcurl) and a whole test framework isn't one of its genuine needs,
the same "only depend on what's necessary" line every client in this repo draws.

The fatal-signal handler's own body isn't exercised by this test suite -- deliberately: actually
raising a fatal signal to test it would crash the test process itself, the same reason every real
crash reporter's signal path is validated by manual/integration crash testing, not a unit test.
Installation succeeding is tested; the handler's own body is not.
