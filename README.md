# forgeops_tracker (C)

Plain C error/crash reporting client for a [ForgeOps](../../) instance. Requires a POSIX
platform (macOS, Linux) -- see "Platform" below. Targets C11.

This is a crash reporter, not a web-framework middleware: plain C has no exceptions and no web
framework of its own to hook a request-exception path into. Plain C has no exceptions at all, so
the only "automatic capture" story that actually exists here is a fatal-signal handler -- see
"What gets reported automatically" below.

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

One real dependency: **libcurl**, for HTTP delivery: plain C has no HTTP client anywhere in its
standard library, and hand-rolling raw HTTP/1.1-over-TLS from a bare socket is a
security-sensitive undertaking no reasonable client should attempt from scratch.

Everything else reaches for POSIX rather than a third-party library: `<regex.h>` for PII-pattern
matching (see "PII scrubbing" below for what POSIX ERE syntax actually supports), `<execinfo.h>`'s
`backtrace()`/`backtrace_symbols()` for stack capture, plain `<dirent.h>`/`<sys/stat.h>` file I/O
for the crash store. JSON encoding is hand-rolled (~150 lines across `event_builder.c`/
`signal_handler.c`), since plain C has no JSON support of its own at all.

### Platform

POSIX only (verified on macOS; Linux/glibc should work identically -- `<execinfo.h>`,
`<regex.h>`, and `sigaction` are all standard there too, though the exact
`backtrace_symbols()` line format is confirmed on Darwin specifically, see `event_builder.c`'s own
comment). Not Windows: no `<execinfo.h>`, no POSIX signal handling, no POSIX `<regex.h>` without
extra tooling.

## Configuration

Set a DSN (from a project's settings page in ForgeOps), either via the `FORGE_OPS_DSN` environment
variable or explicitly. There's no configure-block API here -- plain C has no closures to pass one
as -- so `forgeops_tracker_configuration()` just hands back the shared `Configuration` struct
directly:

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
exceptions to begin with. Installed via a small signal handler (`signal_handler.c`); see that
file's own comment for why the handler itself has to stay this minimal (only async-signal-safe
calls are safe inside a real signal handler) and can't build a full JSON payload inline. It
restores the default signal disposition and re-raises after writing its report, so the process
still actually crashes (and produces a real OS-level crash log) exactly as it would without this
client installed: this client only reports, it never changes what the program actually does.

**An error you've already detected yourself is different** -- report it explicitly:

```c
const char *keys[] = {"order_id"};
const char *values[] = {"42"};
forgeops_tracker_capture_error("ChargeDeclined", "the card was declined", keys, values, 1);
```

Context here is always string-valued (`const char **keys`/`const char **values`, parallel arrays)
-- C has no dynamically-typed value type to build an arbitrary nested-map context out of, so a
flat set of string key/value pairs is what this API accepts.

## Why a report always uploads on the *next* call, not live during the error itself

A fatal signal means the process is about to terminate, possibly abnormally -- there's no safe way
to make a live network call from inside that handler. Instead, every report (crash or explicit) is
written to disk first (`crash_store.c`, a small durable "queue" that survives the process dying,
rather than held live in memory) and only actually sent over the network by
`forgeops_tracker_upload_pending_reports()` -- called once automatically by
`forgeops_tracker_install_handlers()` (covering whatever crashed on a *previous* run), and safe to
call again yourself whenever else makes sense for your app (a periodic timer; right after an
explicit `forgeops_tracker_capture_error` call, since that case didn't just terminate the process
and has no particular reason to wait). A failed upload leaves the file in place for the next call
to retry.

There is no background thread doing this automatically: plain C has no runtime event loop or
built-in async story to hang one off of. If you want uploads to happen off your main thread, spawn
one yourself (pthreads, or whatever your platform's own threading story is) and call
`forgeops_tracker_upload_pending_reports()` from it.

## Backtrace frames: image + symbol, never file/line

A compiled, stripped C binary has no source file/line information left in it at runtime.
`backtrace_symbols()` gives a binary image name (closest available analog to "file") and a
resolved symbol (closest analog to "method"); `line` is always JSON `null`. `in_app` is always
`false` for every frame: a C backtrace's image name for the main executable isn't reliably
distinguishable from a system library's by name alone across platforms, so this client doesn't
attempt a heuristic that could be wrong more often than it's right.

Real line-level symbolication needs an offline pass against the binary's own debug symbols after
the fact (how native crash reporters work) -- out of scope for a client
that has to work standalone, with no external symbolication service to call.

## Source context

Every other client in this repo reads a few lines of source off disk around an in-app frame's
culprit line, gated on a `capture_source_context` option (on by default) and the frame actually
being `in_app`. This client has that same option (`config->capture_source_context`, on by
default, `int` 1/0) for API-shape consistency with the rest of this repo, and a real, independently
tested function behind it (`forgeops_source_context_json` in `event_builder.h`) that does the same
5-lines-either-side read, with the same 500-character per-line truncation, given an actual file
path and line number.

What this client does *not* have is anywhere that ever calls it with a real file path and line
number. As "Backtrace frames: image + symbol, never file/line" above explains, a compiled, stripped
C binary carries no source location at runtime at all -- `backtrace_symbols()` gives a binary image
name and a resolved symbol, never a file path or line, and every frame this client produces
(fatal-signal or explicit `forgeops_tracker_capture_error`) is `in_app: false` with `line: null` for
that same reason. `append_backtrace_json` in `event_builder.c` still calls
`forgeops_source_context_json` for every frame it builds, exactly the way every other client in
this repo wires its own equivalent call in, but it always passes `in_app: 0`, so the call always
takes its own gated-off return. In today's build, this is a real, exercised, and documented no-op:
not a stub that was never wired up, and not a fake implementation pretending to do something it
can't, just a genuinely correct function with nothing valid to feed it from this client's own two
capture paths. It's kept (rather than left out) so this client's public API shape matches every
other one in this repo, and so it's ready the moment there is a real file+line to give it, such as
an explicit capture API that accepted one directly, which doesn't exist yet.

To turn the option off anyway (there's nothing for it to disable today, but it's there):

```c
config->capture_source_context = 0;
```

## PII scrubbing

PII pattern matching uses POSIX Extended Regular Expressions (`<regex.h>`), the only regex engine
available in the C standard library: `\d`/`\s` translate directly (`[0-9]`/`[[:space:]]`); `\b`
(word boundary) has no POSIX equivalent at all, so the boundary-sensitive patterns (JWT, AWS key,
Stripe key, GitHub token, bearer token, SSN) simply don't require one here. Verified directly during
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
exactly one real dependency (libcurl), and a whole test framework isn't one of its genuine needs.

The fatal-signal handler's own body isn't exercised by this test suite -- deliberately: actually
raising a fatal signal to test it would crash the test process itself, the same reason a real
crash reporter's signal path is generally validated by manual/integration crash testing, not a
unit test. Installation succeeding is tested; the handler's own body is not.
