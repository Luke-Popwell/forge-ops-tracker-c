# forgeops_tracker (C)

Plain C error/crash reporting client for a [ForgeOps](../../) instance. Requires a POSIX
platform (macOS, Linux): see "Platform" below. Targets C11.

This is a crash reporter, not a web-framework middleware: plain C has no exceptions and no web
framework of its own to hook a request-exception path into. Plain C has no exceptions at all, so
the only "automatic capture" story that actually exists here is a fatal-signal handler: see
"What gets reported automatically" below.

## Installation

There's no package registry for C the way npm/PyPI/etc. work for other languages: CMake's own
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
private, so isn't itself something `FetchContent` could ever pull directly): develop against
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

POSIX only (verified on macOS; Linux/glibc should work identically: `<execinfo.h>`,
`<regex.h>`, and `sigaction` are all standard there too, though the exact
`backtrace_symbols()` line format is confirmed on Darwin specifically, see `event_builder.c`'s own
comment). Not Windows: no `<execinfo.h>`, no POSIX signal handling, no POSIX `<regex.h>` without
extra tooling.

## Configuration

Set a DSN (from a project's settings page in ForgeOps), either via the `FORGE_OPS_DSN` environment
variable or explicitly. There's no configure-block API here: plain C has no closures to pass one
as: so `forgeops_tracker_configuration()` just hands back the shared `Configuration` struct
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
story plain C has: there's nothing resembling an uncaught-exception hook, because C has no
exceptions to begin with. Installed via a small signal handler (`signal_handler.c`); see that
file's own comment for why the handler itself has to stay this minimal (only async-signal-safe
calls are safe inside a real signal handler) and can't build a full JSON payload inline. It
restores the default signal disposition and re-raises after writing its report, so the process
still actually crashes (and produces a real OS-level crash log) exactly as it would without this
client installed: this client only reports, it never changes what the program actually does.

**An error you've already detected yourself is different**: report it explicitly:

```c
const char *keys[] = {"order_id"};
const char *values[] = {"42"};
forgeops_tracker_capture_error("ChargeDeclined", "the card was declined", keys, values, 1, NULL, NULL, 0);
```

Context here is always string-valued (`const char **keys`/`const char **values`, parallel arrays):
C has no dynamically-typed value type to build an arbitrary nested-map context out of, so a
flat set of string key/value pairs is what this API accepts.

## Identifying users

```c
const char *user_keys[] = {"id", "email"};
const char *user_values[] = {"42", "ada@example.com"};
forgeops_tracker_capture_error("ChargeDeclined", "the card was declined", NULL, NULL, 0, user_keys, user_values, 2);
```

Or `forgeops_tracker_set_user` to attach it to every subsequently reported error on this thread (an
explicit `forgeops_tracker_capture_error` call passing `user_count 0`, or a fatal signal, filled in
at upload time) until changed or cleared, rather than passing it to every call by hand, e.g. right
after authenticating a request:

```c
forgeops_tracker_set_user(user_keys, user_values, 2);
// once the request is done, or on sign-out:
forgeops_tracker_set_user(NULL, NULL, 0);
```

There's no way to automatically detect "the current user" in plain C, so this is always manual.
`forgeops_tracker_set_user` copies (`strdup`'s) every key/value pair given, so the arrays you pass
may be freed or reused immediately after the call returns. This is a plain C11 `_Thread_local`, not
a process-wide global: the right choice for a server handling more than one request at a time, each
on its own thread, the same reasoning `gems/forge_ops_tracker` documents for its own
`Thread.current` use; a single-threaded program just has the one thread's worth of state, so this
still behaves like a plain global there. A fatal-signal crash report is filled in with whoever is
"current" (on that same thread) at *upload* time, not necessarily who was current the moment it
actually crashed: the signal handler itself can never safely read this (see `signal_handler.h`'s
own comment on what's safe to touch there), the same "best effort, filled in later" treatment that
crash report's `environment`/`release`/`server_name` already get. `id`/`email`/`username` keys are
all independently optional; there's no fixed key list enforced, follow whatever shape your own app
uses. Shows up on an issue's own detail page, and as its own affected-users count alongside the
regular event count.

## Breadcrumbs

A small, bounded trail of recent events attached to whatever gets reported next, so an issue's
detail page can show what led up to it, not just the moment it happened:

```c
const char *data_keys[] = {"order_id"};
const char *data_values[] = {"42"};
forgeops_tracker_add_breadcrumb("charging card", "payment", "info", data_keys, data_values, 1);
forgeops_tracker_add_breadcrumb("opened checkout", NULL, NULL, NULL, NULL, 0); /* "custom", "info" */
```

`category`/`level` may be `NULL` (plain C has no default arguments), meaning `"custom"`/`"info"`.
Only the 30 most recent (`config->max_breadcrumbs`, at most 100) are kept per thread, oldest
dropped first; turn it off with `config->track_breadcrumbs = 0`. Every string is copied, so what you
pass may be freed or reused right after the call. `message` and data values are PII-scrubbed when
they're *added*, not when reported (see below for why); `category`, `level`, and `timestamp` never
are. Each entry is capped to a fixed 1 KB slot: an oversized one loses data pairs from the end
first, then has its message shortened (never mid-UTF-8-character). Omitted from the payload
entirely when the trail is empty.

There's no framework integration in this client to record one from automatically, so every
breadcrumb here is one you add by hand. Like `forgeops_tracker_set_user`, the trail is a plain
per-thread value: right for a server that handles one request per thread, but a thread that serves
several units of work in a row (a thread pool worker, say) must call
`forgeops_tracker_clear_breadcrumbs()` itself at the start of each one, or the previous one's trail
carries over.

**A fatal signal keeps its breadcrumbs too, exactly.** Each thread's trail lives in a small
heap-allocated ring of already-JSON-encoded entries (pointed to by a `_Thread_local`), and the
signal handler runs on the crashing thread, so it can walk that ring with plain reads and `write()`
each entry straight into the raw crash report, with no allocation: the next launch's upload turns
those lines into the report's `breadcrumbs` array. That's also why scrubbing happens at add time: a
raw report can't be scrubbed later. Unlike this repo's Objective-C and Swift clients, no separate
file on disk is needed, since there the handler can't read Foundation state at all.

## Performance monitoring

Times whatever you wrap and reports one small aggregate per transaction (how many times it ran,
total and maximum duration) every `config->performance_flush_interval_seconds` (60 by default), for
the Performance page's per-transaction table. Not one network call per timed call.

```c
forgeops_performance_timer_t timer = forgeops_tracker_performance_start("GET /users/:id");
handle_request(request);
forgeops_tracker_performance_stop(&timer);

/* Or record a duration you measured yourself, in milliseconds: */
forgeops_tracker_record_performance("nightly-export", elapsed_ms);
```

Plain C has no closures to pass a block to time, so the timer helpers bracket it instead. This
client has no web framework integration, so **nothing is timed automatically**: you choose what to
wrap. Keep transaction names low-cardinality (`"GET /users/:id"`, not `"GET /users/42"`): every
distinct name is its own row, and at most 500 are kept per process (past that, a new name is dropped
while existing ones keep counting), so a name accidentally built from an id can't grow the process
without bound. The name is copied when recorded, but a timer only keeps the pointer until its
`stop`: pass a string that outlives the call, typically a literal. Turn it off with
`config->track_performance = 0`; it also does nothing when reporting isn't enabled for the current
environment.

**This is the one feature that starts a thread.** The rest of this client never does (a crash
report is written now and uploaded by an explicit call), but a periodic flush has no call site to
piggyback on. So the first recorded duration starts one joinable `pthread` that sleeps on a
condition variable between flushes, and registers an `atexit` hook that flushes the last partial
window on a normal exit. Both block on libcurl for up to `config->timeout_seconds`, never the caller
of `record`/`stop`. A process that exits some other way (a fatal signal, `_exit`) loses the last
window, like anything queued in memory. `forgeops_tracker_flush_performance()` sends it right now.

A failed delivery keeps every tally, so the next flush's window just grows. What a flush delivered
is *subtracted* from the tallies afterward, never the whole set cleared: a record that lands from
another thread while the network call is in flight (the lock is deliberately released around it)
would otherwise be silently discarded, a real bug `sdks/go` had and fixed and that
`gems/forge_ops_tracker`'s reference implementation still has. A deterministic test pins this.

## Distributed tracing

A slow call's own breakdown: which database calls, HTTP calls, or pieces of your code the time went
to, shown as a span tree on ForgeOps. Bracket the unit of work with `trace_start`/`trace_stop`, and
anything inside it, on the same thread, can add spans; the trace is sent only when the whole thing
took at least `trace_capture_threshold_ms` (1000 by default), so fast calls cost nothing on the
wire. Traces are per service; nothing is propagated across services.

```c
forgeops_trace_t trace = forgeops_tracker_trace_start();

forgeops_span_t span = forgeops_tracker_span_start("charge card", "service");
charge(order);
const char *keys[] = {"order_id"};
const char *values[] = {"42"};
forgeops_tracker_span_stop_with_data(&span, keys, values, 1);

/* Something you timed yourself (started_at is wall-clock milliseconds since the epoch): */
forgeops_tracker_record_span("SELECT orders", "database", started_at_ms, duration_ms, NULL, NULL, 0);

forgeops_tracker_trace_stop(&trace, "GET /checkout");
```

`kind` is one of `controller`, `service`, `database`, `redis`, `http`, `job`, `other`; `NULL` or
anything else is sent as `other`, since the server rejects a whole trace over one unknown kind.
This client has no web framework integration, so **nothing starts a trace or records a span
automatically**: you bracket what you want traced. A `trace_start` inside an open trace does not
start a second one, and its `trace_stop` does nothing. Plain C has no closures, so a span is a value
you start and stop yourself; stopping one twice records it once, and every call outside a trace is a
no-op. The trace lives in a `_Thread_local`, like the breadcrumb trail: call `trace_stop` on the same
thread that called `trace_start`. A trace holds at most 500 spans.

Like the performance flusher, delivery runs on one background pthread (started on the first finished
slow trace) fed by a bounded queue (a full queue drops the trace rather than blocking the caller),
plus an `atexit` hook that drains what is left on a normal exit; a process that exits some other way
loses it. Turn the feature off with `config->track_tracing = 0`.

## Custom metrics and infrastructure monitoring

Two explicit calls (nothing is automatic, so there is no `track_metrics` flag): a business event you
name yourself, and a reading from one of your own hosts.

```c
forgeops_tracker_capture_metric("signup", 1.0);    /* a bare counter */
forgeops_tracker_capture_metric("payment", 49.0);  /* a real magnitude; it may be negative (a refund) */

forgeops_tracker_capture_infrastructure_metric("cpu", 0.42, NULL);    /* NULL means config->server_name */
forgeops_tracker_capture_infrastructure_metric("disk", 0.81, "db-1");
forgeops_tracker_flush_metrics();                                     /* send right now */
```

Each capture is buffered and flushed as one batch every `metric_flush_interval_seconds` /
`infrastructure_metric_flush_interval_seconds` (60 by default) on a background pthread started at the
first capture, and once more by an `atexit` hook on a normal exit, so a short-lived cron program that
captures a few readings and returns from `main` needs nothing more (a test runs exactly that in a
forked child); call `forgeops_tracker_flush_metrics()` if it might exit another way (`_exit`, a
signal). Every entry is stored as it was captured (a signup is a row, not a running total), so a count
or sum you compute later is exact. Both are a no-op when reporting isn't enabled for the environment,
and names are copied.

A failed delivery keeps every entry for the next flush, and an entry captured while a delivery is in
flight is kept too (the Ruby gem's own buffer loses it; a test pins this with a hook that captures at
exactly that moment). Each buffer holds at most 1000 entries and drops further ones until a flush
succeeds, since a plan without the feature rejects every flush and would otherwise grow it for as long
as the process lives. A NaN or infinite value is dropped at capture: `printf` would write `nan`/`inf`,
which is not valid JSON and would make the server reject the whole batch behind it. Requires a
ForgeOps plan that includes custom metrics / infrastructure monitoring.

## Why a report always uploads on the *next* call, not live during the error itself

A fatal signal means the process is about to terminate, possibly abnormally: there's no safe way
to make a live network call from inside that handler. Instead, every report (crash or explicit) is
written to disk first (`crash_store.c`, a small durable "queue" that survives the process dying,
rather than held live in memory) and only actually sent over the network by
`forgeops_tracker_upload_pending_reports()`: called once automatically by
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
the fact (how native crash reporters work): out of scope for a client
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
C binary carries no source location at runtime at all: `backtrace_symbols()` gives a binary image
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
development that this doesn't cause false negatives against any of this client's own test inputs:
every pattern still requires its own literal delimiters (a leading `"AKIA"`, a `"-"` between SSN
groups, and so on), so dropping `\b` only risks a slightly *wider* match, never a narrower one that
misses real PII. See `pii_scrubber.c`'s own top comment for the full reasoning.

The message, backtrace, and any context you attach are scanned for likely personal data (email
addresses, formatted SSNs/credit cards, known API key/token formats, and anything under a
suspiciously-named key like `password`, `api_key`, or `ssn`) and redacted before the
payload ever leaves this process. ForgeOps itself scrubs again on arrival regardless, so this is a
second, earlier layer, not the only one. The user attached via `forgeops_tracker_capture_error`'s
`user_keys`/`user_values` or `forgeops_tracker_set_user` above is a deliberate exception: it's
never scrubbed, since redacting it would defeat the whole point of identifying users in the first
place.

To disable it: `config->scrub_pii = 0;`

## Running the tests

```bash
cd sdks/c
cmake -B build
cmake --build build
./build/forgeops_tracker_tests
```

A hand-rolled test runner, not an external framework (Unity/CMocka/Criterion): this client has
exactly one real dependency (libcurl), and a whole test framework isn't one of its genuine needs.

The fatal-signal handler's own body isn't exercised by this test suite: deliberately: actually
raising a fatal signal to test it would crash the test process itself, the same reason a real
crash reporter's signal path is generally validated by manual/integration crash testing, not a
unit test. Installation succeeding is tested; the handler's own body is not.
