# Changelog

## 0.12.0 (2026-10-22)

- Strict privacy: the message fingerprint now also replaces email addresses with `<email>` and quoted
  values (`"..."`, and `'...'` when the quotes aren't part of a word) with `<str>`, before the existing
  steps. `KeyError: 'Jane Doe'` and `KeyError: 'Bob Smith'` now group together, and no guessable value sits
  behind the hash. Errors whose messages contain quotes or emails get new fingerprints once, so they open
  new issues after upgrading.

## 0.11.1 (2026-10-22)

- The README says what strict privacy does in its opening lines.

## 0.11.0 (2026-10-20)

- **Behavior change under strict privacy: a raw request path keeps only its first segment.** A span name or performance `transaction_name` holding a raw path is now sent as its first segment plus `/:path` (`/patients/jane-doe/12` is `/patients/:path`; a first segment with a digit, or over 40 characters, is `:id`), where before only segments with a digit were replaced, so a name slug like `jane-doe` went out. A route template (any segment like `:id`, `{id}`, `<int:id>`, `[slug]` or `*path`) is kept exactly as it is. New `forgeops_strict_privacy_strict_path`; `forgeops_strict_privacy_path_without_ids` is kept as another name for it. With strict privacy off, nothing changes.

## 0.10.0 (2026-10-20)

- New strict privacy mode, for apps that can't let personal or health data leave their own servers. Set `config->strict_privacy = 1` (or `FORGE_OPS_STRICT_PRIVACY=true`) and a report carries no message (a `message_fingerprint`, computed in this process, instead), no breadcrumbs, no SQL statement and no source context, only the user's `id`, and only the context keys named with `forgeops_configuration_set_privacy_allowed_fields` (or `FORGE_OPS_PRIVACY_ALLOWED_FIELDS=error_code,feature`). Fatal-signal crash reports follow the same rules. Span names keep an outbound call's method and host but never its path, a raw path in a span name or a performance sample's `transaction_name` loses its ids, and span data keeps only `db.statement` and `db.system`. Off by default; with it off nothing changes. See the README's "Strict privacy" section.

## 0.9.0 (2026-10-13)

- A delivery the server will never accept is no longer sent again and again. A response of 4xx (other than 408 and 429) now means the payload is let go: a crash or error report file is deleted, and a batch of performance samples, metrics or infrastructure readings is dropped. A network error, a timeout, a 5xx, 408 or 429 still keeps the payload for a later try, but not for good: a batch is dropped after five failed flushes in a row, at most 20 reports wait on disk (the oldest beyond that are deleted), and a report last written more than 7 days ago is deleted. Before, any failure kept the payload, so a rejected report was uploaded at every launch and a rejected batch at every flush.
- The `atexit` upload no longer gets stuck behind one bad report. It used to stop at the first failed delivery of any kind, oldest first, so a report the server rejected blocked every report behind it at every exit. A rejected report is now deleted and the pass goes on; only a failure that may pass (network down, a 5xx, 408, 429) stops it, as before.
- Pending reports are now uploaded oldest first by the time they were written, which also puts a crash report and an explicit error report in one order; before, they were ordered by file name.
- New `forgeops_client_deliver_status` (and the same for performance samples, metrics and infrastructure metrics) return the HTTP status, 0 for no response, and `forgeops_delivery_outcome_for_status` sorts one into delivered, rejected or failed. Every existing function is unchanged: `forgeops_client_deliver` and the rest still return 1 only for a 2xx.

## 0.8.1 (2026-10-07)

- The library now ships its MIT licence (`LICENSE.txt`). Earlier versions were published without one. No code changes.

## 0.8.0 (2026-10-02)

- **Behavior change: the default environment is now `"production"`, not `"development"`.** It is `FORGE_OPS_ENVIRONMENT` when that is set, else `"production"`. A program that sets a DSN and nothing else now sends, where before every capture was silently dropped. If you relied on the old default to keep a development machine quiet, set `FORGE_OPS_ENVIRONMENT=development` there (or leave the DSN unset). The enabled environments are unchanged: `production` and `staging`.
- With a DSN set and an environment that isn't enabled, the first SDK call now prints one line to stderr, once per process: `[ForgeOps] Not sending: this environment is "development", and only production, staging are enabled. Set FORGE_OPS_ENVIRONMENT=production (or add "development" to the enabled environments) to send from here.` Nothing is printed without a DSN.
- **Behavior change: an explicit `forgeops_tracker_capture_error` is now uploaded on the run that captured it.** It is still written to disk first, so a crash right after it loses nothing, but a normal exit (returning from `main`, or `exit`) now uploads it from an `atexit` hook instead of leaving it for the next launch. That hook stops at the first failed delivery, so an exit with the network down waits for one timeout at most, and the rest goes up on the next run as before. Fatal-signal crash reports are unchanged: they still go up from `forgeops_tracker_install_handlers()` on the next launch.
- New `forgeops_tracker_flush()` sends everything waiting, synchronously: pending error reports, then performance samples and both metric buffers. The README quick-start is now a complete program (configure, capture, flush) that shows up in ForgeOps on its first run.
- New `forgeops_upload_pending_reports_until_failure(config, stop_at_first_failure)` in `forgeops_tracker/reporter.h`, the lower-level form the exit hook uses.

## 0.7.0 (2026-09-29)

- SQL masking now catches values it used to let through, matching ForgeOps's own masker again: a string with a backslash-escaped quote (`'o\'brien'`, `E'o\'brien'`) is masked whole instead of leaving the rest of it visible, a string's type prefix goes with it (`E''`, `X''`, `N''`, `B''` and `U&''` each become one `?`), and hex (`0x1F`), binary (`0b101`), exponent (`3e10`, `1.5E-3`) and leading-dot (`.5`) numbers are masked. On a `database` span whose `db.system` is `mysql` or `mariadb`, "double quoted" text is a string and is masked too; on any other database it's a name and is still left alone. New `forgeops_sql_mask_for_system(statement, db_system)` in `forgeops_tracker/sql_statement.h` is that system-aware masker; `forgeops_sql_mask(statement)` keeps its signature and masks as it does with a `NULL` system.

## 0.6.0 (2026-09-25)

- A `database` span can now carry the SQL it ran, such as an embedded SQLite query: new `forgeops_tracker_span_stop_with_sql(span, statement, db_system, keys, values, count)` and `forgeops_tracker_record_span_with_sql(name, kind, started_at_unix_ms, duration_ms, statement, db_system, keys, values, count)`. The statement is masked before it leaves the process (every string and number literal becomes `?`), cut at 4000 characters, and sent in the span's data as `db.statement`, with `db.system` lowercased; either may be `NULL`. A `db.statement` passed in the data arrays of a `database` span directly is masked the same way. Both are ignored on spans of any other kind.

## 0.5.0 (2026-09-25)

- Change tracking: `forgeops_tracker_record_change(kind, title, details_keys, details_values, details_count)` records one change you made (a feature flag flipped, a config value changed, a firmware setting pushed) so ForgeOps can show it next to the errors and slowdowns that followed. `forgeops_tracker_record_change_with_options` also takes a `forgeops_change_options_t` for `environment` (default `config->environment`), `service`, `actor`, `url`, `id` (an idempotency key) and `occurred_at_unix_ms` (default now). `kind` is one of `feature_flag`, `config`, `migration`, `dependency`, `infrastructure` or `other`; `NULL` or anything else is sent as `other`. The title is cut to 200 characters, never through a multibyte UTF-8 character, and a blank one records nothing. Every string is copied, and delivery runs on a background pthread fed by a bounded queue (the same shape tracing uses) with an `atexit` hook that drains it on a normal exit, so the call never blocks on the network; a full queue or a failed delivery, including a 403 on a plan without change tracking, drops the change quietly. A no-op when reporting isn't enabled. This client sends no startup snapshot of its own.

## 0.4.0

- Distributed tracing across services, using the W3C Trace Context standard (`traceparent`). `forgeops_tracker_http_span_start(method, url)` / `forgeops_tracker_http_span_stop(&span)` (and `_stop_with_data`) record an outgoing HTTP call as an `http` span named after the method and host, and hand back the header to send with that request in the returned `forgeops_http_span_t`: `traceparent` (the bare value) and `header` (the whole `traceparent: <value>` line, ready for `curl_slist_append`), both empty when there is nothing to send. Its parent id is the span's own id, so the called service's root span nests under it. `forgeops_tracker_trace_start_with_traceparent(traceparent)` continues an incoming request's trace (same trace id, root span parented under the caller's span); `NULL` or a malformed value starts a fresh trace. New `propagate_traces` (default 1) and `trace_propagation_targets` (default `NULL`, meaning every host; set with `forgeops_configuration_set_trace_propagation_targets(config, hosts, count)`, each host matching itself and its subdomains) control where the header goes. Host strings only; there is no regular expression form.
- Errors captured inside a trace now carry a top-level `trace_id`, so ForgeOps can link them to errors from other services that handled the same request: `forgeops_tracker_capture_error` (and `_with_sql`) directly, and a fatal signal through a `#trace_id` line the handler writes into the raw report next to the breadcrumb trail. `forgeops_tracker_current_trace_id()` returns it. Errors captured outside a trace are unchanged.
- With `track_tracing = 0`, `forgeops_tracker_trace_start` still starts a trace with an id (attached to errors and propagated in the header, since that is also what links errors across services); only span reporting stops. Previously nothing started with tracing off.
- Trace and span ids were already W3C shaped (32 and 16 lowercase hex characters); they are now also guaranteed never to be all zeros, the one value the standard reserves as invalid.

This SDK has earlier tagged releases on its mirror (v0.3.0 is the latest), but no `CHANGELOG.md` existed for it before this entry; it starts here rather than backfilling every earlier version. There is no version constant in the source or `CMakeLists.txt`: a release is its git tag, so this one is `v0.4.0`.
