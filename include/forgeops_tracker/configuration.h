#ifndef FORGEOPS_TRACKER_CONFIGURATION_H
#define FORGEOPS_TRACKER_CONFIGURATION_H

#include <stddef.h>

/*
 * Holds a single ForgeOps DSN plus everything else the client needs to build and deliver events.
 * Mirrors gems/forge_ops_tracker's Configuration: a single DSN string carries both
 * the ingestion URL and the project's api_key: "https://<api_key>@host/api/v1/events".
 *
 * Every string field is heap-owned (strdup'd) and freed by forgeops_configuration_destroy:
 * there is no ownership-transfer alternative in this API, deliberately, so a caller never has to
 * reason about who owns what.
 */
typedef struct {
  char *dsn;                       /* NULL if unset */
  char *environment;               /* never NULL: defaults to "development" */
  char *release;                   /* NULL if unset */
  char *server_name;               /* NULL if the hostname lookup failed */
  char *crash_reports_directory;   /* never NULL: see forgeops_configuration_create */
  int scrub_pii;                   /* boolean: 1 = on (the default), 0 = off */
  /*
   * Whether a backtrace frame with a real file+line (see event_builder.h's
   * forgeops_source_context_json) gets a few lines of source read off disk around it. Boolean:
   * 1 = on (the default), 0 = off. Defaults on so a snippet shows up with zero extra setup, but
   * this field isn't the durable protection against literal source code leaving a deployment it
   * shouldn't: ForgeOps' own per-project setting is, since it applies server-side regardless of
   * what any given app happens to have this field set to locally. Set to 0 here if this app
   * should never even attempt the disk read in the first place.
   *
   * As things stand today, this SDK's own two real capture paths never actually have a real
   * file+line to offer at all (a compiled, stripped C binary carries no source location: see
   * README.md's "Backtrace frames" section), so this field exists purely for API-shape
   * consistency with every other client in this repo; see forgeops_source_context_json's own
   * comment for the honest, tested-but-currently-unreachable-in-production story.
   */
  int capture_source_context;
  /*
   * When an error is reported with the SQL behind a failed database call (see
   * forgeops_tracker_capture_error_with_sql), send the names of the stored procedure, table and
   * view that SQL touched, so an issue says where to start looking. Names are identifiers, never
   * values, which is why this defaults on (1). capture_sql_statement is the separate, opt-in step
   * (default 0) of also sending the statement itself, with every string and number replaced by
   * "?"; off by default because even a masked statement describes your schema, and ForgeOps' own
   * per-project setting is what durably governs whether the server stores it. See
   * sql_statement.h.
   */
  int capture_sql_objects;
  int capture_sql_statement;
  /*
   * Whether forgeops_tracker_add_breadcrumb records anything at all. Boolean: 1 = on (the
   * default), 0 = off, matching every other client in this repo.
   */
  int track_breadcrumbs;
  /*
   * How many of the most recent breadcrumbs each thread keeps, oldest dropped first. 30, matching
   * every other client's default. Capped at FORGEOPS_BREADCRUMB_RING_LIMIT (see breadcrumbs.h):
   * each thread's ring is allocated once, at its first breadcrumb.
   */
  int max_breadcrumbs;
  /*
   * Whether forgeops_tracker_record_performance and the timer helpers time anything at all.
   * Boolean: 1 = on (the default), 0 = off. This client has no web framework integration, so nothing
   * is timed automatically: this only gates the manual API.
   */
  int track_performance;
  /*
   * How often the in-process tallies are flushed as one small aggregate report, in seconds, rather
   * than one network call per timed call. Matches gems/forge_ops_tracker's own default (60).
   */
  long performance_flush_interval_seconds;
  /*
   * Whether a trace (forgeops_tracker_trace_start) is sent to ForgeOps when slow. Boolean: 1 = on
   * (the default), 0 = off. With it off, a trace still starts and has an id, attached to errors
   * captured inside it and handed out by forgeops_tracker_http_span_start (see propagate_traces),
   * since that id is also what links an error here to one in another service; only span reporting
   * stops. This client has no web framework integration, so nothing starts a trace automatically.
   */
  int track_tracing;
  /* A trace is only sent when its root span took at least this many milliseconds. 1000 by default. */
  long trace_capture_threshold_ms;
  /*
   * How often the buffered forgeops_tracker_capture_metric / forgeops_tracker_capture_infrastructure_metric
   * entries are flushed as one batch, in seconds (60 by default). There is no track_metrics flag the way
   * track_performance has one: these are explicit calls the host app's own code makes, not automatic
   * instrumentation, so there is nothing to turn off that simply not calling them doesn't already do.
   */
  long metric_flush_interval_seconds;
  long infrastructure_metric_flush_interval_seconds;
  long timeout_seconds;
  /*
   * Whether forgeops_tracker_http_span_start hands back a W3C traceparent header for the outgoing
   * call, so the service being called continues this trace. Boolean: 1 = on (the default), matching
   * gems/forge_ops_tracker: the header carries the trace id that links an error here to an error
   * there, which is useful with or without spans, so it goes out even with track_tracing off.
   */
  int propagate_traces;
  /*
   * Which hosts get that header. NULL (the default) means every host. Otherwise an array of
   * trace_propagation_target_count heap strings, each matching that host and its subdomains on a dot
   * boundary, ignoring case and a leading dot ("example.com" matches "api.example.com", never
   * "badexample.com"); an empty array matches no host. Set it with
   * forgeops_configuration_set_trace_propagation_targets, which copies. Host strings only: unlike
   * the clients whose language has a standard regular expression type, there is no pattern form.
   */
  char **trace_propagation_targets;
  int trace_propagation_target_count;
  int enabled_environment_count;
  char **enabled_environments;     /* array of enabled_environment_count heap strings */
} forgeops_configuration_t;

/*
 * Seeds a Configuration from FORGE_OPS_DSN/FORGE_OPS_ENVIRONMENT/FORGE_OPS_RELEASE and sensible
 * defaults for everything else: the same env vars and defaults every other client in this repo
 * reads. Returns NULL only on allocation failure.
 */
forgeops_configuration_t *forgeops_configuration_create(void);

void forgeops_configuration_destroy(forgeops_configuration_t *config);

/* Replaces config->dsn, taking a copy of dsn (which may be NULL to clear it). */
void forgeops_configuration_set_dsn(forgeops_configuration_t *config, const char *dsn);

/*
 * The DSN's userinfo component, percent-decoded. Returns a newly-allocated string the caller must
 * free, or NULL if the DSN is unset, malformed, or has no userinfo.
 */
char *forgeops_configuration_api_key(const forgeops_configuration_t *config);

/*
 * The ingestion URL with credentials stripped out (they travel as the Authorization header
 * instead). Returns a newly-allocated string the caller must free, or NULL if the DSN is unset or
 * malformed.
 */
char *forgeops_configuration_ingestion_url(const forgeops_configuration_t *config);

/*
 * Same derivation as forgeops_configuration_ingestion_url, with the trailing "/events" swapped for
 * "/performance_samples": one DSN, two endpoints, matching the Ruby gem's own
 * Configuration#performance_samples_uri. Returns a newly-allocated string the caller must free, or
 * NULL if the DSN is unset or malformed.
 */
char *forgeops_configuration_performance_samples_url(const forgeops_configuration_t *config);

/*
 * Same derivation again, swapping the trailing "/events" for "/spans". Returns a newly-allocated
 * string the caller must free, or NULL if the DSN is unset or malformed.
 */
char *forgeops_configuration_spans_url(const forgeops_configuration_t *config);

/* Same derivation again, swapping the trailing "/events" for "/custom_metrics" and "/infrastructure_metrics". Newly-allocated, or NULL. */
char *forgeops_configuration_custom_metrics_url(const forgeops_configuration_t *config);
char *forgeops_configuration_infrastructure_metrics_url(const forgeops_configuration_t *config);

/* Same derivation again, swapping the trailing "/events" for "/changes". Newly-allocated, or NULL. */
char *forgeops_configuration_changes_url(const forgeops_configuration_t *config);

int forgeops_configuration_is_enabled(const forgeops_configuration_t *config);

/*
 * Replaces config->trace_propagation_targets with copies of hosts[0..count). hosts NULL restores the
 * default (every host); a non-NULL hosts with count 0 means no host at all. The caller keeps
 * ownership of hosts and may free it right after this returns.
 */
void forgeops_configuration_set_trace_propagation_targets(forgeops_configuration_t *config, const char **hosts, size_t count);

/* 1 if an outgoing call to host should carry a traceparent header (see propagate_traces and
 * trace_propagation_targets), 0 otherwise. A NULL or empty host only matches with no target list. */
int forgeops_configuration_should_propagate_trace(const forgeops_configuration_t *config, const char *host);

#endif
