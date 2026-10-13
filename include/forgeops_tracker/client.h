#ifndef FORGEOPS_TRACKER_CLIENT_H
#define FORGEOPS_TRACKER_CLIENT_H

#include "forgeops_tracker/configuration.h"

/*
 * Delivers one already-built JSON payload over HTTP via libcurl. Every failure mode: DNS,
 * connection, timeout, TLS, a non-2xx response: is caught here and turned into a 0 (false)
 * return rather than a crash, since a broken or unreachable tracker must never be able to break
 * the host app.
 *
 * libcurl is this client's one real dependency, the same reasoning as this repo's own C++
 * client's own libcurl dependency: plain C has no HTTP client anywhere in its standard library at
 * all (unlike Python's urllib, Go's net/http, or Java's java.net.http), and hand-rolling raw
 * HTTP/1.1-over-TLS from a bare socket is a security-sensitive undertaking no reasonable client
 * should attempt from scratch.
 */
int forgeops_client_deliver(const forgeops_configuration_t *config, const char *json_payload);

/*
 * Same delivery contract as forgeops_client_deliver, against the DSN's performance_samples
 * endpoint (see forgeops_configuration_performance_samples_url). json_payload is the whole request
 * body, already encoded: {"samples":[...]}, the shape Api::V1::PerformanceSamplesController expects.
 */
int forgeops_client_deliver_performance_samples(const forgeops_configuration_t *config, const char *json_payload);

/*
 * Same delivery contract again, against the DSN's spans endpoint (see
 * forgeops_configuration_spans_url). json_payload is the whole request body, already encoded:
 * {"trace_id":...,"spans":[...]}, the shape Api::V1::SpansController expects.
 */
int forgeops_client_deliver_spans(const forgeops_configuration_t *config, const char *json_payload);

/*
 * Same delivery contract again, against the DSN's custom metrics and infrastructure metrics endpoints
 * (see forgeops_configuration_custom_metrics_url). json_payload is the whole request body, already
 * encoded: {"metrics":[...]}.
 */
int forgeops_client_deliver_metrics(const forgeops_configuration_t *config, const char *json_payload);
int forgeops_client_deliver_infrastructure_metrics(const forgeops_configuration_t *config, const char *json_payload);

/*
 * Same delivery contract again, against the DSN's changes endpoint (see
 * forgeops_configuration_changes_url). json_payload is one change, already encoded. A 403 (a plan
 * without change tracking) is an ordinary non-2xx here: a quiet 0.
 */
int forgeops_client_deliver_changes(const forgeops_configuration_t *config, const char *json_payload);

/*
 * What became of one delivery attempt. Rejected is a 4xx other than 408 and 429: the server will
 * never take this payload, so whoever holds it lets it go instead of sending it again. Failed is
 * everything that may work later (no DSN, a network error, a timeout, a 5xx, 408, 429), so the
 * payload is kept and retried, within the bounds each caller sets.
 */
typedef enum {
  FORGEOPS_DELIVERY_DELIVERED = 0,
  FORGEOPS_DELIVERY_REJECTED = 1,
  FORGEOPS_DELIVERY_FAILED = 2
} forgeops_delivery_outcome_t;

/* The outcome an HTTP status stands for; 0 is no response at all. */
forgeops_delivery_outcome_t forgeops_delivery_outcome_for_status(long status);

/*
 * The same requests as forgeops_client_deliver, forgeops_client_deliver_performance_samples,
 * forgeops_client_deliver_metrics and forgeops_client_deliver_infrastructure_metrics, returning the
 * HTTP status instead (0 when there was no response), for the callers inside this client that hold
 * on to a payload and so need to know whether a failure is final, not only that it happened.
 */
long forgeops_client_deliver_status(const forgeops_configuration_t *config, const char *json_payload);
long forgeops_client_deliver_performance_samples_status(const forgeops_configuration_t *config, const char *json_payload);
long forgeops_client_deliver_metrics_status(const forgeops_configuration_t *config, const char *json_payload);
long forgeops_client_deliver_infrastructure_metrics_status(const forgeops_configuration_t *config, const char *json_payload);

#endif
