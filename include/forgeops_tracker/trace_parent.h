#ifndef FORGEOPS_TRACKER_TRACE_PARENT_H
#define FORGEOPS_TRACKER_TRACE_PARENT_H

#include <stddef.h>

/*
 * Reads and writes the W3C Trace Context "traceparent" header (https://www.w3.org/TR/trace-context/),
 * the vendor-neutral format for carrying one trace across service boundaries:
 * "00-<32 hex trace id>-<16 hex parent span id>-<2 hex flags>". Mirrors gems/forge_ops_tracker's own
 * TraceParent: forgeops_traceparent_parse lets forgeops_tracker_trace_start_with_traceparent continue a
 * caller's trace, and forgeops_traceparent_build is what forgeops_tracker_http_span_start hands over for
 * the next service along. Internal: the public API is in forgeops_tracker.h.
 *
 * Strict on the way in, the posture the spec asks receivers to take: a malformed value, uppercase hex,
 * the reserved version "ff", or an all-zero trace or parent id all mean "no usable header" (parse
 * returns 0 and a fresh trace starts), never half-trusted. A future version is still accepted when its
 * first four fields have version 00's shape; version 00 itself must have exactly four.
 */

#define FORGEOPS_TRACEPARENT_HEADER "traceparent"
#define FORGEOPS_TRACE_ID_LENGTH 32
#define FORGEOPS_TRACE_SPAN_ID_LENGTH 16
/* "00-" + 32 + "-" + 16 + "-01" plus the terminating NUL. */
#define FORGEOPS_TRACEPARENT_SIZE 56
/* "traceparent: " + a whole value plus the terminating NUL: a ready-made libcurl header line. */
#define FORGEOPS_TRACEPARENT_HEADER_LINE_SIZE 69

/*
 * Parses value. On success returns 1 and fills trace_id (33 bytes) and parent_span_id (17 bytes);
 * returns 0 for NULL or anything unusable, leaving both untouched. Surrounding whitespace is ignored.
 */
int forgeops_traceparent_parse(const char *value, char *trace_id, char *parent_span_id);

/* Writes "00-<trace_id>-<span_id>-01" into out (FORGEOPS_TRACEPARENT_SIZE bytes). */
void forgeops_traceparent_build(const char *trace_id, const char *span_id, char *out);

/*
 * Fills out with hex_length lowercase hex characters (32 for a trace id, 16 for a span id, at most 32)
 * plus a NUL, never all zeros: the one value the spec reserves as invalid.
 */
void forgeops_trace_random_id(char *out, size_t hex_length);

/*
 * The host of an absolute URL ("scheme://[userinfo@]host[:port]/..."), lowercased, into out. Returns
 * 1 on success, 0 when url is NULL, has no "scheme://", no host, or a host that doesn't fit in
 * out_size (out is then ""). An IPv6 literal keeps its brackets.
 */
int forgeops_url_host(const char *url, char *out, size_t out_size);

#endif
