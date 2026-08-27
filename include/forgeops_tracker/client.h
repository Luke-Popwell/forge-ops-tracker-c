#ifndef FORGEOPS_TRACKER_CLIENT_H
#define FORGEOPS_TRACKER_CLIENT_H

#include "forgeops_tracker/configuration.h"

/*
 * Delivers one already-built JSON payload over HTTP via libcurl. Every failure mode -- DNS,
 * connection, timeout, TLS, a non-2xx response -- is caught here and turned into a 0 (false)
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

#endif
