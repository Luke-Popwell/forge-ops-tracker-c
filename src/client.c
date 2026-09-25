#include "forgeops_tracker/client.h"

#include <curl/curl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* libcurl calls this with every byte of the response body: discarded, this client never reads
 * a response, but a write callback still has to consume the data or curl treats it as an error. */
static size_t discard_response(char *ptr, size_t size, size_t nmemb, void *userdata) {
  (void)ptr;
  (void)userdata;
  return size * nmemb;
}

static int post_json(const forgeops_configuration_t *config, char *url, const char *json_payload) {
  char *api_key = forgeops_configuration_api_key(config);
  if (url == NULL || api_key == NULL) {
    free(url);
    free(api_key);
    return 0;
  }

  CURL *curl = curl_easy_init();
  if (curl == NULL) {
    free(url);
    free(api_key);
    return 0;
  }

  char auth_header[512];
  snprintf(auth_header, sizeof(auth_header), "Authorization: Bearer %s", api_key);

  struct curl_slist *headers = NULL;
  headers = curl_slist_append(headers, auth_header);
  headers = curl_slist_append(headers, "Content-Type: application/json");

  curl_easy_setopt(curl, CURLOPT_URL, url);
  curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
  curl_easy_setopt(curl, CURLOPT_POSTFIELDS, json_payload);
  curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, (long)strlen(json_payload));
  curl_easy_setopt(curl, CURLOPT_TIMEOUT, config->timeout_seconds);
  curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, discard_response);
  curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L); /* this client may run alongside its own signal handler installation: don't let libcurl install/rely on its own SIGALRM-based timeout */

  CURLcode result = curl_easy_perform(curl);
  int success = 0;
  if (result == CURLE_OK) {
    long status = 0;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &status);
    success = status >= 200 && status < 300;
  }

  curl_slist_free_all(headers);
  curl_easy_cleanup(curl);
  free(url);
  free(api_key);
  return success;
}

int forgeops_client_deliver(const forgeops_configuration_t *config, const char *json_payload) {
  return post_json(config, forgeops_configuration_ingestion_url(config), json_payload);
}

int forgeops_client_deliver_performance_samples(const forgeops_configuration_t *config, const char *json_payload) {
  return post_json(config, forgeops_configuration_performance_samples_url(config), json_payload);
}

int forgeops_client_deliver_spans(const forgeops_configuration_t *config, const char *json_payload) {
  return post_json(config, forgeops_configuration_spans_url(config), json_payload);
}

int forgeops_client_deliver_metrics(const forgeops_configuration_t *config, const char *json_payload) {
  return post_json(config, forgeops_configuration_custom_metrics_url(config), json_payload);
}

int forgeops_client_deliver_changes(const forgeops_configuration_t *config, const char *json_payload) {
  return post_json(config, forgeops_configuration_changes_url(config), json_payload);
}

int forgeops_client_deliver_infrastructure_metrics(const forgeops_configuration_t *config, const char *json_payload) {
  return post_json(config, forgeops_configuration_infrastructure_metrics_url(config), json_payload);
}
