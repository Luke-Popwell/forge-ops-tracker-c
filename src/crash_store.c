#include "forgeops_tracker/crash_store.h"

#include <dirent.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>

/* mkdir -p, since sys/stat.h's mkdir() only creates one level. */
static int mkdir_recursive(const char *path) {
  char buf[1024];
  size_t len = strlen(path);
  if (len == 0 || len >= sizeof(buf)) return -1;
  memcpy(buf, path, len + 1);

  for (size_t i = 1; i < len; i++) {
    if (buf[i] != '/') continue;
    buf[i] = '\0';
    if (mkdir(buf, 0755) != 0 && errno != EEXIST) return -1;
    buf[i] = '/';
  }
  if (mkdir(buf, 0755) != 0 && errno != EEXIST) return -1;
  return 0;
}

int forgeops_crash_store_write(const forgeops_configuration_t *config, const char *json_payload) {
  if (config->crash_reports_directory == NULL) return -1;
  if (mkdir_recursive(config->crash_reports_directory) != 0) return -1;

  /* now + a monotonically-increasing counter (not just a raw counter alone) so a fresh process
   * doesn't reuse a filename an earlier run already wrote, and so pending files sort chronologically
   * by name alone without needing to stat() each one. */
  static long counter = 0;
  char path[1152];
  snprintf(path, sizeof(path), "%s/event-%ld-%ld.json", config->crash_reports_directory, (long)time(NULL), counter++);

  FILE *f = fopen(path, "w");
  if (f == NULL) return -1;
  size_t len = strlen(json_payload);
  size_t written = fwrite(json_payload, 1, len, f);
  fclose(f);
  return written == len ? 0 : -1;
}

static int has_suffix(const char *s, const char *suffix) {
  size_t s_len = strlen(s);
  size_t suffix_len = strlen(suffix);
  if (suffix_len > s_len) return 0;
  return strcmp(s + (s_len - suffix_len), suffix) == 0;
}

static int compare_strings(const void *a, const void *b) {
  return strcmp(*(const char **)a, *(const char **)b);
}

char **forgeops_crash_store_pending_paths(const forgeops_configuration_t *config) {
  if (config->crash_reports_directory == NULL) return NULL;

  DIR *dir = opendir(config->crash_reports_directory);
  if (dir == NULL) return NULL;

  size_t capacity = 8;
  size_t count = 0;
  char **names = malloc(capacity * sizeof(char *));
  if (names == NULL) {
    closedir(dir);
    return NULL;
  }

  struct dirent *entry;
  while ((entry = readdir(dir)) != NULL) {
    /* Both extensions -- ".json" is a full event payload written by forgeops_report_error;
     * ".txt" is a raw signal-crash report written by the signal handler (see its own comment for
     * why that path can't safely build JSON inline). forgeops_upload_pending_reports branches on
     * which one it's looking at. */
    if (!has_suffix(entry->d_name, ".json") && !has_suffix(entry->d_name, ".txt")) continue;
    if (count == capacity) {
      capacity *= 2;
      char **grown = realloc(names, capacity * sizeof(char *));
      if (grown == NULL) break;
      names = grown;
    }
    names[count] = strdup(entry->d_name);
    if (names[count] != NULL) count++;
  }
  closedir(dir);

  if (count == 0) {
    free(names);
    return NULL;
  }

  /* File names embed time(NULL) first, so a plain string sort is already a chronological sort --
   * no need to stat() each file individually. */
  qsort(names, count, sizeof(char *), compare_strings);

  char **paths = malloc((count + 1) * sizeof(char *));
  if (paths == NULL) {
    for (size_t i = 0; i < count; i++) free(names[i]);
    free(names);
    return NULL;
  }
  for (size_t i = 0; i < count; i++) {
    size_t path_len = strlen(config->crash_reports_directory) + 1 + strlen(names[i]) + 1;
    paths[i] = malloc(path_len);
    if (paths[i] != NULL) {
      snprintf(paths[i], path_len, "%s/%s", config->crash_reports_directory, names[i]);
    }
    free(names[i]);
  }
  paths[count] = NULL;
  free(names);
  return paths;
}

void forgeops_crash_store_free_paths(char **paths) {
  if (paths == NULL) return;
  for (char **p = paths; *p != NULL; p++) free(*p);
  free(paths);
}

char *forgeops_crash_store_read(const char *path) {
  FILE *f = fopen(path, "r");
  if (f == NULL) return NULL;

  if (fseek(f, 0, SEEK_END) != 0) {
    fclose(f);
    return NULL;
  }
  long size = ftell(f);
  if (size < 0 || fseek(f, 0, SEEK_SET) != 0) {
    fclose(f);
    return NULL;
  }

  char *contents = malloc((size_t)size + 1);
  if (contents == NULL) {
    fclose(f);
    return NULL;
  }
  size_t read_bytes = fread(contents, 1, (size_t)size, f);
  fclose(f);
  contents[read_bytes] = '\0';
  return contents;
}

void forgeops_crash_store_delete(const char *path) {
  remove(path);
}
