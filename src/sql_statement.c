/* See include/forgeops_tracker/sql_statement.h for what this does and why it's hand-rolled. */
#include "forgeops_tracker/sql_statement.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#include "strbuf.h"

#define SQL_MASK "?"
#define MAX_SQL_LENGTH 4000
#define MAX_NAMES 10
#define MAX_NAME_LENGTH 200

static int is_word(unsigned char c) { return c == '_' || isalnum(c) != 0; }
static int is_digit_char(unsigned char c) { return c >= '0' && c <= '9'; }
static int is_alpha_char(unsigned char c) { return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z'); }
static int is_space_char(unsigned char c) { return c == ' ' || (c >= '\t' && c <= '\r'); }

/* Where the number starting at i ends, or -1 when it isn't a standalone number (digits immediately
 * followed by a letter or underscore). A decimal that fails that check falls back to just its
 * integer part, the same way the shared pattern's backtracking does. */
static long number_end(const char *s, size_t len, size_t i) {
  size_t k = i;
  while (k < len && is_digit_char((unsigned char)s[k])) k++;
  size_t int_end = k;
  if (k + 1 < len && s[k] == '.' && is_digit_char((unsigned char)s[k + 1])) {
    size_t m = k + 1;
    while (m < len && is_digit_char((unsigned char)s[m])) m++;
    if (m >= len || !is_word((unsigned char)s[m])) return (long)m;
  }
  if (int_end >= len || !is_word((unsigned char)s[int_end])) return (long)int_end;
  return -1;
}

char *forgeops_sql_mask(const char *statement) {
  if (statement == NULL) return NULL;
  size_t len = strlen(statement);
  size_t first = 0;
  while (first < len && is_space_char((unsigned char)statement[first])) first++;
  if (first == len) return NULL;

  forgeops_strbuf_t out;
  if (forgeops_strbuf_init(&out, len + 8) != 0) return NULL;

  const char *s = statement;
  size_t i = 0;
  while (i < len) {
    unsigned char c = (unsigned char)s[i];
    if (c == '\'') {
      /* A string literal; '' is an escaped quote. One cut off by truncation (no closing quote) is
       * masked to the end of the statement, never left half-visible. */
      size_t j = i + 1;
      while (j < len) {
        if (s[j] == '\'') {
          if (j + 1 < len && s[j + 1] == '\'') {
            j += 2;
            continue;
          }
          j++;
          break;
        }
        j++;
      }
      forgeops_strbuf_append_str(&out, SQL_MASK);
      i = j;
    } else if (c == '$') {
      /* A dollar-quoted body ($tag$ ... $tag$): PostgreSQL function bodies and DO blocks. */
      size_t j = i + 1;
      while (j < len && (s[j] == '_' || is_alpha_char((unsigned char)s[j]))) j++;
      if (j < len && s[j] == '$') {
        size_t tag_len = j - i + 1;
        size_t end = len;
        for (size_t k = j + 1; k + tag_len <= len; k++) {
          if (memcmp(s + k, s + i, tag_len) == 0) {
            end = k + tag_len;
            break;
          }
        }
        forgeops_strbuf_append_str(&out, SQL_MASK);
        i = end;
      } else {
        forgeops_strbuf_append(&out, s + i, 1);
        i++;
      }
    } else if (is_digit_char(c)) {
      /* A number, unless it's part of an identifier (orders2, sp_v2), a $1 placeholder, or the
       * fraction of another number; those digits are left alone. */
      int part_of_something = i > 0 && (is_word((unsigned char)s[i - 1]) || s[i - 1] == '$' || s[i - 1] == '.');
      long end = part_of_something ? -1 : number_end(s, len, i);
      if (end >= 0) {
        forgeops_strbuf_append_str(&out, SQL_MASK);
        i = (size_t)end;
      } else {
        forgeops_strbuf_append(&out, s + i, 1);
        i++;
      }
    } else {
      forgeops_strbuf_append(&out, s + i, 1);
      i++;
    }
  }

  if (out.length > MAX_SQL_LENGTH) {
    /* Cut back to a UTF-8 character boundary so the result is still valid text. */
    size_t cut = MAX_SQL_LENGTH;
    while (cut > 0 && ((unsigned char)out.data[cut] & 0xC0) == 0x80) cut--;
    out.data[cut] = '\0';
    out.length = cut;
    forgeops_strbuf_append_str(&out, "...");
  }
  return out.data;
}

/* ---- tokenizer --------------------------------------------------------------------------------- */

typedef struct {
  char *text;
  int is_name;
} token_t;

typedef struct {
  token_t *items;
  size_t count;
  size_t capacity;
} tokens_t;

typedef struct {
  char **items;
  size_t count;
  size_t capacity;
} list_t;

static int is_bare_char(unsigned char c) { return is_word(c) || c == '$' || c == '#' || c == '@'; }

/* Where the identifier part starting at i ends, or -1: bare (letters, digits, _ $ # @), "double
 * quoted", [bracketed] (SQL Server) or `backticked`. */
static long name_part_end(const char *s, size_t len, size_t i) {
  if (i >= len) return -1;
  unsigned char c = (unsigned char)s[i];
  if (is_bare_char(c)) {
    size_t j = i;
    while (j < len && is_bare_char((unsigned char)s[j])) j++;
    return (long)j;
  }
  if (c == '"' || c == '`' || c == '[') {
    char closer = c == '[' ? ']' : (char)c;
    size_t j = i + 1;
    while (j < len && s[j] != closer) j++;
    if (j < len && j > i + 1) return (long)(j + 1);
  }
  return -1;
}

/* Where the (optionally schema-qualified) name starting at i ends, or -1. */
static long name_end(const char *s, size_t len, size_t i) {
  long end = name_part_end(s, len, i);
  if (end < 0) return -1;
  while ((size_t)end < len && s[end] == '.') {
    long next = name_part_end(s, len, (size_t)end + 1);
    if (next < 0) break;
    end = next;
  }
  return end;
}

static char *dup_range(const char *s, size_t from, size_t to) {
  char *copy = malloc(to - from + 1);
  if (copy == NULL) return NULL;
  memcpy(copy, s + from, to - from);
  copy[to - from] = '\0';
  return copy;
}

static int tokens_push(tokens_t *tokens, char *text, int is_name) {
  if (text == NULL) return -1;
  if (tokens->count == tokens->capacity) {
    size_t capacity = tokens->capacity == 0 ? 32 : tokens->capacity * 2;
    token_t *grown = realloc(tokens->items, capacity * sizeof(token_t));
    if (grown == NULL) {
      free(text);
      return -1;
    }
    tokens->items = grown;
    tokens->capacity = capacity;
  }
  tokens->items[tokens->count].text = text;
  tokens->items[tokens->count].is_name = is_name;
  tokens->count++;
  return 0;
}

static void tokens_free(tokens_t *tokens) {
  for (size_t i = 0; i < tokens->count; i++) free(tokens->items[i].text);
  free(tokens->items);
  tokens->items = NULL;
  tokens->count = tokens->capacity = 0;
}

static int tokenize(const char *s, tokens_t *tokens) {
  size_t len = strlen(s);
  size_t i = 0;
  while (i < len) {
    if (is_space_char((unsigned char)s[i])) {
      i++;
      continue;
    }
    long end = name_end(s, len, i);
    if (end >= 0) {
      if (tokens_push(tokens, dup_range(s, i, (size_t)end), 1) != 0) return -1;
      i = (size_t)end;
      continue;
    }
    /* Any other byte is its own token. A multi-byte UTF-8 character becomes several one-byte
     * tokens, which no keyword rule below ever matches, so it's harmless. */
    if (tokens_push(tokens, dup_range(s, i, i + 1), 0) != 0) return -1;
    i++;
  }
  return 0;
}

static int list_push(list_t *list, const char *text) {
  if (list->count == list->capacity) {
    size_t capacity = list->capacity == 0 ? 8 : list->capacity * 2;
    char **grown = realloc(list->items, capacity * sizeof(char *));
    if (grown == NULL) return -1;
    list->items = grown;
    list->capacity = capacity;
  }
  list->items[list->count] = strdup(text);
  if (list->items[list->count] == NULL) return -1;
  list->count++;
  return 0;
}

static void list_free(list_t *list) {
  for (size_t i = 0; i < list->count; i++) free(list->items[i]);
  free(list->items);
  list->items = NULL;
  list->count = list->capacity = 0;
}

static int is_full_name(const char *name) {
  size_t len = strlen(name);
  return len > 0 && name_end(name, len, 0) == (long)len;
}

static int in_set(const char *word, const char *const *set) {
  for (; *set != NULL; set++) {
    if (strcasecmp(word, *set) == 0) return 1;
  }
  return 0;
}

static const char *const OPERATIONS[] = {"SELECT", "INSERT", "UPDATE", "DELETE", "MERGE", "WITH", "CALL", "EXEC", "EXECUTE", "CREATE", "ALTER", "DROP", "TRUNCATE", NULL};
static const char *const BUILTINS[] = {"count", "sum", "min", "max", "avg", "now", "coalesce", "nullif", "lower", "upper", "length", "concat", "cast", "date_trunc", "current_timestamp", "current_date", "row_number", "rank", "json_build_object", "json_agg", "array_agg", NULL};
static const char *const KEYWORDS_NOT_NAMES[] = {"select", "set", "values", "where", "lateral", "only", "unnest", "generate_series", NULL};
static const char *const PROCEDURE_KEYWORDS[] = {"call", "exec", "execute", "perform", NULL};
static const char *const NOT_PROCEDURE_NAMES[] = {"immediate", "function", "procedure", NULL};
static const char *const RELATION_KEYWORDS[] = {"from", "join", "into", "update", "table", NULL};
static const char *const FUNCTION_LIKE_SKIPPED[] = {"extract", "substring", "trim", "overlay", NULL};

/* Trims, caps, validates and de-duplicates `names` in place (freeing what it drops). */
static void clean_list(list_t *names) {
  size_t kept = 0;
  for (size_t i = 0; i < names->count; i++) {
    char *name = names->items[i];
    size_t start = 0;
    size_t end = strlen(name);
    while (start < end && is_space_char((unsigned char)name[start])) start++;
    while (end > start && is_space_char((unsigned char)name[end - 1])) end--;
    if (end - start > MAX_NAME_LENGTH) end = start + MAX_NAME_LENGTH;
    memmove(name, name + start, end - start);
    name[end - start] = '\0';

    int duplicate = 0;
    for (size_t k = 0; k < kept; k++) {
      if (strcmp(names->items[k], name) == 0) {
        duplicate = 1;
        break;
      }
    }
    if (!is_full_name(name) || duplicate || kept >= MAX_NAMES) {
      free(name);
      continue;
    }
    names->items[kept++] = name;
  }
  names->count = kept;
}

static void append_json_string(forgeops_strbuf_t *out, const char *value) {
  forgeops_strbuf_append(out, "\"", 1);
  for (const unsigned char *p = (const unsigned char *)value; *p != '\0'; p++) {
    switch (*p) {
      case '"': forgeops_strbuf_append(out, "\\\"", 2); break;
      case '\\': forgeops_strbuf_append(out, "\\\\", 2); break;
      case '\n': forgeops_strbuf_append(out, "\\n", 2); break;
      case '\r': forgeops_strbuf_append(out, "\\r", 2); break;
      case '\t': forgeops_strbuf_append(out, "\\t", 2); break;
      default:
        if (*p < 0x20) {
          char escaped[8];
          snprintf(escaped, sizeof(escaped), "\\u%04x", *p);
          forgeops_strbuf_append_str(out, escaped);
        } else {
          forgeops_strbuf_append(out, (const char *)p, 1);
        }
    }
  }
  forgeops_strbuf_append(out, "\"", 1);
}

static void append_json_list(forgeops_strbuf_t *out, const list_t *list) {
  forgeops_strbuf_append(out, "[", 1);
  for (size_t i = 0; i < list->count; i++) {
    if (i > 0) forgeops_strbuf_append(out, ",", 1);
    append_json_string(out, list->items[i]);
  }
  forgeops_strbuf_append(out, "]", 1);
}

char *forgeops_sql_objects_json(const char *masked) {
  if (masked == NULL) return NULL;
  size_t masked_len = strlen(masked);
  size_t first = 0;
  while (first < masked_len && is_space_char((unsigned char)masked[first])) first++;
  if (first == masked_len) return NULL;

  tokens_t all = {0};
  tokens_t kept = {0};
  list_t procedures = {0};
  list_t relations = {0};
  char *result = NULL;
  char operation[16] = "";
  int ok = tokenize(masked, &all) == 0;

  /* EXTRACT(year FROM col), SUBSTRING(x FROM 2), TRIM(BOTH FROM x): a FROM that isn't a table.
   * `kept` borrows the token structs from `all` (its texts are freed via `all`), so it's released
   * with a plain free of the array only. */
  for (size_t i = 0; ok && i < all.count; i++) {
    token_t *t = &all.items[i];
    if (t->is_name && in_set(t->text, FUNCTION_LIKE_SKIPPED) && i + 1 < all.count && strcmp(all.items[i + 1].text, "(") == 0) {
      long close = -1;
      for (size_t j = i + 2; j < all.count; j++) {
        if (strcmp(all.items[j].text, "(") == 0) break;
        if (strcmp(all.items[j].text, ")") == 0) {
          close = (long)j;
          break;
        }
      }
      if (close >= 0) {
        i = (size_t)close;
        continue;
      }
    }
    if (kept.count == kept.capacity) {
      size_t capacity = kept.capacity == 0 ? 32 : kept.capacity * 2;
      token_t *grown = realloc(kept.items, capacity * sizeof(token_t));
      if (grown == NULL) {
        ok = 0;
        break;
      }
      kept.items = grown;
      kept.capacity = capacity;
    }
    kept.items[kept.count++] = *t;
  }

  for (size_t i = 0; ok && i + 1 < kept.count; i++) {
    if (kept.items[i].is_name && in_set(kept.items[i].text, PROCEDURE_KEYWORDS) && kept.items[i + 1].is_name) {
      const char *name = kept.items[i + 1].text;
      size_t first_part_len = strcspn(name, ".");
      char first_part[16];
      snprintf(first_part, sizeof(first_part), "%.*s", (int)(first_part_len < 15 ? first_part_len : 15), name);
      if (first_part_len < 15 && in_set(first_part, NOT_PROCEDURE_NAMES)) continue;
      if (list_push(&procedures, name) != 0) ok = 0;
      i++;
    }
  }

  for (size_t i = 0; ok && i + 1 < kept.count; i++) {
    if (!(kept.items[i].is_name && in_set(kept.items[i].text, RELATION_KEYWORDS) && kept.items[i + 1].is_name)) continue;
    const char *keyword = kept.items[i].text;
    const char *name = kept.items[i + 1].text;
    int paren = i + 2 < kept.count && strcmp(kept.items[i + 2].text, "(") == 0;
    i++;
    if (in_set(name, KEYWORDS_NOT_NAMES)) continue;
    /* FROM/JOIN some_function(...) is a set-returning function (often a stored one), not a table.
     * INSERT INTO t (a, b) is just a column list, so INTO/UPDATE/TABLE never count. */
    int function_call = paren && (strcasecmp(keyword, "from") == 0 || strcasecmp(keyword, "join") == 0);
    if (list_push(function_call ? &procedures : &relations, name) != 0) ok = 0;
  }

  if (ok && kept.count >= 3 && kept.items[0].is_name && strcasecmp(kept.items[0].text, "select") == 0 && kept.items[1].is_name &&
      strcmp(kept.items[2].text, "(") == 0 && !in_set(kept.items[1].text, BUILTINS)) {
    int has_from = 0;
    for (size_t i = 0; i < kept.count; i++) {
      if (kept.items[i].is_name && strcasecmp(kept.items[i].text, "from") == 0) {
        has_from = 1;
        break;
      }
    }
    if (!has_from && list_push(&procedures, kept.items[1].text) != 0) ok = 0;
  }

  if (ok && kept.count > 0) {
    const char *word = kept.items[0].text;
    size_t end = 0;
    while (word[end] != '\0' && is_word((unsigned char)word[end])) end++;
    if (end > 0 && end < sizeof(operation)) {
      char candidate[16];
      memcpy(candidate, word, end);
      candidate[end] = '\0';
      if (in_set(candidate, OPERATIONS)) {
        for (size_t i = 0; i <= end; i++) operation[i] = (char)toupper((unsigned char)candidate[i]);
      }
    }
  }

  if (ok) {
    clean_list(&procedures);
    clean_list(&relations);
    if (procedures.count > 0 || relations.count > 0 || operation[0] != '\0') {
      forgeops_strbuf_t out;
      if (forgeops_strbuf_init(&out, 128) == 0) {
        forgeops_strbuf_append(&out, "{", 1);
        if (operation[0] != '\0') {
          forgeops_strbuf_append_str(&out, "\"operation\":");
          append_json_string(&out, operation);
          forgeops_strbuf_append(&out, ",", 1);
        }
        forgeops_strbuf_append_str(&out, "\"procedures\":");
        append_json_list(&out, &procedures);
        forgeops_strbuf_append_str(&out, ",\"relations\":");
        append_json_list(&out, &relations);
        forgeops_strbuf_append(&out, "}", 1);
        result = out.data;
      }
    }
  }

  free(kept.items);
  tokens_free(&all);
  list_free(&procedures);
  list_free(&relations);
  return result;
}
