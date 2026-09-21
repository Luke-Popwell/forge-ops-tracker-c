#ifndef FORGEOPS_TRACKER_SQL_STATEMENT_H
#define FORGEOPS_TRACKER_SQL_STATEMENT_H

/*
 * Reduces the SQL behind a database error to something safe to send: the names of the stored
 * procedures, tables and views it touched, and (only if the configuration's capture_sql_statement
 * is on) the statement itself with every string and number replaced by "?". Ported from
 * gems/forge_ops_tracker's SqlStatement, which is itself ported from the server's own
 * SqlStatementMasker/SqlObjectExtractor: same rules everywhere, and the server applies them again
 * on arrival, so a difference here can only ever mean less is masked client-side, never that
 * something unmasked gets stored.
 *
 * Hand-rolled scanner and tokenizer rather than regular expressions: POSIX regcomp has no
 * lookbehind and no backreferences, which the shared pattern relies on (a number is only a value
 * when it isn't part of an identifier, and a dollar-quoted body ends at the same tag that opened
 * it). The rules are identical; only the mechanism differs. Deliberately not a SQL parser.
 *
 * A C program has no exception type that could carry the statement, so the code that ran the
 * query hands it over explicitly: forgeops_tracker_capture_error_with_sql.
 */

/* Returns a newly-allocated copy of `statement` with every string literal and number replaced by
 * "?", truncated to 4000 characters, or NULL for a NULL/blank statement (or on allocation
 * failure). The caller must free a non-NULL return value. */
char *forgeops_sql_mask(const char *statement);

/* Takes an already-masked statement (so a keyword inside a string value can't be mistaken for SQL)
 * and returns the names it touched as a newly-allocated JSON object,
 * {"operation":"EXEC","procedures":[...],"relations":[...]}, or NULL when nothing recognizable was
 * found. A view and a table are written the same way in SQL text, so both land in "relations". The
 * caller must free a non-NULL return value. */
char *forgeops_sql_objects_json(const char *masked);

#endif
