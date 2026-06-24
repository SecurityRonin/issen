//! Guard for the read-only `--sql` escape hatch.
//!
//! Phase-2 lets an analyst run a raw `SELECT`/`WITH` against the case DB on the
//! [read-only handle](crate::tquery::open_read_only). Read-only at the handle
//! makes a write *physically* impossible; this guard is a second, loud layer
//! that rejects any statement containing a mutating/side-effecting keyword
//! *before* it reaches DuckDB, so the analyst gets a clear refusal ("DELETE is
//! not allowed") instead of a generic engine error — and so the intent is
//! documented in one place. Defense in depth, not the sole control.

use thiserror::Error;

/// Why a `--sql` statement was rejected by [`check_query_safe`].
#[derive(Debug, Error, PartialEq, Eq)]
pub enum SqlGuardError {
    /// A forbidden (mutating/side-effecting) keyword appeared in the statement.
    #[error(
        "refused: --sql is read-only and may not contain '{keyword}'. \
         Only SELECT/WITH queries are allowed."
    )]
    ForbiddenKeyword {
        /// The forbidden keyword that was found (upper-cased), e.g. `DROP`.
        keyword: String,
    },

    /// The statement was empty / contained no SQL.
    #[error("refused: --sql is empty")]
    Empty,
}

/// The forbidden keywords. Any of these as a whole word (case-insensitive)
/// rejects the statement. This is a deny-list layered atop the read-only handle.
const FORBIDDEN: &[&str] = &[
    "CREATE", "ALTER", "DROP", "DELETE", "UPDATE", "INSERT", "PRAGMA", "ATTACH", "DETACH", "COPY",
];

/// Reject a raw `--sql` statement that contains any forbidden keyword.
///
/// Returns `Ok(())` only for a statement free of every [`FORBIDDEN`] keyword
/// (the common case being a `SELECT`/`WITH` query). Matching is case-insensitive
/// and **whole-word** (so a column named `updated_at` or `created` does not trip
/// `UPDATE`/`CREATE`).
pub fn check_query_safe(sql: &str) -> Result<(), SqlGuardError> {
    if sql.trim().is_empty() {
        return Err(SqlGuardError::Empty);
    }
    // Tokenize on any non-alphanumeric/underscore boundary so a forbidden
    // keyword is matched only as a whole word — `updated_at`/`created` tokenize
    // to `updated_at`/`created`, never to `UPDATE`/`CREATE`. A trailing
    // `; DROP …` tokenizes `DROP` on its own and is caught.
    for token in sql.split(|c: char| !c.is_ascii_alphanumeric() && c != '_') {
        if token.is_empty() {
            continue;
        }
        let upper = token.to_ascii_uppercase();
        if let Some(kw) = FORBIDDEN.iter().find(|f| **f == upper) {
            return Err(SqlGuardError::ForbiddenKeyword {
                keyword: (*kw).to_string(),
            });
        }
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn rejects_each_forbidden_keyword() {
        let cases = [
            ("CREATE TABLE x(a int)", "CREATE"),
            ("ALTER TABLE timeline ADD c int", "ALTER"),
            ("DROP TABLE timeline", "DROP"),
            ("DELETE FROM timeline", "DELETE"),
            ("UPDATE timeline SET source='x'", "UPDATE"),
            ("INSERT INTO timeline VALUES (1)", "INSERT"),
            ("PRAGMA database_list", "PRAGMA"),
            ("ATTACH 'evil.db' AS e", "ATTACH"),
            ("DETACH e", "DETACH"),
            ("COPY timeline TO 'out.csv'", "COPY"),
        ];
        for (sql, kw) in cases {
            let err = check_query_safe(sql).expect_err(sql);
            assert_eq!(
                err,
                SqlGuardError::ForbiddenKeyword {
                    keyword: kw.to_string()
                },
                "{sql} must be rejected for {kw}"
            );
        }
    }

    #[test]
    fn rejects_forbidden_keyword_case_insensitively() {
        assert!(check_query_safe("drop table timeline").is_err());
        assert!(check_query_safe("Delete From timeline").is_err());
    }

    #[test]
    fn rejects_forbidden_keyword_hidden_after_a_select() {
        // A SELECT prefix must not launder a trailing mutation.
        assert!(check_query_safe("SELECT 1; DROP TABLE timeline").is_err());
    }

    #[test]
    fn accepts_plain_select() {
        check_query_safe("SELECT count(*) FROM timeline").expect("select is safe");
    }

    #[test]
    fn accepts_with_cte() {
        check_query_safe("WITH t AS (SELECT event_type FROM timeline) SELECT count(*) FROM t")
            .expect("WITH is safe");
    }

    #[test]
    fn accepts_columns_that_merely_contain_a_keyword_substring() {
        // `created_at` / `updated_at` are common column names; whole-word
        // matching must not reject them.
        check_query_safe("SELECT created_at, updated_at FROM timeline").expect("substring is safe");
    }

    #[test]
    fn rejects_empty() {
        assert_eq!(
            check_query_safe("   ").expect_err("empty"),
            SqlGuardError::Empty
        );
    }
}
