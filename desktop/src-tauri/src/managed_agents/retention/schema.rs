//! Additive schema migration for the retention store.
//!
//! Three columns were added after the original seven-column
//! `persona_events` table shipped, so an upgraded install has to grow its
//! table in place:
//!
//! - `event_id` — the NIP-01 id of the row's own `raw_event`. Ordering has to
//!   match the relay's NIP-33 comparator, which breaks an equal `created_at`
//!   by lowest event id; without a real column every compare would have to
//!   reparse `raw_event`.
//! - `baseline_event_id` / `baseline_content` — provenance for the record
//!   currently on disk: which event last wrote it and what that event
//!   published. This is what lets the boot pass tell "the user edited this
//!   locally" from "this store never learned about the newer relay head",
//!   instead of inferring intent from a content diff.
//!
//! # Crash and concurrency safety
//!
//! A cheap read-only probe decides whether anything is missing, and only then
//! does the migration open a `BEGIN EXCLUSIVE` transaction, re-probe inside
//! it, and apply the `ALTER TABLE`s together with the `event_id` backfill.
//! Serializing on the write lock is what makes two processes opening the same
//! database at once safe: the loser waits, re-probes, and finds nothing to do.
//! A crash mid-migration rolls back the whole transaction, so a column can
//! never exist with its backfill half-applied.

use rusqlite::{Connection, TransactionBehavior};

/// Columns added after the initial `persona_events` shape.
const ADDED_COLUMNS: [(&str, &str); 3] = [
    ("event_id", "TEXT"),
    ("baseline_event_id", "TEXT"),
    ("baseline_content", "TEXT"),
];

/// Bring `persona_events` up to the current column set.
///
/// A no-op on a database created by the current `CREATE TABLE` (and on any
/// database already migrated), so it stays on the cheap path for every open
/// after the first.
pub(super) fn migrate(conn: &mut Connection) -> Result<(), String> {
    if missing_columns(conn)?.is_empty() {
        return Ok(());
    }

    let transaction = conn
        .transaction_with_behavior(TransactionBehavior::Exclusive)
        .map_err(|e| format!("failed to open retention schema transaction: {e}"))?;

    // Re-probe under the write lock: a concurrent opener may have migrated the
    // database while this one waited for the lock.
    for (column, column_type) in missing_columns(&transaction)? {
        transaction
            .execute_batch(&format!(
                "ALTER TABLE persona_events ADD COLUMN {column} {column_type}"
            ))
            .map_err(|e| format!("failed to add retention column {column}: {e}"))?;
    }
    backfill_event_ids(&transaction)?;

    transaction
        .commit()
        .map_err(|e| format!("failed to commit retention schema migration: {e}"))
}

/// Which of [`ADDED_COLUMNS`] the table does not have yet, in declaration
/// order.
fn missing_columns(conn: &Connection) -> Result<Vec<(&'static str, &'static str)>, String> {
    let mut stmt = conn
        .prepare("SELECT name FROM pragma_table_info('persona_events')")
        .map_err(|e| format!("failed to probe retention columns: {e}"))?;
    let existing = stmt
        .query_map([], |row| row.get::<_, String>(0))
        .map_err(|e| format!("failed to read retention columns: {e}"))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| format!("failed to read retention column row: {e}"))?;

    Ok(ADDED_COLUMNS
        .into_iter()
        .filter(|(column, _)| !existing.iter().any(|name| name == column))
        .collect())
}

/// Recover `event_id` for rows written before the column existed.
///
/// The id comes from re-deriving it out of the stored event
/// ([`super::event_id_from_raw`]), never from the JSON's own `id` field: a row
/// whose stored bytes do not hash and verify to the id they claim has no
/// trustworthy ordering key, and inventing one would let it win a comparator
/// tie it should lose. Such a row keeps `event_id IS NULL` and the comparator
/// treats it as unresolved instead.
fn backfill_event_ids(conn: &Connection) -> Result<(), String> {
    let mut stmt = conn
        .prepare("SELECT rowid, raw_event FROM persona_events WHERE event_id IS NULL")
        .map_err(|e| format!("failed to prepare retention backfill query: {e}"))?;
    let rows = stmt
        .query_map([], |row| {
            Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?))
        })
        .map_err(|e| format!("failed to read retention backfill rows: {e}"))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| format!("failed to read retention backfill row: {e}"))?;

    for (rowid, raw_event) in rows {
        let Some(event_id) = super::event_id_from_raw(&raw_event) else {
            continue; // unverifiable: no ordering key rather than a fabricated one
        };
        conn.execute(
            "UPDATE persona_events SET event_id = ?1 WHERE rowid = ?2",
            rusqlite::params![event_id, rowid],
        )
        .map_err(|e| format!("failed to backfill retention event id: {e}"))?;
    }

    Ok(())
}

#[cfg(test)]
mod tests;
