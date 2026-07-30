//! Local SQLite retention store for persona events.
//!
//! Provides durable client-side storage for persona events, enabling offline
//! boot when the relay is unreachable. Upserts via `ON CONFLICT DO UPDATE`
//! keyed on `(kind, pubkey, d_tag)`, replacing only on a newer-or-equal
//! `created_at` for NIP-33 latest-wins semantics.

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use rusqlite::{params, Connection, OptionalExtension};
use sha2::{Digest, Sha256};
use tauri::AppHandle;

use crate::app_state::AppState;

mod legacy_migration;
mod schema;
pub use legacy_migration::migrate_legacy_retention_db;

/// Durable event-retention scope for one community relay and owner identity.
///
/// Persona, team, and managed-agent definitions are workspace-global, but
/// their relay heads and pending publications are not. Keeping a separate
/// database per `(relay_url, owner_pubkey)` prevents a pending write created in
/// community A from being drained into community B after a workspace switch.
pub struct RetentionScope {
    pub db_path: PathBuf,
    pub relay_url: String,
    pub owner_keys: nostr::Keys,
}

/// Decide whether `scope` — the workspace's active retention scope — is the one
/// that owns an event delivered by `arrival_relay_url`.
///
/// Inbound reconcile resolves its retention database when it PROCESSES an event,
/// while the event belongs to the community that DELIVERED it. `None` means a
/// workspace switch happened in between and the caller must drop the event
/// rather than file community A's event into community B's store.
///
/// The comparison goes through the same normalization
/// [`scoped_retention_db_path`] hashes, so "same relay" can never disagree with
/// "same database".
pub fn scope_for_arrival(scope: RetentionScope, arrival_relay_url: &str) -> Option<RetentionScope> {
    let same_scope =
        normalized_relay_scope(&scope.relay_url) == normalized_relay_scope(arrival_relay_url);
    same_scope.then_some(scope)
}

/// Relay-URL form that identifies a retention scope: equivalent workspace URLs
/// (surrounding space, trailing slash) must resolve to one scope.
fn normalized_relay_scope(relay_url: &str) -> &str {
    relay_url.trim().trim_end_matches('/')
}

/// Resolve the retention database path for a relay + owner pair.
///
/// The normalized scope is hashed so relay URLs never become path components.
/// Trimming a trailing slash keeps equivalent workspace URLs on one scope.
pub fn scoped_retention_db_path(base_dir: &Path, relay_url: &str, owner_pubkey: &str) -> PathBuf {
    let normalized_relay = normalized_relay_scope(relay_url);
    let mut hasher = Sha256::new();
    hasher.update(owner_pubkey.trim().to_ascii_lowercase().as_bytes());
    hasher.update(b"\0");
    hasher.update(normalized_relay.as_bytes());
    let scope_id = hex::encode(hasher.finalize());
    base_dir.join("retention").join(format!("{scope_id}.db"))
}

/// Snapshot the active relay + owner and resolve their durable event store.
///
/// Callers keep the returned relay and keys alongside the path whenever work
/// crosses an `.await`; a later workspace switch cannot retarget that work.
pub fn active_retention_scope(app: &AppHandle, state: &AppState) -> Result<RetentionScope, String> {
    let relay_url = crate::relay::relay_ws_url_with_override(state);
    let owner_keys = state.signing_keys()?;
    let base_dir = super::managed_agents_base_dir(app)?;
    let db_path =
        scoped_retention_db_path(&base_dir, &relay_url, &owner_keys.public_key().to_hex());
    let parent = db_path
        .parent()
        .ok_or_else(|| "retention scope path has no parent".to_string())?;
    std::fs::create_dir_all(parent)
        .map_err(|error| format!("failed to create retention scope directory: {error}"))?;
    Ok(RetentionScope {
        db_path,
        relay_url,
        owner_keys,
    })
}

/// Snapshot the active relay + owner, but only when it is the scope that owns
/// events delivered by `arrival_relay_url`.
///
/// Resolving the scope and matching it in one step is what closes the gap: the
/// returned scope is both the one that will be written to and the one the event
/// arrived on. `Ok(None)` means the arrival community is no longer active and
/// the caller must drop the event — see [`scope_for_arrival`].
pub fn arrival_retention_scope(
    app: &AppHandle,
    state: &AppState,
    arrival_relay_url: &str,
) -> Result<Option<RetentionScope>, String> {
    Ok(scope_for_arrival(
        active_retention_scope(app, state)?,
        arrival_relay_url,
    ))
}

/// A retained persona event row.
#[derive(Debug, Clone)]
pub struct RetainedEvent {
    pub kind: u32,
    pub pubkey: String,
    pub d_tag: String,
    pub content: String,
    pub created_at: i64,
    pub raw_event: String,
    pub pending_sync: bool,
    /// NIP-01 id of this row's own event, the second half of the ordering key.
    ///
    /// NIP-33 resolves an equal-`created_at` collision by lowest event id, so a
    /// row without an id cannot be ordered against a relay head at all. `None`
    /// means exactly that — unresolved: a legacy row whose `raw_event` did not
    /// parse and verify during the schema backfill. Writers derive the value
    /// from the event they just signed, so it always describes `raw_event`.
    pub event_id: Option<String>,
}

/// Re-derive an event's NIP-01 id from its stored JSON, or `None` when the
/// bytes do not parse or do not verify.
///
/// Deliberately not `serde_json::from_str::<Value>()["id"]`: the id is only an
/// ordering key worth trusting if the stored bytes actually hash and sign to
/// it. A row that fails here stays unresolved rather than being handed a
/// self-asserted key it could win a comparator tie with.
pub fn event_id_from_raw(raw_event: &str) -> Option<String> {
    use nostr::JsonUtil;
    let event = nostr::Event::from_json(raw_event).ok()?;
    event.verify().ok()?;
    Some(event.id.to_hex())
}

impl RetainedEvent {
    /// A row for a locally signed event that still has to reach the relay.
    ///
    /// Every event-derived field is read from the one event passed in, so a row
    /// can never carry an `event_id` that describes different bytes than its own
    /// `raw_event` — the ordering key and the payload cannot drift apart.
    pub fn pending(kind: u32, pubkey: String, d_tag: String, event: &nostr::Event) -> Self {
        Self::from_signed(kind, pubkey, d_tag, event, true)
    }

    /// A row for an event that arrived FROM the relay, and so is already
    /// published.
    pub fn inbound(kind: u32, pubkey: String, d_tag: String, event: &nostr::Event) -> Self {
        Self::from_signed(kind, pubkey, d_tag, event, false)
    }

    fn from_signed(
        kind: u32,
        pubkey: String,
        d_tag: String,
        event: &nostr::Event,
        pending_sync: bool,
    ) -> Self {
        use nostr::JsonUtil;
        Self {
            kind,
            pubkey,
            d_tag,
            content: event.content.to_string(),
            // Safety: nostr timestamps are seconds and stay below i64::MAX
            // until year 2262.
            created_at: event.created_at.as_secs() as i64,
            raw_event: event.as_json(),
            event_id: Some(event.id.to_hex()),
            pending_sync,
        }
    }
}

/// Open (or create) the retention database at the given path.
///
/// Sets WAL journaling and a `busy_timeout` on every connection so the
/// flush-loop connection and command-path connections can write concurrently
/// without spurious `SQLITE_BUSY` errors.
pub fn open_retention_db(path: &Path) -> Result<Connection, String> {
    let mut conn =
        Connection::open(path).map_err(|e| format!("failed to open retention db: {e}"))?;

    conn.pragma_update(None, "busy_timeout", 5000)
        .map_err(|e| format!("failed to set busy_timeout: {e}"))?;
    set_wal_mode(&conn)?;

    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS persona_events (
            kind INTEGER NOT NULL,
            pubkey TEXT NOT NULL,
            d_tag TEXT NOT NULL,
            content TEXT NOT NULL,
            created_at INTEGER NOT NULL,
            raw_event TEXT NOT NULL,
            pending_sync INTEGER NOT NULL DEFAULT 0,
            event_id TEXT,
            baseline_event_id TEXT,
            baseline_content TEXT,
            PRIMARY KEY (kind, pubkey, d_tag)
        );",
    )
    .map_err(|e| format!("failed to create retention table: {e}"))?;
    schema::migrate(&mut conn)?;

    Ok(conn)
}

fn set_wal_mode(conn: &Connection) -> Result<(), String> {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        match conn.pragma_update(None, "journal_mode", "WAL") {
            Ok(()) => return Ok(()),
            Err(error) if sqlite_is_busy(&error) && Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(25));
            }
            Err(error) => return Err(format!("failed to set WAL mode: {error}")),
        }
    }
}

fn sqlite_is_busy(error: &rusqlite::Error) -> bool {
    matches!(
        error,
        rusqlite::Error::SqliteFailure(inner, _)
            if matches!(
                inner.code,
                rusqlite::ErrorCode::DatabaseBusy | rusqlite::ErrorCode::DatabaseLocked
            )
    )
}

/// Build the retention `d_tag` column value for a kind:5 tombstone row.
///
/// Tombstones for all target kinds share `kind = 5` in the retention table, so
/// keying a tombstone by the bare target d-tag would collide across kinds when
/// a persona slug, team id, and agent pubkey happen to coincide — one
/// tombstone row would clobber another's pending publish. Folding the target
/// kind into the key (`"<target_kind>:<d_tag>"`) gives each its own PK row.
/// This is the retention-store key only; the published NIP-09 event still
/// carries the plain `a`-tag coordinate.
pub fn tombstone_retention_d_tag(target_kind: u32, d_tag: &str) -> String {
    format!("{target_kind}:{d_tag}")
}

/// Whether a pending row must be deferred to the next sweep because a kind:5
/// tombstone covering its coordinate failed to publish earlier in the same
/// sweep.
///
/// `get_pending_sync` orders tombstones first so a deletion always reaches the
/// relay before the replacement that supersedes it — but the flush is
/// best-effort per row, so a tombstone that fails mid-sweep would otherwise be
/// leapfrogged by its own replacement and then wipe it on the next sweep.
/// Deferring the replacement restores the ordering guarantee: next sweep the
/// `ORDER BY` puts the tombstone first again. Kind:5 rows are never deferred.
pub fn deferred_behind_failed_tombstone(
    kind: u32,
    pubkey: &str,
    d_tag: &str,
    failed_tombstones: &std::collections::HashSet<(String, String)>,
) -> bool {
    kind != 5
        && failed_tombstones.contains(&(pubkey.to_string(), tombstone_retention_d_tag(kind, d_tag)))
}

/// Upsert a persona event into the retention store.
///
/// Only replaces if the new event has a newer or equal `created_at` (NIP-33 semantics).
pub fn retain_event(conn: &Connection, event: &RetainedEvent) -> Result<(), String> {
    conn.execute(
        "INSERT INTO persona_events (kind, pubkey, d_tag, content, created_at, raw_event, pending_sync, event_id)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
         ON CONFLICT (kind, pubkey, d_tag) DO UPDATE SET
            content = excluded.content,
            created_at = excluded.created_at,
            raw_event = excluded.raw_event,
            pending_sync = excluded.pending_sync,
            event_id = excluded.event_id
         WHERE excluded.created_at >= persona_events.created_at",
        params![
            event.kind,
            event.pubkey,
            event.d_tag,
            event.content,
            event.created_at,
            event.raw_event,
            event.pending_sync as i32,
            event.event_id,
        ],
    )
    .map_err(|e| format!("failed to retain event: {e}"))?;

    Ok(())
}

/// Outcome of an inbound retain — whether the local store now reflects the
/// inbound event, so the caller knows whether to patch `personas.json`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InboundOutcome {
    /// The inbound event was applied (no row, or it was strictly newer than a
    /// non-conflicting local row). The caller patches the local record store.
    Applied,
    /// The inbound event was NOT applied: either it is older than the retained
    /// row, or it collides at the same `created_at` with a pending local edit.
    /// The local record store is left untouched and the pending edit republishes.
    Skipped,
}

/// Retain an event arriving FROM the relay, resolving it against any local row.
///
/// Inbound events are already on the relay, so they are retained with
/// `pending_sync = 0`. The resolution is deliberately narrower than
/// [`retain_event`]'s blind newer-or-equal upsert, which would clobber a
/// pending local edit's `pending_sync` flag and silently drop its publish:
///
/// - No local row, or inbound strictly newer (`created_at >`): apply the
///   inbound event, clearing `pending_sync`. Inbound wins; a stale local edit
///   the relay already superseded stops republishing instead of looping.
/// - Equal `created_at`, local row NOT pending: order by event id, matching the
///   relay's own NIP-33 comparator — lowest id wins (`buzz-db`'s
///   `replace_parameterized_event` rejects an incoming event whose id is `>=`
///   the accepted one at an equal timestamp). Without this the local cache can
///   disagree with the relay about which of two same-second events is the head,
///   and every subsequent compare against that head inherits the error.
/// - Equal `created_at`, local row pending: skip regardless of id. A pending row
///   is durable local intent, and intent is arbitrated by the boot decision
///   pass against a writer-consistent head — never dropped by an id compare
///   here. (A re-received echo at equal time is also a no-op.)
/// - Inbound older: skip — nothing to change.
///
/// An unorderable compare is never resolved by guessing: if either side's
/// `event_id` is `None` at an equal timestamp, the local row stands.
pub fn retain_inbound_event(
    conn: &Connection,
    event: &RetainedEvent,
) -> Result<InboundOutcome, String> {
    let existing = get_retained_event(conn, event.kind, &event.pubkey, &event.d_tag)?;

    let apply = match &existing {
        None => true,
        Some(row) if event.created_at > row.created_at => true,
        Some(row) if event.created_at == row.created_at => {
            !row.pending_sync && inbound_wins_equal_timestamp(event, row)
        }
        // Older: stale.
        Some(_) => false,
    };

    if !apply {
        return Ok(InboundOutcome::Skipped);
    }

    // Inbound is strictly newer (or there was no row): overwrite and clear
    // `pending_sync`. No upsert guard is needed — the Rust check above already
    // established that this event wins.
    conn.execute(
        "INSERT INTO persona_events (kind, pubkey, d_tag, content, created_at, raw_event, pending_sync, event_id)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, 0, ?7)
         ON CONFLICT (kind, pubkey, d_tag) DO UPDATE SET
            content = excluded.content,
            created_at = excluded.created_at,
            raw_event = excluded.raw_event,
            pending_sync = 0,
            event_id = excluded.event_id",
        params![
            event.kind,
            event.pubkey,
            event.d_tag,
            event.content,
            event.created_at,
            event.raw_event,
            event.event_id,
        ],
    )
    .map_err(|e| format!("failed to retain inbound event: {e}"))?;

    Ok(InboundOutcome::Applied)
}

/// Whether an inbound event beats a retained row they share a `created_at`
/// with, under the relay's tie-break: strictly lower event id wins.
///
/// Mirrors `buzz-db`'s `replace_parameterized_event`, which rejects an incoming
/// event when `created_at == accepted_ts && incoming_id >= accepted_id`. The
/// comparison is over the id's raw bytes there and its lowercase hex here —
/// same ordering, since hex encoding is monotonic over byte strings of equal
/// length and NIP-01 ids are always 32 bytes.
///
/// A missing id on either side means the pair cannot be ordered the way the
/// relay orders it. That returns `false`: the retained row stands, the inbound
/// event is skipped, and nothing is decided from a fabricated key. The cost is
/// a stale row until a strictly newer event arrives; the alternative is a local
/// head the relay disagrees with.
fn inbound_wins_equal_timestamp(inbound: &RetainedEvent, retained: &RetainedEvent) -> bool {
    match (&inbound.event_id, &retained.event_id) {
        (Some(inbound_id), Some(retained_id)) => inbound_id < retained_id,
        _ => false,
    }
}

/// Load all retained persona events for a given pubkey.
#[cfg(test)]
pub fn get_retained_personas(
    conn: &Connection,
    pubkey: &str,
) -> Result<Vec<RetainedEvent>, String> {
    let mut stmt = conn
        .prepare(
            "SELECT kind, pubkey, d_tag, content, created_at, raw_event, pending_sync, event_id
             FROM persona_events
             WHERE pubkey = ?1
             ORDER BY d_tag",
        )
        .map_err(|e| format!("failed to prepare query: {e}"))?;

    let rows = stmt
        .query_map(params![pubkey], |row| {
            Ok(RetainedEvent {
                kind: row.get(0)?,
                pubkey: row.get(1)?,
                d_tag: row.get(2)?,
                content: row.get(3)?,
                created_at: row.get(4)?,
                raw_event: row.get(5)?,
                pending_sync: row.get::<_, i32>(6)? != 0,
                event_id: row.get(7)?,
            })
        })
        .map_err(|e| format!("failed to query retained events: {e}"))?;

    rows.collect::<Result<Vec<_>, _>>()
        .map_err(|e| format!("failed to read retained event row: {e}"))
}

/// Get all events marked as pending sync (not yet confirmed on relay).
///
/// Tombstones (kind:5) sort FIRST: a delete retained in one session and its
/// coordinate's replacement retained in a later one (B5 backfill resurrecting
/// a deleted definition) must publish in that order — the relay's a-tag
/// deletion soft-deletes every live row at the coordinate with no timestamp
/// comparison, so a tombstone published AFTER the replacement would wipe it.
/// Within each group, oldest first for the same reason.
pub fn get_pending_sync(conn: &Connection) -> Result<Vec<RetainedEvent>, String> {
    let mut stmt = conn
        .prepare(
            "SELECT kind, pubkey, d_tag, content, created_at, raw_event, pending_sync, event_id
             FROM persona_events
             WHERE pending_sync = 1
             ORDER BY (kind != 5), created_at ASC",
        )
        .map_err(|e| format!("failed to prepare pending sync query: {e}"))?;

    let rows = stmt
        .query_map([], |row| {
            Ok(RetainedEvent {
                kind: row.get(0)?,
                pubkey: row.get(1)?,
                d_tag: row.get(2)?,
                content: row.get(3)?,
                created_at: row.get(4)?,
                raw_event: row.get(5)?,
                pending_sync: row.get::<_, i32>(6)? != 0,
                event_id: row.get(7)?,
            })
        })
        .map_err(|e| format!("failed to query pending sync events: {e}"))?;

    rows.collect::<Result<Vec<_>, _>>()
        .map_err(|e| format!("failed to read pending sync row: {e}"))
}

/// Clear the `pending_sync` flag for an event the relay just confirmed.
///
/// Compare-and-clear: only clears the row if its `created_at` and `content`
/// still match what was published. A concurrent edit that upserted a newer
/// version at the same coordinate between the flush loop's read and this call
/// leaves `pending_sync` set, so the newer edit publishes on the next pass
/// instead of being silently dropped.
pub fn mark_synced(
    conn: &Connection,
    kind: u32,
    pubkey: &str,
    d_tag: &str,
    created_at: i64,
    content: &str,
) -> Result<(), String> {
    conn.execute(
        "UPDATE persona_events SET pending_sync = 0
         WHERE kind = ?1 AND pubkey = ?2 AND d_tag = ?3
           AND created_at = ?4 AND content = ?5",
        params![kind, pubkey, d_tag, created_at, content],
    )
    .map_err(|e| format!("failed to mark event synced: {e}"))?;

    Ok(())
}

/// Delete a retained event by its coordinate.
///
/// Called from the synchronous, lock-held delete-persona command body so the
/// purge serializes against `retain_event` upserts at the same coordinate —
/// closing the same-second resurrect race where a pending edit would otherwise
/// publish after the deletion tombstone.
pub fn delete_retained_event(
    conn: &Connection,
    kind: u32,
    pubkey: &str,
    d_tag: &str,
) -> Result<(), String> {
    conn.execute(
        "DELETE FROM persona_events
         WHERE kind = ?1 AND pubkey = ?2 AND d_tag = ?3",
        params![kind, pubkey, d_tag],
    )
    .map_err(|e| format!("failed to delete retained event: {e}"))?;

    Ok(())
}

/// Check if the retention store has any persona events for the given pubkey.
#[cfg(test)]
pub fn has_retained_personas(conn: &Connection, pubkey: &str) -> Result<bool, String> {
    conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM persona_events WHERE pubkey = ?1)",
        params![pubkey],
        |row| row.get(0),
    )
    .map_err(|e| format!("failed to check retained personas: {e}"))
}

/// Look up a single retained event by its coordinate.
pub fn get_retained_event(
    conn: &Connection,
    kind: u32,
    pubkey: &str,
    d_tag: &str,
) -> Result<Option<RetainedEvent>, String> {
    conn.query_row(
        "SELECT kind, pubkey, d_tag, content, created_at, raw_event, pending_sync, event_id
         FROM persona_events
         WHERE kind = ?1 AND pubkey = ?2 AND d_tag = ?3",
        params![kind, pubkey, d_tag],
        |row| {
            Ok(RetainedEvent {
                kind: row.get(0)?,
                pubkey: row.get(1)?,
                d_tag: row.get(2)?,
                content: row.get(3)?,
                created_at: row.get(4)?,
                raw_event: row.get(5)?,
                pending_sync: row.get::<_, i32>(6)? != 0,
                event_id: row.get(7)?,
            })
        },
    )
    .optional()
    .map_err(|e| format!("failed to get retained event: {e}"))
}

#[cfg(test)]
mod tests;
