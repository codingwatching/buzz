use super::*;
use crate::managed_agents::retention::open_retention_db;
use nostr::JsonUtil;
use std::path::Path;

/// The seven-column table as it shipped before `event_id` existed.
const LEGACY_TABLE: &str = "CREATE TABLE persona_events (
    kind INTEGER NOT NULL,
    pubkey TEXT NOT NULL,
    d_tag TEXT NOT NULL,
    content TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    raw_event TEXT NOT NULL,
    pending_sync INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (kind, pubkey, d_tag)
);";

fn legacy_db(path: &Path) -> Connection {
    let conn = Connection::open(path).unwrap();
    conn.execute_batch(LEGACY_TABLE).unwrap();
    conn
}

fn column_names(conn: &Connection) -> Vec<String> {
    let mut stmt = conn
        .prepare("SELECT name FROM pragma_table_info('persona_events')")
        .unwrap();
    let names = stmt
        .query_map([], |row| row.get::<_, String>(0))
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    names
}

/// A real signed event, so `raw_event` actually verifies against its id.
fn signed_event() -> nostr::Event {
    let keys = nostr::Keys::generate();
    nostr::EventBuilder::text_note("agent config")
        .sign_with_keys(&keys)
        .unwrap()
}

fn insert_legacy_row(conn: &Connection, d_tag: &str, raw_event: &str) {
    conn.execute(
        "INSERT INTO persona_events (kind, pubkey, d_tag, content, created_at, raw_event, pending_sync)
         VALUES (30175, 'owner', ?1, '{}', 1000, ?2, 0)",
        rusqlite::params![d_tag, raw_event],
    )
    .unwrap();
}

fn stored_event_id(conn: &Connection, d_tag: &str) -> Option<String> {
    conn.query_row(
        "SELECT event_id FROM persona_events WHERE d_tag = ?1",
        rusqlite::params![d_tag],
        |row| row.get::<_, Option<String>>(0),
    )
    .unwrap()
}

#[test]
fn test_legacy_table_gains_every_added_column() {
    let dir = tempfile::tempdir().unwrap();
    let mut conn = legacy_db(&dir.path().join("retention.db"));
    for (column, _) in ADDED_COLUMNS {
        assert!(
            !column_names(&conn).contains(&column.to_string()),
            "{column} should be absent before migrating"
        );
    }

    migrate(&mut conn).unwrap();

    let columns = column_names(&conn);
    for (column, _) in ADDED_COLUMNS {
        assert!(columns.contains(&column.to_string()), "missing {column}");
    }
}

#[test]
fn test_migration_preserves_existing_rows() {
    let dir = tempfile::tempdir().unwrap();
    let mut conn = legacy_db(&dir.path().join("retention.db"));
    insert_legacy_row(&conn, "reviewer", r#"{"content":"unverifiable"}"#);

    migrate(&mut conn).unwrap();

    let (content, created_at, pending): (String, i64, i64) = conn
        .query_row(
            "SELECT content, created_at, pending_sync FROM persona_events WHERE d_tag = 'reviewer'",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .unwrap();
    assert_eq!(content, "{}");
    assert_eq!(created_at, 1000);
    assert_eq!(pending, 0);
}

#[test]
fn test_backfill_recovers_event_id_from_verifiable_row() {
    let dir = tempfile::tempdir().unwrap();
    let mut conn = legacy_db(&dir.path().join("retention.db"));
    let event = signed_event();
    insert_legacy_row(&conn, "reviewer", &event.as_json());

    migrate(&mut conn).unwrap();

    assert_eq!(stored_event_id(&conn, "reviewer"), Some(event.id.to_hex()));
}

#[test]
fn test_backfill_leaves_unverifiable_row_unresolved() {
    let dir = tempfile::tempdir().unwrap();
    let mut conn = legacy_db(&dir.path().join("retention.db"));
    // Row shapes that must never be handed a fabricated ordering key: not
    // JSON at all, valid JSON that is not an event, and an event whose
    // self-asserted id does not match its own bytes.
    insert_legacy_row(&conn, "not-json", "}{");
    insert_legacy_row(&conn, "not-an-event", r#"{"content":"old"}"#);
    let mut forged: serde_json::Value = serde_json::from_str(&signed_event().as_json()).unwrap();
    forged["content"] = serde_json::json!("tampered after signing");
    insert_legacy_row(&conn, "forged", &forged.to_string());

    migrate(&mut conn).unwrap();

    for d_tag in ["not-json", "not-an-event", "forged"] {
        assert_eq!(stored_event_id(&conn, d_tag), None, "{d_tag}");
    }
}

#[test]
fn test_migration_is_idempotent_across_repeated_opens() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("retention.db");
    let event = signed_event();
    {
        let conn = legacy_db(&path);
        insert_legacy_row(&conn, "reviewer", &event.as_json());
    }

    // Every open after the first must find nothing to do and leave the
    // backfilled id in place.
    for _ in 0..3 {
        let conn = open_retention_db(&path).unwrap();
        assert_eq!(stored_event_id(&conn, "reviewer"), Some(event.id.to_hex()));
        assert_eq!(
            conn.query_row("SELECT COUNT(*) FROM persona_events", [], |row| row
                .get::<_, i64>(0))
                .unwrap(),
            1
        );
    }
}

#[test]
fn test_fresh_database_needs_no_migration() {
    let dir = tempfile::tempdir().unwrap();
    let mut conn = open_retention_db(&dir.path().join("retention.db")).unwrap();
    assert!(
        missing_columns(&conn).unwrap().is_empty(),
        "CREATE TABLE and ADDED_COLUMNS have diverged"
    );
    migrate(&mut conn).unwrap();
}

#[test]
fn test_concurrent_open_of_unmigrated_database_migrates_once() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("retention.db");
    let event = signed_event();
    {
        let conn = legacy_db(&path);
        insert_legacy_row(&conn, "reviewer", &event.as_json());
    }

    // Both openers race the same unmigrated database; the exclusive
    // transaction serializes them and the loser re-probes and no-ops.
    let handles: Vec<_> = (0..2)
        .map(|_| {
            let path = path.clone();
            std::thread::spawn(move || open_retention_db(&path))
        })
        .collect();
    for handle in handles {
        assert!(handle.join().unwrap().is_ok());
    }

    let conn = Connection::open(&path).unwrap();
    assert_eq!(stored_event_id(&conn, "reviewer"), Some(event.id.to_hex()));
    let columns = column_names(&conn);
    for (column, _) in ADDED_COLUMNS {
        assert_eq!(
            columns.iter().filter(|name| *name == column).count(),
            1,
            "{column} added twice"
        );
    }
}
