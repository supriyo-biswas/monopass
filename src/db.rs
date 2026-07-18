use std::io::{self, IsTerminal, Write};
use std::time::{SystemTime, UNIX_EPOCH};

use age::secrecy::ExposeSecret;
use rusqlite::{Connection, OpenFlags};
use zeroize::Zeroizing;

#[cfg(debug_assertions)]
use crate::AppResult;
#[cfg(debug_assertions)]
use crate::config::Config;
use crate::settings::USER_SETTINGS;

const SCHEMA: &str = r#"
CREATE TABLE system_settings (
    name TEXT PRIMARY KEY,
    value TEXT
);

CREATE TABLE dirs (
    id INTEGER PRIMARY KEY,
    name TEXT UNIQUE NOT NULL,
    bitmask INTEGER NOT NULL DEFAULT 0,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
);

CREATE TABLE contacts (
    email TEXT PRIMARY KEY,
    name TEXT,
    age_public_key TEXT NOT NULL,
    description TEXT,
    created_at INTEGER NOT NULL
) WITHOUT ROWID;

CREATE TABLE items (
    id INTEGER PRIMARY KEY,
    dir_id INTEGER NOT NULL REFERENCES dirs (id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    bitmask INTEGER NOT NULL DEFAULT 0,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    oldest_version_id INTEGER,
    latest_version_id INTEGER,
    UNIQUE (dir_id, name),
    FOREIGN KEY (id, oldest_version_id) REFERENCES item_versions (item_id, version_id) DEFERRABLE INITIALLY DEFERRED,
    FOREIGN KEY (id, latest_version_id) REFERENCES item_versions (item_id, version_id) DEFERRABLE INITIALLY DEFERRED
);

CREATE TABLE item_versions (
    version_id INTEGER NOT NULL,
    item_id INTEGER NOT NULL REFERENCES items (id) ON DELETE CASCADE,
    fields TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    PRIMARY KEY (item_id, version_id)
) WITHOUT ROWID;

CREATE TABLE files (
    id BLOB PRIMARY KEY,
    sha256 TEXT NOT NULL,
    size INTEGER NOT NULL,
    nonce BLOB NOT NULL,
    tag BLOB NOT NULL,
    created_at INTEGER NOT NULL,
    UNIQUE (sha256)
) WITHOUT ROWID;

CREATE TABLE item_version_file_mapping (
    item_id INTEGER NOT NULL,
    version_id INTEGER NOT NULL,
    file_id BLOB NOT NULL REFERENCES files (id) ON DELETE CASCADE,
    file_name TEXT NOT NULL,
    PRIMARY KEY (item_id, version_id, file_id),
    UNIQUE (item_id, version_id, file_name),
    FOREIGN KEY (item_id, version_id) REFERENCES item_versions (item_id, version_id) ON DELETE CASCADE
) WITHOUT ROWID;

CREATE TABLE jobs (
    job_id TEXT PRIMARY KEY,
    type TEXT NOT NULL,
    status TEXT NOT NULL,
    target_dir TEXT NOT NULL,
    target_item TEXT NOT NULL,
    target_contact TEXT,
    output_path TEXT,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    started_at INTEGER,
    finished_at INTEGER,
    error_code TEXT,
    error_message TEXT
) WITHOUT ROWID;
"#;
const DEFAULT_DIR_NAME: &str = "Personal";
const TRASH_DIR_NAME: &str = "Trash";
const INTERNAL_DIR_NAME: &str = "_Internal";
const FILE_ENCRYPTION_KEY_ITEM_NAME: &str = "FileEncryptionKey";
const AGE_PUBLIC_KEY_ITEM_NAME: &str = "AgePublicKey";
const AGE_PRIVATE_KEY_ITEM_NAME: &str = "AgePrivateKey";
const DIR_HIDDEN: i64 = 1 << 0;
const DIR_SYSTEM: i64 = 1 << 1;
const ITEM_HIDDEN: i64 = 1 << 0;
const ITEM_READ_MUSTAUTH: i64 = 1 << 1;

#[cfg(debug_assertions)]
pub fn open_encrypted_database(config: &Config) -> AppResult<Connection> {
    let password = prompt_password("Enter master password: ")?;
    let conn = open_encrypted_database_with_password(config.database_path(), &password)?;

    Ok(conn)
}

pub fn open_encrypted_database_with_password(
    database_path: impl AsRef<std::path::Path>,
    password: &str,
) -> rusqlite::Result<Connection> {
    let conn = Connection::open_with_flags(database_path, OpenFlags::SQLITE_OPEN_READ_WRITE)?;

    conn.pragma_update(None, "key", password)?;
    conn.query_row("SELECT count(*) FROM sqlite_master", [], |_| Ok(()))?;
    configure_open_connection(&conn)?;
    insert_missing_user_setting_defaults(&conn)?;

    Ok(conn)
}

pub(crate) fn open_encrypted_database_reader_with_password(
    database_path: impl AsRef<std::path::Path>,
    password: &str,
) -> rusqlite::Result<Connection> {
    let conn = Connection::open_with_flags(database_path, OpenFlags::SQLITE_OPEN_READ_ONLY)?;

    conn.pragma_update(None, "key", password)?;
    conn.query_row("SELECT count(*) FROM sqlite_master", [], |_| Ok(()))?;
    configure_read_only_connection(&conn)?;

    Ok(conn)
}

pub(crate) fn rekey_encrypted_database(
    conn: &Connection,
    new_password: &str,
) -> rusqlite::Result<()> {
    conn.pragma_update(None, "rekey", new_password)?;
    conn.query_row("SELECT count(*) FROM sqlite_master", [], |_| Ok(()))
}

pub(crate) fn create_encrypted_database_with_password(
    database_path: impl AsRef<std::path::Path>,
    password: &str,
) -> rusqlite::Result<()> {
    let conn = Connection::open_with_flags(
        database_path,
        OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_CREATE,
    )?;

    conn.pragma_update(None, "key", password)?;
    configure_new_connection(&conn)?;
    conn.execute_batch(SCHEMA)?;
    create_default_dirs(&conn)?;
    create_file_encryption_key_item(&conn)?;
    create_age_keypair_items(&conn)?;
    create_default_user_settings(&conn)?;
    conn.pragma_update(None, "user_version", 1)?;

    Ok(())
}

fn create_file_encryption_key_item(conn: &Connection) -> rusqlite::Result<()> {
    let mut key = Zeroizing::new([0u8; 32]);
    getrandom::fill(&mut key[..]).map_err(|error| {
        rusqlite::Error::ToSqlConversionFailure(Box::new(io::Error::other(error.to_string())))
    })?;
    let key_hex = Zeroizing::new(hex_encode(&*key));
    let fields = Zeroizing::new(internal_key_fields(&key_hex, true));
    insert_internal_key_item(
        conn,
        FILE_ENCRYPTION_KEY_ITEM_NAME,
        ITEM_HIDDEN | ITEM_READ_MUSTAUTH,
        fields.as_str(),
    )
}

fn create_age_keypair_items(conn: &Connection) -> rusqlite::Result<()> {
    let identity = age::x25519::Identity::generate();
    let recipient = identity.to_public();
    let public_key = recipient.to_string();
    let private_key = identity.to_string();

    insert_internal_key_item(
        conn,
        AGE_PUBLIC_KEY_ITEM_NAME,
        0,
        internal_key_fields(&public_key, false).as_str(),
    )?;

    let private_key_fields = Zeroizing::new(internal_key_fields(private_key.expose_secret(), true));
    insert_internal_key_item(
        conn,
        AGE_PRIVATE_KEY_ITEM_NAME,
        ITEM_HIDDEN | ITEM_READ_MUSTAUTH,
        private_key_fields.as_str(),
    )
}

fn internal_key_fields(key: &str, concealed: bool) -> String {
    format!(r#"{{"key":{{"type":"string","concealed":{concealed},"data":"{key}"}}}}"#)
}

fn insert_internal_key_item(
    conn: &Connection,
    item_name: &str,
    bitmask: i64,
    fields: &str,
) -> rusqlite::Result<()> {
    let now = now_timestamp();
    let internal_dir_id: i64 = conn.query_row(
        "SELECT id FROM dirs WHERE name = ?1",
        [INTERNAL_DIR_NAME],
        |row| row.get(0),
    )?;

    conn.execute(
        r#"
        INSERT INTO items (dir_id, name, bitmask, created_at, updated_at)
        VALUES (?1, ?2, ?3, ?4, ?4)
        "#,
        (internal_dir_id, item_name, bitmask, now),
    )?;
    let item_id = conn.last_insert_rowid();
    conn.execute(
        r#"
        INSERT INTO item_versions (item_id, version_id, fields, created_at)
        VALUES (?1, 1, ?2, ?3)
        "#,
        (item_id, fields, now),
    )?;
    conn.execute(
        r#"
        UPDATE items
        SET oldest_version_id = 1, latest_version_id = 1
        WHERE id = ?1
        "#,
        [item_id],
    )?;
    Ok(())
}

fn create_default_user_settings(conn: &Connection) -> rusqlite::Result<()> {
    for setting in USER_SETTINGS {
        conn.execute(
            "INSERT INTO system_settings (name, value) VALUES (?1, ?2)",
            (setting.name, setting.default),
        )?;
    }
    Ok(())
}

fn insert_missing_user_setting_defaults(conn: &Connection) -> rusqlite::Result<()> {
    for setting in USER_SETTINGS {
        conn.execute(
            r#"
            INSERT INTO system_settings (name, value)
            VALUES (?1, ?2)
            ON CONFLICT(name) DO NOTHING
            "#,
            (setting.name, setting.default),
        )?;
    }
    Ok(())
}

fn create_default_dirs(conn: &Connection) -> rusqlite::Result<()> {
    let now = now_timestamp();
    for (name, bitmask) in [
        (TRASH_DIR_NAME, DIR_HIDDEN),
        (INTERNAL_DIR_NAME, DIR_HIDDEN | DIR_SYSTEM),
        (DEFAULT_DIR_NAME, 0),
    ] {
        conn.execute(
            "INSERT INTO dirs (name, bitmask, created_at, updated_at) VALUES (?1, ?2, ?3, ?3)",
            (name, bitmask, now),
        )?;
    }
    Ok(())
}

fn now_timestamp() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

fn configure_new_connection(conn: &Connection) -> rusqlite::Result<()> {
    conn.pragma_update(None, "auto_vacuum", "INCREMENTAL")?;
    configure_open_connection(conn)
}

fn configure_open_connection(conn: &Connection) -> rusqlite::Result<()> {
    conn.pragma_update(None, "foreign_keys", "ON")?;
    conn.pragma_update(None, "auto_vacuum", "INCREMENTAL")?;
    conn.pragma_update(None, "journal_mode", "WAL")?;
    Ok(())
}

fn configure_read_only_connection(conn: &Connection) -> rusqlite::Result<()> {
    conn.pragma_update(None, "foreign_keys", "ON")?;
    Ok(())
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(HEX[(byte >> 4) as usize] as char);
        encoded.push(HEX[(byte & 0x0f) as usize] as char);
    }
    encoded
}

pub(crate) fn prompt_password(prompt: &str) -> io::Result<Zeroizing<String>> {
    if io::stdin().is_terminal() {
        return rpassword::prompt_password(prompt).map(Zeroizing::new);
    }

    eprint!("{prompt}");
    io::stderr().flush()?;

    let mut password = Zeroizing::new(String::new());
    io::stdin().read_line(&mut password)?;
    while password.ends_with(['\r', '\n']) {
        password.pop();
    }
    Ok(password)
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use rusqlite::{Connection, OpenFlags, OptionalExtension};
    use tempfile::NamedTempFile;

    #[test]
    fn creates_schema_and_configures_database() {
        let file = NamedTempFile::new().unwrap();

        super::create_encrypted_database_with_password(file.path(), "correct").unwrap();
        let conn = super::open_encrypted_database_with_password(file.path(), "correct").unwrap();

        assert_table_exists(&conn, "dirs");
        assert_table_exists(&conn, "items");
        assert_table_exists(&conn, "item_versions");
        assert_table_exists(&conn, "files");
        assert_table_exists(&conn, "item_version_file_mapping");
        assert_table_exists(&conn, "system_settings");
        assert_table_exists(&conn, "contacts");
        assert_table_without_rowid(&conn, "contacts");
        assert_table_without_rowid(&conn, "item_versions");
        assert_table_without_rowid(&conn, "files");
        assert_table_without_rowid(&conn, "item_version_file_mapping");
        assert_primary_key(&conn, "contacts", &["email"]);
        assert_column_exists(&conn, "contacts", "name");
        assert_no_column(&conn, "items", "fields");
        assert_no_column(&conn, "files", "item_id");
        assert_no_column(&conn, "files", "name");
        assert_unique_index(&conn, "files", &["sha256"]);
        assert_column_exists(&conn, "dirs", "bitmask");
        assert_column_exists(&conn, "items", "bitmask");
        assert_column_exists(&conn, "contacts", "created_at");
        assert_primary_key(&conn, "item_versions", &["item_id", "version_id"]);
        assert_primary_key(
            &conn,
            "item_version_file_mapping",
            &["item_id", "version_id", "file_id"],
        );
        assert_unique_index(
            &conn,
            "item_version_file_mapping",
            &["item_id", "version_id", "file_name"],
        );
        assert_eq!(1, pragma_i64(&conn, "foreign_keys"));
        assert_eq!(2, pragma_i64(&conn, "auto_vacuum"));
        assert_eq!("wal", pragma_string(&conn, "journal_mode"));
        assert_eq!(1, pragma_i64(&conn, "user_version"));
        assert_eq!(1, dir_count(&conn, "Personal"));
        assert_dir_bitmask(&conn, "Personal", 0);
        assert_dir_bitmask(&conn, "Trash", super::DIR_HIDDEN);
        assert_dir_bitmask(&conn, "_Internal", super::DIR_HIDDEN | super::DIR_SYSTEM);
        assert_internal_file_encryption_key_exists(&conn);
        assert_internal_age_keypair_exists(&conn);
        assert_setting_missing(&conn, "sys.fileEncryptionKey");
        assert_setting_value(&conn, "user.authTtlSeconds", "900");
        assert_setting_value(&conn, "user.settingsAuthTtlSeconds", "300");
        assert_setting_value(&conn, "user.denialTtlSeconds", "60");
        assert_setting_value(&conn, "user.gcSeconds", "3600");
        assert_setting_value(&conn, "user.trustedProgramPaths", "[]");
    }

    #[test]
    fn opened_database_enforces_foreign_keys() {
        let file = NamedTempFile::new().unwrap();

        super::create_encrypted_database_with_password(file.path(), "correct").unwrap();
        let conn = super::open_encrypted_database_with_password(file.path(), "correct").unwrap();

        let error = conn
            .execute(
                "INSERT INTO items (dir_id, name, created_at, updated_at) VALUES (999, 'item', 1, 1)",
                [],
            )
            .unwrap_err();

        assert_eq!(rusqlite::ErrorCode::ConstraintViolation, sqlite_code(error));
    }

    #[test]
    fn opening_existing_database_enables_foreign_keys_and_wal() {
        let file = NamedTempFile::new().unwrap();
        let conn = Connection::open_with_flags(
            file.path(),
            OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_CREATE,
        )
        .unwrap();
        conn.pragma_update(None, "key", "correct").unwrap();
        conn.execute_batch(super::SCHEMA).unwrap();
        drop(conn);

        let conn = super::open_encrypted_database_with_password(file.path(), "correct").unwrap();

        assert_eq!(1, pragma_i64(&conn, "foreign_keys"));
        assert_eq!("wal", pragma_string(&conn, "journal_mode"));
    }

    #[test]
    fn opening_existing_database_inserts_missing_user_settings_without_version_bump() {
        let file = NamedTempFile::new().unwrap();
        let conn = Connection::open_with_flags(
            file.path(),
            OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_CREATE,
        )
        .unwrap();
        conn.pragma_update(None, "key", "correct").unwrap();
        conn.execute_batch(super::SCHEMA).unwrap();
        conn.pragma_update(None, "user_version", 1).unwrap();
        drop(conn);

        let conn = super::open_encrypted_database_with_password(file.path(), "correct").unwrap();

        assert_eq!(1, pragma_i64(&conn, "user_version"));
        assert_setting_value(&conn, "user.authTtlSeconds", "900");
        assert_setting_value(&conn, "user.settingsAuthTtlSeconds", "300");
        assert_setting_value(&conn, "user.denialTtlSeconds", "60");
        assert_setting_value(&conn, "user.gcSeconds", "3600");
        assert_setting_value(&conn, "user.trustedProgramPaths", "[]");
    }

    #[test]
    fn encrypted_read_only_database_opens_with_correct_password() {
        let file = NamedTempFile::new().unwrap();

        super::create_encrypted_database_with_password(file.path(), "correct").unwrap();
        let conn =
            super::open_encrypted_database_reader_with_password(file.path(), "correct").unwrap();

        assert_table_exists(&conn, "dirs");
        assert_eq!(1, dir_count(&conn, "Personal"));
    }

    #[test]
    fn encrypted_read_only_database_rejects_wrong_password() {
        let file = NamedTempFile::new().unwrap();

        super::create_encrypted_database_with_password(file.path(), "correct").unwrap();

        assert!(super::open_encrypted_database_reader_with_password(file.path(), "wrong").is_err());
    }

    #[test]
    fn encrypted_read_only_database_queries_data_and_enforces_foreign_keys() {
        let file = NamedTempFile::new().unwrap();

        super::create_encrypted_database_with_password(file.path(), "correct").unwrap();
        let conn =
            super::open_encrypted_database_reader_with_password(file.path(), "correct").unwrap();

        assert_eq!(1, pragma_i64(&conn, "foreign_keys"));
        assert_eq!(1, dir_count(&conn, "Personal"));
        let error = conn
            .execute(
                "INSERT INTO items (dir_id, name, created_at, updated_at) VALUES (999, 'item', 1, 1)",
                [],
            )
            .unwrap_err();
        assert!(matches!(
            sqlite_code(error),
            rusqlite::ErrorCode::ReadOnly | rusqlite::ErrorCode::ConstraintViolation
        ));
    }

    #[test]
    fn rekeys_encrypted_database() {
        let file = NamedTempFile::new().unwrap();

        super::create_encrypted_database_with_password(file.path(), "old-password").unwrap();
        let conn =
            super::open_encrypted_database_with_password(file.path(), "old-password").unwrap();
        super::rekey_encrypted_database(&conn, "new-password").unwrap();
        drop(conn);

        assert!(super::open_encrypted_database_with_password(file.path(), "old-password").is_err());
        let conn =
            super::open_encrypted_database_with_password(file.path(), "new-password").unwrap();
        assert_table_exists(&conn, "dirs");
        assert_eq!(1, dir_count(&conn, "Personal"));
    }

    fn assert_table_exists(conn: &Connection, table: &str) {
        conn.query_row(
            "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?1",
            [table],
            |_| Ok(()),
        )
        .unwrap();
    }

    fn assert_table_without_rowid(conn: &Connection, table: &str) {
        let sql: String = conn
            .query_row(
                "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = ?1",
                [table],
                |row| row.get(0),
            )
            .unwrap();
        assert!(sql.to_uppercase().contains("WITHOUT ROWID"), "{sql}");
    }

    fn assert_no_column(conn: &Connection, table: &str, column: &str) {
        let count: i64 = conn
            .query_row(
                &format!("SELECT count(*) FROM pragma_table_info('{table}') WHERE name = ?1"),
                [column],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(0, count);
    }

    fn assert_column_exists(conn: &Connection, table: &str, column: &str) {
        let count: i64 = conn
            .query_row(
                &format!("SELECT count(*) FROM pragma_table_info('{table}') WHERE name = ?1"),
                [column],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(1, count);
    }

    fn assert_primary_key(conn: &Connection, table: &str, columns: &[&str]) {
        let mut statement = conn
            .prepare(&format!(
                "SELECT name FROM pragma_table_info('{table}') WHERE pk > 0 ORDER BY pk"
            ))
            .unwrap();
        let actual = statement
            .query_map([], |row| row.get::<_, String>(0))
            .unwrap()
            .collect::<rusqlite::Result<Vec<_>>>()
            .unwrap();
        assert_eq!(columns, actual.as_slice());
    }

    fn assert_unique_index(conn: &Connection, table: &str, columns: &[&str]) {
        let mut indexes = conn
            .prepare(&format!(
                "SELECT name FROM pragma_index_list('{table}') WHERE [unique] = 1"
            ))
            .unwrap();
        let indexes = indexes
            .query_map([], |row| row.get::<_, String>(0))
            .unwrap()
            .collect::<rusqlite::Result<Vec<_>>>()
            .unwrap();

        let found = indexes.iter().any(|index| {
            let mut info = conn
                .prepare(&format!(
                    "SELECT name FROM pragma_index_info('{index}') ORDER BY seqno"
                ))
                .unwrap();
            let actual = info
                .query_map([], |row| row.get::<_, String>(0))
                .unwrap()
                .collect::<rusqlite::Result<Vec<_>>>()
                .unwrap();
            actual.as_slice() == columns
        });
        assert!(found, "missing unique index on {table}({columns:?})");
    }

    fn pragma_i64(conn: &Connection, name: &str) -> i64 {
        conn.query_row(&format!("PRAGMA {name}"), [], |row| row.get(0))
            .unwrap()
    }

    fn pragma_string(conn: &Connection, name: &str) -> String {
        conn.query_row(&format!("PRAGMA {name}"), [], |row| row.get(0))
            .unwrap()
    }

    fn dir_count(conn: &Connection, name: &str) -> i64 {
        conn.query_row("SELECT count(*) FROM dirs WHERE name = ?1", [name], |row| {
            row.get(0)
        })
        .unwrap()
    }

    fn assert_dir_bitmask(conn: &Connection, name: &str, expected: i64) {
        let bitmask: i64 = conn
            .query_row("SELECT bitmask FROM dirs WHERE name = ?1", [name], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(expected, bitmask);
    }

    fn assert_internal_file_encryption_key_exists(conn: &Connection) {
        let (bitmask, fields) = internal_item(conn, "FileEncryptionKey");
        assert_eq!(super::ITEM_HIDDEN | super::ITEM_READ_MUSTAUTH, bitmask);
        let value: serde_json::Value = serde_json::from_str(&fields).unwrap();
        let key = value["key"]["data"].as_str().unwrap();
        assert!(value["key"]["concealed"].as_bool().unwrap());
        assert_eq!(64, key.len());
        assert!(key.chars().all(|character| character.is_ascii_hexdigit()));
    }

    fn assert_internal_age_keypair_exists(conn: &Connection) {
        let (public_bitmask, public_fields) = internal_item(conn, "AgePublicKey");
        assert_eq!(0, public_bitmask);
        let public_fields: serde_json::Value = serde_json::from_str(&public_fields).unwrap();
        assert!(!public_fields["key"]["concealed"].as_bool().unwrap());
        let public_key = public_fields["key"]["data"].as_str().unwrap();
        assert!(public_key.starts_with("age1"), "{public_key}");

        let (private_bitmask, private_fields) = internal_item(conn, "AgePrivateKey");
        assert_eq!(
            super::ITEM_HIDDEN | super::ITEM_READ_MUSTAUTH,
            private_bitmask
        );
        let private_fields: serde_json::Value = serde_json::from_str(&private_fields).unwrap();
        assert!(private_fields["key"]["concealed"].as_bool().unwrap());
        let private_key = private_fields["key"]["data"].as_str().unwrap();
        assert!(private_key.starts_with("AGE-SECRET-KEY-"), "{private_key}");

        let identity = age::x25519::Identity::from_str(private_key).unwrap();
        assert_eq!(public_key, identity.to_public().to_string());
    }

    fn internal_item(conn: &Connection, name: &str) -> (i64, String) {
        conn.query_row(
            r#"
            SELECT i.bitmask, v.fields
            FROM dirs d
            JOIN items i ON i.dir_id = d.id
            JOIN item_versions v ON v.item_id = i.id AND v.version_id = i.latest_version_id
            WHERE d.name = '_Internal'
              AND i.name = ?1
              AND i.oldest_version_id = 1
              AND i.latest_version_id = 1
            "#,
            [name],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap()
    }

    fn assert_setting_missing(conn: &Connection, name: &str) {
        let exists = conn
            .query_row(
                "SELECT 1 FROM system_settings WHERE name = ?1",
                [name],
                |_| Ok(()),
            )
            .optional()
            .unwrap()
            .is_some();
        assert!(!exists);
    }

    fn assert_setting_value(conn: &Connection, name: &str, expected: &str) {
        let value: String = conn
            .query_row(
                "SELECT value FROM system_settings WHERE name = ?1",
                [name],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(expected, value);
    }

    fn sqlite_code(error: rusqlite::Error) -> rusqlite::ErrorCode {
        match error {
            rusqlite::Error::SqliteFailure(error, _) => error.code,
            error => panic!("expected sqlite error, got {error:?}"),
        }
    }
}
