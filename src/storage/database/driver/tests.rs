use super::{DatabaseDriver, driver_config::DEFAULT_SQLITE_DB_URL};

#[test]
fn sqlite_url_normalization_uses_default_and_appends_mode() {
    assert_eq!(
        DatabaseDriver::normalize_db_url(None),
        DEFAULT_SQLITE_DB_URL.to_string()
    );
    assert_eq!(
        DatabaseDriver::normalize_db_url(Some("sqlite:///tmp/pushgo.db")),
        "sqlite:///tmp/pushgo.db?mode=rwc"
    );
    assert_eq!(
        DatabaseDriver::normalize_db_url(Some("sqlite:///tmp/pushgo.db?cache=shared")),
        "sqlite:///tmp/pushgo.db?cache=shared&mode=rwc"
    );
}

#[test]
fn sqlite_url_normalization_preserves_existing_mode_and_non_sqlite_urls() {
    assert_eq!(
        DatabaseDriver::normalize_db_url(Some("sqlite:///tmp/pushgo.db?mode=ro")),
        "sqlite:///tmp/pushgo.db?mode=ro"
    );
    assert_eq!(
        DatabaseDriver::normalize_db_url(Some("postgres://gateway:pw@localhost/pushgo")),
        "postgres://gateway:pw@localhost/pushgo"
    );
}
