use super::*;

#[derive(Debug, Clone)]
pub enum DatabaseDriver {
    Sqlite(SqliteDb),
    MySql(MySqlDb),
    Postgres(PostgresDb),
}

macro_rules! delegate_db_async {
    ($self:ident, $method:ident ( $($arg:expr),* $(,)? )) => {
        match $self {
            DatabaseDriver::Sqlite(inner) => inner.$method($($arg),*).await,
            DatabaseDriver::MySql(inner) => inner.$method($($arg),*).await,
            DatabaseDriver::Postgres(inner) => inner.$method($($arg),*).await,
        }
    };
}

#[path = "access.rs"]
mod driver_access;
#[path = "config.rs"]
mod driver_config;

#[cfg(test)]
#[path = "tests.rs"]
mod tests;
