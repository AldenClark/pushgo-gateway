#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DomainAction {
    Send,
    Create,
    Update,
    Close,
    Archive,
    Delete,
}

impl DomainAction {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Send => "send",
            Self::Create => "create",
            Self::Update => "update",
            Self::Close => "close",
            Self::Archive => "archive",
            Self::Delete => "delete",
        }
    }
}
