use std::borrow::Cow;

use thiserror::Error;

pub(crate) type ValueResult<T> = Result<T, ValueError>;

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub(crate) enum ValueError {
    #[error("{message}")]
    Message { message: Cow<'static, str> },
}

impl ValueError {
    pub(crate) fn new(message: impl Into<Cow<'static, str>>) -> Self {
        Self::Message {
            message: message.into(),
        }
    }
}
