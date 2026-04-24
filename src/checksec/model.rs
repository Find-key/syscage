use std::path::PathBuf;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum RelroStatus {
    None,
    Partial,
    Full,
}

impl RelroStatus {
    pub(crate) fn as_str(&self) -> &'static str {
        match self {
            Self::None => "No RELRO",
            Self::Partial => "Partial RELRO",
            Self::Full => "Full RELRO",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum Status {
    Enabled,
    Disabled,
    Unknown,
}

impl Status {
    pub(crate) fn as_str(&self) -> &'static str {
        match self {
            Self::Enabled => "Enabled",
            Self::Disabled => "Disabled",
            Self::Unknown => "Unknown",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ChecksecReport {
    pub(crate) path: PathBuf,
    pub(crate) arch: String,
    pub(crate) relro: RelroStatus,
    pub(crate) shstk: Status,
    pub(crate) ibt: Status,
    pub(crate) canary: Status,
    pub(crate) nx: Status,
    pub(crate) pie: Status,
    pub(crate) fortify: Status,
    pub(crate) rpath: Status,
    pub(crate) runpath: Status,
    pub(crate) stripped: Status,
    pub(crate) rwx: Status,
    pub(crate) pie_base: Option<u64>,
}
