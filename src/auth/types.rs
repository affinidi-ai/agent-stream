use serde::{Deserialize, Serialize};

/// User role enum
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default, strum::EnumIter)]
#[serde(rename_all = "lowercase")]
pub enum UserRole {
    Administrator,
    PowerUser,
    #[default]
    User,
}

impl UserRole {
    /// The role a configuration file names, read without regard to case, or `None` when the
    /// name is not `administrator`, `poweruser` or `user`.
    pub fn from_config_name(name: &str) -> Option<Self> {
        match name.to_lowercase().as_str() {
            "administrator" => Some(UserRole::Administrator),
            "poweruser" => Some(UserRole::PowerUser),
            "user" => Some(UserRole::User),
            _ => None,
        }
    }

    /// Orders roles by the access they grant, so the highest of several can be chosen
    /// and the PAT scope ceiling can compare an issuer with its subject.
    pub fn rank(&self) -> u8 {
        match self {
            UserRole::User => 0,
            UserRole::PowerUser => 1,
            UserRole::Administrator => 2,
        }
    }
}

impl std::fmt::Display for UserRole {
    fn fmt(
        &self,
        f: &mut std::fmt::Formatter<'_>,
    ) -> std::fmt::Result {
        match self {
            UserRole::Administrator => write!(f, "administrator"),
            UserRole::PowerUser => write!(f, "poweruser"),
            UserRole::User => write!(f, "user"),
        }
    }
}

/// User status enum
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
#[serde(rename_all = "lowercase")]
pub enum UserStatus {
    /// New user awaiting approval
    #[default]
    New,
    /// Approved user who can sign in
    Approved,
    /// Disabled user who cannot sign in
    Disabled,
}

impl std::fmt::Display for UserStatus {
    fn fmt(
        &self,
        f: &mut std::fmt::Formatter<'_>,
    ) -> std::fmt::Result {
        match self {
            UserStatus::New => write!(f, "new"),
            UserStatus::Approved => write!(f, "approved"),
            UserStatus::Disabled => write!(f, "disabled"),
        }
    }
}
