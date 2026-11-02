//! Channel-specific logging utilities
//!
//! Provides macros for logging with channel context prepended as
//! `[CHANNEL:config_id]`.

/// Log info message with channel prefix
#[macro_export]
macro_rules! channel_info {
    ($config_id:expr, $($arg:tt)*) => {
        tracing::info!("[CHANNEL:{}] {}", $config_id, format!($($arg)*))
    };
}

/// Log warn message with channel prefix
#[macro_export]
macro_rules! channel_warn {
    ($config_id:expr, $($arg:tt)*) => {
        tracing::warn!("[CHANNEL:{}] {}", $config_id, format!($($arg)*))
    };
}

/// Log error message with channel prefix
#[macro_export]
macro_rules! channel_error {
    ($config_id:expr, $($arg:tt)*) => {
        tracing::error!("[CHANNEL:{}] {}", $config_id, format!($($arg)*))
    };
}

/// Log debug message with channel prefix
#[macro_export]
macro_rules! channel_debug {
    ($config_id:expr, $($arg:tt)*) => {
        tracing::debug!("[CHANNEL:{}] {}", $config_id, format!($($arg)*))
    };
}
