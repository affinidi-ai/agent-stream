//! Message storage for incoming DIDComm messages received by connection points

use anyhow::Result;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use tokio::fs;

/// A received DIDComm message with metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReceivedMessage {
    /// Unique message ID
    pub id: String,

    /// Connection point ID this message was received on
    pub connection_point_id: String,

    /// Gateway ID
    pub gateway_id: String,

    /// DIDComm message type
    pub message_type: String,

    /// Message ID from the DIDComm message
    pub didcomm_message_id: String,

    /// Thread ID from the DIDComm message (for correlation)
    pub didcomm_thid: Option<String>,

    /// Parent thread ID binding a handshake message to its OOB invitation.
    #[serde(default)]
    pub didcomm_pthid: Option<String>,

    /// Claimed sender DID from the unpacked message; identity metadata must bind it.
    pub from_did: Option<String>,

    /// Recipient DID(s)
    pub to_dids: Vec<String>,

    /// The `domain` a presentation in a `forward-request` must name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub receiving_connection_point_did: Option<String>,

    /// Full DIDComm message body
    pub message_body: serde_json::Value,

    /// Message metadata from unpacking
    pub metadata: MessageMetadata,

    /// When this message was received
    pub received_at: DateTime<Utc>,

    /// Whether the message has been read/processed
    pub read: bool,

    /// Context data for message processing (not persisted)
    #[serde(skip)]
    pub context: std::collections::HashMap<String, serde_json::Value>,
}

/// Metadata from DIDComm message unpacking
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MessageMetadata {
    /// Whether the message was encrypted
    pub encrypted: bool,

    /// Whether the message was authenticated
    pub authenticated: bool,

    /// Verified sender key ID (authcrypt or signed), if available.
    pub from_key: Option<String>,

    /// Whether unpacking verified a signed envelope.
    #[serde(default)]
    pub non_repudiation: bool,

    /// Whether the encrypted envelope intentionally omitted sender identity.
    #[serde(default)]
    pub anonymous_sender: bool,

    /// Additional metadata fields
    pub extra: serde_json::Value,
}

impl ReceivedMessage {
    /// Create a new received message
    pub fn new(
        connection_point_id: String,
        gateway_id: String,
        message_type: String,
        didcomm_message_id: String,
        didcomm_thid: Option<String>,
        didcomm_pthid: Option<String>,
        from_did: Option<String>,
        to_dids: Vec<String>,
        message_body: serde_json::Value,
        metadata: MessageMetadata,
    ) -> Self {
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            connection_point_id,
            gateway_id,
            message_type,
            didcomm_message_id,
            didcomm_thid,
            didcomm_pthid,
            from_did,
            to_dids,
            receiving_connection_point_did: None,
            message_body,
            metadata,
            received_at: Utc::now(),
            read: false,
            context: std::collections::HashMap::new(),
        }
    }

    /// Add context data for message processing
    #[allow(dead_code)]
    pub fn with_context(
        mut self,
        key: impl Into<String>,
        value: serde_json::Value,
    ) -> Self {
        self.context
            .insert(key.into(), value);
        self
    }

    /// Mark message as read
    pub fn mark_read(&mut self) {
        self.read = true;
    }
}

/// Storage for received messages
pub struct MessageStore {
    base_path: PathBuf,
}

impl MessageStore {
    /// Create a new message store
    pub async fn new(base_path: PathBuf) -> Result<Self> {
        fs::create_dir_all(&base_path).await?;
        Ok(Self { base_path })
    }

    /// Store a received message
    pub async fn store(
        &self,
        _message: &ReceivedMessage,
    ) -> Result<()> {
        Ok(())
    }

    /// Get a message by ID
    pub async fn get(
        &self,
        connection_point_id: &str,
        message_id: &str,
    ) -> Result<Option<ReceivedMessage>> {
        let file_path = self
            .base_path
            .join(connection_point_id)
            .join(format!("{}.json", message_id));

        if !file_path.exists() {
            return Ok(None);
        }

        let contents = fs::read_to_string(file_path).await?;
        let message: ReceivedMessage = serde_json::from_str(&contents)?;
        Ok(Some(message))
    }

    /// List all messages for a connection point
    pub async fn list_by_connection_point(
        &self,
        connection_point_id: &str,
    ) -> Result<Vec<ReceivedMessage>> {
        let cp_dir = self
            .base_path
            .join(connection_point_id);

        if !cp_dir.exists() {
            return Ok(Vec::new());
        }

        let mut messages = Vec::new();
        let mut entries = fs::read_dir(cp_dir).await?;

        while let Some(entry) = entries.next_entry().await? {
            let path = entry.path();
            if path
                .extension()
                .and_then(|s| s.to_str())
                == Some("json")
                && let Ok(contents) = fs::read_to_string(&path).await
                && let Ok(message) = serde_json::from_str::<ReceivedMessage>(&contents)
            {
                messages.push(message);
            }
        }

        // Sort by received_at descending (newest first)
        messages.sort_by(|a, b| {
            b.received_at
                .cmp(&a.received_at)
        });

        Ok(messages)
    }

    /// Mark a message as read
    pub async fn mark_read(
        &self,
        connection_point_id: &str,
        message_id: &str,
    ) -> Result<()> {
        if let Some(mut message) = self
            .get(connection_point_id, message_id)
            .await?
        {
            message.mark_read();
            self.store(&message).await?;
        }
        Ok(())
    }

    /// Delete a message
    pub async fn delete(
        &self,
        connection_point_id: &str,
        message_id: &str,
    ) -> Result<()> {
        let file_path = self
            .base_path
            .join(connection_point_id)
            .join(format!("{}.json", message_id));

        if file_path.exists() {
            fs::remove_file(file_path).await?;
        }

        Ok(())
    }

    /// Delete all messages for a connection point
    #[allow(dead_code)]
    pub async fn delete_all(
        &self,
        connection_point_id: &str,
    ) -> Result<()> {
        let cp_dir = self
            .base_path
            .join(connection_point_id);

        if cp_dir.exists() {
            fs::remove_dir_all(cp_dir).await?;
        }

        Ok(())
    }

    /// Get unread message count for a connection point
    pub async fn get_unread_count(
        &self,
        connection_point_id: &str,
    ) -> Result<usize> {
        let messages = self
            .list_by_connection_point(connection_point_id)
            .await?;
        Ok(messages
            .iter()
            .filter(|m| !m.read)
            .count())
    }
}
