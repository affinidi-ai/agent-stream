use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use webauthn_rs::prelude::*;

use crate::auth::session::SessionManager;
use crate::auth::storage::PasskeyStorage;

/// How long a registration or sign-in challenge can be completed.
const CHALLENGE_TTL: chrono::Duration = chrono::Duration::minutes(5);

/// Most outstanding challenges held at once. The start endpoints are public,
/// so at the cap the oldest challenge is dropped to make room.
pub(super) const MAX_PENDING_CHALLENGES: usize = 10_000;

/// State for the authentication system
#[derive(Clone)]
pub struct AuthState {
    /// WebAuthn instance for passkey operations
    pub webauthn: Arc<Webauthn>,

    /// Storage for user credentials and passkeys
    pub storage: Arc<PasskeyStorage>,

    /// Session manager for tracking authenticated sessions
    pub session_manager: Arc<SessionManager>,

    /// Temporary storage for registration and authentication challenges
    pub challenges: Arc<RwLock<HashMap<String, ChallengeState>>>,

    /// Optional notification store for sending notifications
    pub notification_store: Arc<RwLock<Option<Arc<crate::integrations::FileSystemNotificationStore>>>>,

    /// Metrics store for recording authentication-related metrics
    pub metrics_store: Arc<crate::metrics::MetricsStore>,

    /// Terms enforcement for human authentication.
    pub terms_manager: Arc<crate::terms::TermsManager>,
}

/// Temporary state for WebAuthn challenges
#[derive(Clone)]
pub struct ChallengeState {
    /// Registration state for passkey creation
    pub registration_state: Option<PasskeyRegistration>,

    /// Authentication state for passkey login
    pub authentication_state: Option<PasskeyAuthentication>,

    /// Username associated with this challenge
    pub username: String,

    /// Timestamp when this challenge was created
    pub created_at: chrono::DateTime<chrono::Utc>,
}

impl ChallengeState {
    fn is_expired(
        &self,
        now: chrono::DateTime<chrono::Utc>,
    ) -> bool {
        now.signed_duration_since(self.created_at) >= CHALLENGE_TTL
    }
}

impl AuthState {
    /// Create a new authentication state
    pub async fn new(
        rp_id: String,
        rp_origin: url::Url,
        storage_path: String,
        avatars_path: String,
        session_timeout_minutes: u64,
        sessions_storage_path: String,
        metrics_store: Arc<crate::metrics::MetricsStore>,
        terms_manager: Arc<crate::terms::TermsManager>,
    ) -> anyhow::Result<Self> {
        // Build WebAuthn instance
        let builder = WebauthnBuilder::new(&rp_id, &rp_origin)?;
        let webauthn = Arc::new(builder.build()?);

        // Initialize storage
        let storage = Arc::new(PasskeyStorage::new(storage_path, avatars_path).await?);

        // Initialize session manager with configured timeout and filesystem persistence
        let session_manager = Arc::new(
            SessionManager::with_storage(session_timeout_minutes, std::path::PathBuf::from(sessions_storage_path))
                .await?,
        );

        Ok(Self {
            webauthn,
            storage,
            session_manager,
            challenges: Arc::new(RwLock::new(HashMap::new())),
            notification_store: Arc::new(RwLock::new(None)),
            metrics_store,
            terms_manager,
        })
    }

    /// Hold a challenge until its finish step. When the store is full,
    /// expired challenges are dropped first, then the oldest.
    pub async fn insert_challenge(
        &self,
        challenge_id: String,
        challenge: ChallengeState,
    ) {
        let mut challenges = self.challenges.write().await;
        if challenges.len() >= MAX_PENDING_CHALLENGES {
            let now = chrono::Utc::now();
            challenges.retain(|_, pending| !pending.is_expired(now));
        }
        while challenges.len() >= MAX_PENDING_CHALLENGES {
            let Some(oldest) = challenges
                .iter()
                .min_by_key(|(_, pending)| pending.created_at)
                .map(|(id, _)| id.clone())
            else {
                break;
            };
            challenges.remove(&oldest);
        }
        challenges.insert(challenge_id, challenge);
    }

    /// Remove and return a challenge for its finish step, or `None` when it is
    /// unknown, already used or expired.
    pub async fn take_challenge(
        &self,
        challenge_id: &str,
    ) -> Option<ChallengeState> {
        let challenge = self
            .challenges
            .write()
            .await
            .remove(challenge_id)?;
        (!challenge.is_expired(chrono::Utc::now())).then_some(challenge)
    }
}
