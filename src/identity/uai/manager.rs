#![allow(dead_code)]

use anyhow::{Result, bail};

use super::types::{TrustScore, UaiIdentity};

pub struct UaiIdentityManager;

impl UaiIdentityManager {
    pub fn new() -> Self {
        Self
    }

    pub fn create_identity(
        &self,
        _identity: UaiIdentity,
    ) -> Result<UaiIdentity> {
        bail!("create_identity() not yet implemented")
    }

    pub fn verify_identity(
        &self,
        _did: &str,
    ) -> Result<TrustScore> {
        bail!("verify_identity() not yet implemented")
    }
}
