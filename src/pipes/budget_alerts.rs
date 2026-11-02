//! Budget alert integration using the integration system

use super::budget_tracker::{AlertService, MonthlyBudgetUsage};
use async_trait::async_trait;
use std::sync::Arc;
use tracing::{error, info};

/// Integration-based budget alert service
/// This triggers pipe budget events through the global integration system
pub struct BudgetAlertIntegration {
    notification_store: Option<Arc<crate::integrations::FileSystemNotificationStore>>,
    pipe_store: Option<Arc<crate::pipes::filesystem::FileSystemPipeStore>>,
}

impl BudgetAlertIntegration {
    pub fn new(
        notification_store: Option<Arc<crate::integrations::FileSystemNotificationStore>>,
        pipe_store: Option<Arc<crate::pipes::filesystem::FileSystemPipeStore>>,
    ) -> Self {
        Self { notification_store, pipe_store }
    }
}

#[async_trait]
impl AlertService for BudgetAlertIntegration {
    async fn send_budget_alert(
        &self,
        pipe_id: &str,
        usage: &MonthlyBudgetUsage,
    ) -> Result<(), String> {
        info!(
            "Sending budget alert for pipe '{}': ${:.2}/${:.2} ({:.1}%)",
            usage.pipe_id,
            usage.total_spent,
            usage.budget_limit,
            usage.usage_percentage()
        );

        // Load the pipe's name and integrations
        let (pipe_name, integrations, tenant_id) = if let Some(pipe_store) = &self.pipe_store {
            match pipe_store.get(pipe_id).await {
                Some(pipe_config) => {
                    // Include the appliance-wide default `pipe` integrations.
                    let pipe_config = pipe_config.with_global_surface_defaults();
                    (pipe_config.name, pipe_config.integrations, pipe_config.tenant_id)
                }
                None => {
                    error!("Failed to load pipe config for budget alert: pipe not found");
                    (pipe_id.to_string(), Vec::new(), None)
                }
            }
        } else {
            (pipe_id.to_string(), Vec::new(), None)
        };

        // Create budget alert object for integration triggers
        let alert = crate::integrations::pipe_integration_triggers::BudgetAlert {
            currency: crate::integrations::pipe_integration_triggers::usd_currency(),
            pipe_id: usage.pipe_id.clone(),
            pipe_name,
            month: usage.month.clone(),
            total_spent: usage.total_spent,
            budget_limit: usage.budget_limit,
            usage_percentage: usage.usage_percentage(),
            remaining_budget: usage.remaining_budget(),
            alert_threshold_percent: usage.alert_threshold_percent,
            budget_exceeded: usage.budget_exceeded(),
            tenant_id,
            integrations,
        };

        // Trigger budget alert integration event asynchronously
        // This will be picked up by any active pipe integrations configured to listen
        // for budget events (pipe.budget.threshold_reached or pipe.budget.exceeded)
        if alert.budget_exceeded {
            crate::integrations::async_triggers::trigger_pipe_budget_exceeded_async(
                self.notification_store
                    .clone(),
                alert,
            );
        } else {
            crate::integrations::async_triggers::trigger_pipe_budget_threshold_async(
                self.notification_store
                    .clone(),
                alert,
            );
        }

        Ok(())
    }
}
