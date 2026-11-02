//! Payment enforcement for paid surfaces on the fabric receive path.
//!
//! A surface whose target sets a `payment_policy` is paid. Before such a
//! request is sent to the target it is relayed to the Agent Pay surface
//! `fabric://{payment_gateway_id}/{payment_surface_id}`, which verifies and
//! settles the payment. Its answer decides the request:
//!
//! * `2xx`: paid (or free). The request goes on to the target, and Agent Pay's
//!   allow-listed receipt headers are added to the caller's response in place
//!   of any receipt header the target set.
//! * `402`: the payment challenge is returned to the caller with only the
//!   allow-listed challenge headers.
//! * any other status, a misconfigured policy, or no answer: refused.

use std::collections::HashMap;
use std::time::Duration;

use crate::config::agent_surface::{PaymentPolicy, PaymentProvider};
use crate::fabric_marketplace::FabricForwardResult;
use crate::gateways::ConnectionPointListenerManager;

/// Request headers relayed to Agent Pay: the payment credential and how the
/// body is encoded. Any other header, such as a credential meant for the
/// target, stays on this appliance.
const RELAYED_HEADERS: &[&str] = &["payment-signature", "x-payment", "content-type", "accept"];

/// Whether the request header `name: value` is relayed to Agent Pay.
/// `Authorization` is relayed only when it carries a `Payment` credential.
pub(crate) fn is_relayed_header(
    name: &str,
    value: &str,
) -> bool {
    RELAYED_HEADERS
        .iter()
        .any(|relayed| name.eq_ignore_ascii_case(relayed))
        || name.eq_ignore_ascii_case("authorization")
            && value
                .split_once(' ')
                .is_some_and(|(scheme, _)| scheme.eq_ignore_ascii_case("payment"))
}

/// Headers that prove a payment. On a charged request only Agent Pay may set them.
const RECEIPT_HEADERS: &[&str] =
    &["payment-response", "x-payment-response", "payment-receipt", "x-payment-receipt", "x-settlement-tx"];

/// Whether `name` is a header that proves a payment.
pub(crate) fn is_receipt_header(name: &str) -> bool {
    RECEIPT_HEADERS
        .iter()
        .any(|receipt| name.eq_ignore_ascii_case(receipt))
}

/// Headers copied from Agent Pay's `402` onto the challenge the caller gets.
/// Everything else (cookies, credentials, tracing, server fingerprints) stays
/// with Agent Pay.
const CHALLENGE_HEADER_ALLOWLIST: &[&str] = &[
    "content-type",
    "payment-required",
    "x-payment-required",
    "payment-response",
    "x-payment-response",
    "www-authenticate",
    "retry-after",
    "cache-control",
];

/// Sends a request to a surface on a peer appliance and returns its answer,
/// waiting at most `timeout`.
#[async_trait::async_trait]
pub(crate) trait AgentPayRelay: Send + Sync {
    async fn relay(
        &self,
        fabric_target: &str,
        method: &str,
        path: &str,
        headers: HashMap<String, String>,
        body: &[u8],
        timeout: Duration,
    ) -> Result<FabricForwardResult, String>;
}

#[async_trait::async_trait]
impl AgentPayRelay for ConnectionPointListenerManager {
    async fn relay(
        &self,
        fabric_target: &str,
        method: &str,
        path: &str,
        headers: HashMap<String, String>,
        body: &[u8],
        timeout: Duration,
    ) -> Result<FabricForwardResult, String> {
        crate::fabric_marketplace::fabric_forward_within(self, fabric_target, method, path, headers, body, timeout)
            .await
    }
}

/// What happens to a request on a paid surface.
#[derive(Debug, PartialEq)]
pub(crate) enum PaymentDecision {
    /// Paid: send the request on and add these headers to the response.
    Proceed { receipt_headers: HashMap<String, String> },
    /// Not paid: return Agent Pay's challenge to the caller.
    Challenge { status: u16, headers: HashMap<String, String>, body: String },
    /// Refused with `status`. `reason` is for the log only.
    Refuse { status: u16, reason: String },
}

/// Ask Agent Pay whether the request may go through, waiting at most `timeout`
/// for its answer. `relay` is `None` when this appliance has no fabric to reach
/// Agent Pay over.
pub(crate) async fn enforce(
    policy: &PaymentPolicy,
    relay: Option<&dyn AgentPayRelay>,
    method: &str,
    path: &str,
    headers: HashMap<String, String>,
    body: &[u8],
    timeout: Duration,
) -> PaymentDecision {
    let target = match agent_pay_target(policy) {
        Ok(target) => target,
        Err(reason) => return PaymentDecision::Refuse { status: 502, reason },
    };
    let Some(relay) = relay else {
        return PaymentDecision::Refuse {
            status: 503,
            reason: "the fabric is not running, so Agent Pay cannot be reached".to_string(),
        };
    };
    match relay
        .relay(&target, method, path, headers, body, timeout)
        .await
    {
        Ok(response) => decide(response),
        Err(e) => PaymentDecision::Refuse {
            status: 502,
            reason: format!("relay to {target} failed: {e}"),
        },
    }
}

/// The `fabric://` address of the policy's Agent Pay surface.
fn agent_pay_target(policy: &PaymentPolicy) -> Result<String, String> {
    let PaymentProvider::AgentPay = policy.provider;
    let segment = |id: &str| {
        let id = id.trim();
        (!id.is_empty() && !id.contains('/')).then_some(id.to_string())
    };
    match (segment(&policy.payment_gateway_id), segment(&policy.payment_surface_id)) {
        (Some(gateway), Some(surface)) => Ok(format!("fabric://{gateway}/{surface}")),
        _ => Err("payment_policy needs a payment_gateway_id and a payment_surface_id, without '/'".to_string()),
    }
}

fn decide(response: FabricForwardResult) -> PaymentDecision {
    match response.status {
        200..=299 => PaymentDecision::Proceed {
            receipt_headers: allowed(&response.headers, &[RECEIPT_HEADERS, &["cache-control"]].concat()),
        },
        402 => PaymentDecision::Challenge {
            status: 402,
            headers: allowed(&response.headers, CHALLENGE_HEADER_ALLOWLIST),
            body: response.body,
        },
        other => PaymentDecision::Refuse {
            status: 502,
            reason: format!("Agent Pay answered with status {other}"),
        },
    }
}

fn allowed(
    headers: &HashMap<String, String>,
    allowlist: &[&str],
) -> HashMap<String, String> {
    headers
        .iter()
        .filter(|(name, _)| {
            allowlist
                .iter()
                .any(|allowed| name.eq_ignore_ascii_case(allowed))
        })
        .map(|(name, value)| (name.clone(), value.clone()))
        .collect()
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::sync::Mutex;

    pub(crate) fn agent_pay_policy() -> PaymentPolicy {
        PaymentPolicy {
            provider: PaymentProvider::AgentPay,
            payment_gateway_id: "gw-pay".to_string(),
            payment_surface_id: "pay-surface".to_string(),
        }
    }

    /// One request Agent Pay received.
    #[derive(Debug, Clone, PartialEq)]
    pub(crate) struct Relayed {
        pub fabric_target: String,
        pub method: String,
        pub path: String,
        pub headers: HashMap<String, String>,
        pub body: Vec<u8>,
        pub timeout: Duration,
    }

    /// Status, headers and body.
    type Answer = (u16, Vec<(&'static str, &'static str)>, &'static str);

    /// An Agent Pay that answers every request with the same status, headers
    /// and body, or fails to answer, and records what it was sent.
    pub(crate) struct FakeAgentPay {
        answer: Result<Answer, &'static str>,
        received: Mutex<Vec<Relayed>>,
    }

    impl FakeAgentPay {
        pub(crate) fn answering(
            status: u16,
            headers: &[(&'static str, &'static str)],
            body: &'static str,
        ) -> Self {
            Self {
                answer: Ok((status, headers.to_vec(), body)),
                received: Mutex::new(Vec::new()),
            }
        }

        pub(crate) fn unreachable() -> Self {
            Self {
                answer: Err("no connection to gateway 'gw-pay'"),
                received: Mutex::new(Vec::new()),
            }
        }

        pub(crate) fn received(&self) -> Vec<Relayed> {
            self.received
                .lock()
                .unwrap()
                .clone()
        }
    }

    #[async_trait::async_trait]
    impl AgentPayRelay for FakeAgentPay {
        async fn relay(
            &self,
            fabric_target: &str,
            method: &str,
            path: &str,
            headers: HashMap<String, String>,
            body: &[u8],
            timeout: Duration,
        ) -> Result<FabricForwardResult, String> {
            self.received
                .lock()
                .unwrap()
                .push(Relayed {
                    fabric_target: fabric_target.to_string(),
                    method: method.to_string(),
                    path: path.to_string(),
                    headers,
                    body: body.to_vec(),
                    timeout,
                });
            let (status, headers, body) = self
                .answer
                .clone()
                .map_err(str::to_string)?;
            Ok(FabricForwardResult {
                status,
                body: body.to_string(),
                headers: headers
                    .into_iter()
                    .map(|(name, value)| (name.to_string(), value.to_string()))
                    .collect(),
            })
        }
    }

    const TIMEOUT: Duration = Duration::from_secs(5);

    async fn enforce_against(agent_pay: &FakeAgentPay) -> PaymentDecision {
        enforce(&agent_pay_policy(), Some(agent_pay), "POST", "/a2a", HashMap::new(), b"{}", TIMEOUT).await
    }

    #[tokio::test]
    async fn a_2xx_from_agent_pay_proceeds_with_only_the_receipt_headers() {
        let agent_pay = FakeAgentPay::answering(
            200,
            &[("PAYMENT-RESPONSE", "settled"), ("Set-Cookie", "sid=agent-pay"), ("Server", "agent-pay")],
            "",
        );

        assert_eq!(
            enforce_against(&agent_pay).await,
            PaymentDecision::Proceed {
                receipt_headers: HashMap::from([("PAYMENT-RESPONSE".to_string(), "settled".to_string())]),
            }
        );
    }

    #[tokio::test]
    async fn a_402_from_agent_pay_is_the_challenge_with_only_the_challenge_headers() {
        let agent_pay = FakeAgentPay::answering(
            402,
            &[
                ("PAYMENT-REQUIRED", "eyJhY2NlcHRzIjpbXX0="),
                ("Content-Type", "application/json"),
                ("Authorization", "Bearer internal"),
                ("Set-Cookie", "sid=agent-pay"),
                ("Traceparent", "00-abc-def-01"),
            ],
            r#"{"accepts":[]}"#,
        );

        assert_eq!(
            enforce_against(&agent_pay).await,
            PaymentDecision::Challenge {
                status: 402,
                headers: HashMap::from([
                    ("PAYMENT-REQUIRED".to_string(), "eyJhY2NlcHRzIjpbXX0=".to_string()),
                    ("Content-Type".to_string(), "application/json".to_string()),
                ]),
                body: r#"{"accepts":[]}"#.to_string(),
            }
        );
    }

    #[tokio::test]
    async fn any_other_answer_from_agent_pay_is_refused() {
        for status in [301, 400, 401, 403, 404, 500, 503] {
            let decision = enforce_against(&FakeAgentPay::answering(status, &[], "")).await;

            assert!(matches!(decision, PaymentDecision::Refuse { status: 502, .. }), "{status}: {decision:?}");
        }
    }

    #[tokio::test]
    async fn no_answer_from_agent_pay_is_refused() {
        let decision = enforce_against(&FakeAgentPay::unreachable()).await;

        assert!(matches!(decision, PaymentDecision::Refuse { status: 502, .. }), "{decision:?}");
    }

    #[tokio::test]
    async fn without_a_fabric_the_request_is_refused() {
        let decision = enforce(&agent_pay_policy(), None, "POST", "/a2a", HashMap::new(), b"{}", TIMEOUT).await;

        assert!(matches!(decision, PaymentDecision::Refuse { status: 503, .. }), "{decision:?}");
    }

    #[tokio::test]
    async fn the_request_goes_to_the_policys_agent_pay_surface_unchanged() {
        let agent_pay = FakeAgentPay::answering(200, &[], "");
        let headers = HashMap::from([("PAYMENT-SIGNATURE".to_string(), "signed".to_string())]);

        enforce(&agent_pay_policy(), Some(&agent_pay), "POST", "/a2a?x=1", headers.clone(), b"{\"id\":1}", TIMEOUT)
            .await;

        assert_eq!(
            agent_pay.received(),
            vec![Relayed {
                fabric_target: "fabric://gw-pay/pay-surface".to_string(),
                method: "POST".to_string(),
                path: "/a2a?x=1".to_string(),
                headers,
                body: b"{\"id\":1}".to_vec(),
                timeout: TIMEOUT,
            }]
        );
    }

    #[tokio::test]
    async fn a_misconfigured_policy_is_refused_without_calling_agent_pay() {
        for (gateway, surface) in [("", "pay-surface"), ("gw-pay", "  "), ("gw-pay/other", "pay-surface")] {
            let agent_pay = FakeAgentPay::answering(200, &[], "");
            let policy = PaymentPolicy {
                payment_gateway_id: gateway.to_string(),
                payment_surface_id: surface.to_string(),
                ..agent_pay_policy()
            };

            let decision = enforce(&policy, Some(&agent_pay), "POST", "/a2a", HashMap::new(), b"{}", TIMEOUT).await;

            assert!(
                matches!(decision, PaymentDecision::Refuse { status: 502, .. }),
                "{gateway:?}/{surface:?}: {decision:?}"
            );
            assert!(
                agent_pay
                    .received()
                    .is_empty(),
                "{gateway:?}/{surface:?} reached Agent Pay"
            );
        }
    }

    #[test]
    fn the_agent_pay_target_trims_its_ids() {
        let policy = PaymentPolicy {
            payment_gateway_id: " gw-pay ".to_string(),
            ..agent_pay_policy()
        };

        assert_eq!(agent_pay_target(&policy), Ok("fabric://gw-pay/pay-surface".to_string()));
    }
}
