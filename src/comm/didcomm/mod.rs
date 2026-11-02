//! Centralized DIDComm client for Agent Stream.
//!
//! `DIDCommClient` owns the affinidi-messaging `ATM`, its `ATMProfile`, and the
//! shared `TDKSharedState`, and exposes every DIDComm operation the service
//! performs (websocket enable, register, pack+send, live-stream, preflight
//! health check, trust ping, auth test, DID-document cache, OOB retrieve). All
//! DIDComm access flows through one handle so reconnect / refresh / health-check
//! happen in one place, instead of the scattered per-call-site ATM instances the
//! service used before.
//!
//! There is no `CommClient` facade or follower-forwarding client; leadership is
//! gated at the connection-point listener manager.

pub mod client;
pub mod gateway;
pub mod mediator;
