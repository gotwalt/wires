//! `WiresApp` — the UniFFI Object the iOS app instantiates once and drives.
//!
//! Lazily binds a single iroh `Endpoint` on first network call. All state on
//! the Rust side is in-memory and process-lifetime: durable fabric state
//! lives on the Swift side in SwiftData + Keychain. The only Rust state that
//! survives across calls is the bound endpoint and the in-flight pair-request
//! map (keyed by an opaque handle so Swift never sees the raw token).

use std::collections::HashMap;
use std::sync::Arc;

use iroh::{Endpoint, SecretKey};
use parking_lot::Mutex;
use tokio::sync::OnceCell;
use wires_net::pair::PairRequest;

use crate::error::{InternalSnafu, UnknownPairHandleSnafu, WiresError};
use crate::fabric as fabric_flow;
use crate::pair as pair_flow;
use crate::parse;
use crate::signer::SwiftRootSigner;
use crate::ticket;
use crate::topic::generate_topic_id_and_epoch0 as gen_topic;
use crate::types::{
    FabricRegistration, GrantedScope, HostInfo, NewTopic, PairAckRecord, PairRequestPreview,
    PendingPairHandle, UnregisterResult,
};

struct PendingPair {
    request: PairRequest,
}

#[derive(uniffi::Object)]
pub struct WiresApp {
    iroh_secret: [u8; 32],
    root_signer: Arc<dyn SwiftRootSigner>,
    endpoint: OnceCell<Endpoint>,
    pending: Mutex<HashMap<String, PendingPair>>,
}

#[uniffi::export(async_runtime = "tokio")]
impl WiresApp {
    #[uniffi::constructor]
    pub fn bootstrap(iroh_secret: Vec<u8>, root_signer: Arc<dyn SwiftRootSigner>) -> Arc<Self> {
        let mut secret = [0u8; 32];
        let n = iroh_secret.len().min(32);
        secret[..n].copy_from_slice(&iroh_secret[..n]);
        Arc::new(Self {
            iroh_secret: secret,
            root_signer,
            endpoint: OnceCell::new(),
            pending: Mutex::new(HashMap::new()),
        })
    }

    pub fn parse_host_ticket(&self, payload: String) -> Result<HostInfo, WiresError> {
        ticket::parse_host_ticket(&payload)
    }

    pub async fn register_with_hosted_service(
        &self,
        host: HostInfo,
    ) -> Result<FabricRegistration, WiresError> {
        let ep = self.endpoint().await?;
        fabric_flow::register_with_hosted_service(ep, self.root_signer.clone(), &host).await
    }

    pub async fn unregister_with_hosted_service(
        &self,
        host: HostInfo,
    ) -> Result<UnregisterResult, WiresError> {
        let ep = self.endpoint().await?;
        fabric_flow::unregister_with_hosted_service(ep, self.root_signer.clone(), &host).await
    }

    pub async fn register_topic(
        &self,
        host: HostInfo,
        topic_id: Vec<u8>,
    ) -> Result<(), WiresError> {
        if topic_id.len() != 32 {
            return Err(InternalSnafu {
                message: String::from("topic_id must be 32 bytes"),
            }
            .build());
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&topic_id);
        let ep = self.endpoint().await?;
        fabric_flow::register_topic(ep, self.root_signer.clone(), &host, &arr).await
    }

    pub fn parse_pair_request(&self, payload: String) -> Result<PairRequestPreview, WiresError> {
        let parsed = parse::parse_pair_request(&payload)?;
        let preview = parsed.preview.clone();
        self.pending.lock().insert(
            parsed.handle.id.clone(),
            PendingPair {
                request: parsed.request,
            },
        );
        Ok(preview)
    }

    pub fn generate_topic_id_and_epoch0(&self) -> NewTopic {
        gen_topic()
    }

    pub async fn approve_pair_request(
        &self,
        handle: PendingPairHandle,
        granted_scopes: Vec<GrantedScope>,
        host: HostInfo,
    ) -> Result<PairAckRecord, WiresError> {
        let pending = self
            .pending
            .lock()
            .remove(&handle.id)
            .ok_or_else(|| UnknownPairHandleSnafu.build())?;
        let ep = self.endpoint().await?;
        pair_flow::approve_pair_request(
            ep,
            self.root_signer.clone(),
            &pending.request,
            granted_scopes,
            host,
        )
        .await
    }

    pub fn discard_pair_request(&self, handle: PendingPairHandle) {
        self.pending.lock().remove(&handle.id);
    }
}

impl WiresApp {
    async fn endpoint(&self) -> Result<Endpoint, WiresError> {
        let ep = self
            .endpoint
            .get_or_try_init(|| async {
                let secret = SecretKey::from_bytes(&self.iroh_secret);
                wires_net::bind_lan(secret, vec![]).await.map_err(|e| {
                    InternalSnafu {
                        message: format!("bind_lan: {e}"),
                    }
                    .build()
                })
            })
            .await?;
        Ok(ep.clone())
    }
}
