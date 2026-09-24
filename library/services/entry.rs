//! A service entry the root signs on its own, like a badge (card 36d).
//!
//! The policy's head signs a hash of every item ([`ItemsHash`](crate::ItemsHash)),
//! which is all a host or directory needs: they hold the whole policy. A
//! caller holds only the services it may use (its [`View`](crate::View)), so
//! each service entry also carries its own root signature: a caller checks
//! each entry alone, against the root key it joined with, and a directory can
//! neither forge one nor move one to another fabric.
//!
//! The service item in the policy *is* the signed entry, so the head's
//! `items_hash` covers it too.
//!
//! - **Signed bytes:** [`ENTRY_CONTEXT`] followed by the canonical JSON of
//!   every field but `sig`.
//! - **Format:** [`ENTRY_V1`], signed; unknown fields are refused at decode.
//! - **`version`** is the policy version at which the entry last changed. An
//!   edit re-signs only the entries it changes
//!   ([`Policy::sign_after`](crate::Policy::sign_after)); the rest keep their
//!   signature and version. A holder keeps the newest version of each entry
//!   and never takes an older one ([`View::apply`](crate::View::apply)).
//!
//! ```
//! use library::{NodeIdentity, Service, ServiceName, SignedEntry, StateVersion};
//! let root = NodeIdentity::from_seed([1u8; 32]);
//! let service = Service {
//!     description: "uptime".into(), allow: vec![], hosts: vec![], readers: vec![],
//! };
//! let name = ServiceName::new("status").unwrap();
//! let entry = SignedEntry::sign(&root, StateVersion(4), name, service).unwrap();
//! entry.verify(root.node_id()).unwrap();
//! // Another fabric's root doesn't vouch for it.
//! assert!(entry.verify(NodeIdentity::from_seed([2u8; 32]).node_id()).is_err());
//! ```

use serde::{Deserialize, Serialize};

use crate::codec::canonical_bytes;
use crate::error::{Error, Result};
use crate::head::StateVersion;
use crate::identity::{AlgorithmId, NodeId, NodeIdentity, Signature};
use crate::registry::{Service, ServiceName};

/// The current (and only) signed-entry format.
pub const ENTRY_V1: u8 = 1;

/// Domain-separation prefix of a signed entry's bytes.
pub const ENTRY_CONTEXT: &[u8] = b"wires/service-entry/v1\0";

/// A service registry entry signed by the root. See the module docs.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedEntry {
    /// Format discriminant; [`ENTRY_V1`]. Signed.
    pub format: u8,
    /// The root's node id: the authority, pinned by
    /// [`verify`](Self::verify).
    pub fabric: NodeId,
    /// The policy version at which this entry last changed (never above the
    /// version of the head it is served under).
    pub version: StateVersion,
    /// The service's name.
    pub name: ServiceName,
    /// Who may call and read it, and which hosts run it.
    pub service: Service,
    /// Which scheme `sig` was produced with.
    pub alg: AlgorithmId,
    /// The root's signature over [`ENTRY_CONTEXT`] ‖ the canonical body.
    pub sig: Signature,
}

impl SignedEntry {
    /// Sign `service` as entry `name` at `version` with the root key (the
    /// fabric is the root's node id).
    pub fn sign(
        root: &NodeIdentity,
        version: StateVersion,
        name: ServiceName,
        service: Service,
    ) -> Result<SignedEntry> {
        let body = SignedBody {
            format: ENTRY_V1,
            fabric: root.node_id(),
            version,
            name: &name,
            service: &service,
            alg: AlgorithmId::Ed25519,
        };
        let sig = root.sign(&body.signed_bytes()?);
        Ok(SignedEntry {
            format: body.format,
            fabric: body.fabric,
            version,
            alg: body.alg,
            name,
            service,
            sig,
        })
    }

    /// Verify it on its own: format and algorithm, the `fabric == root` pin
    /// ([`Error::InvalidSignature`] for another fabric's entry), and the
    /// root's signature. Says nothing about which head it is served under
    /// (a [`View`](crate::View) or [`SignedPolicy`](crate::SignedPolicy)
    /// checks `version` against its head).
    pub fn verify(&self, root: NodeId) -> Result<()> {
        if self.format != ENTRY_V1 {
            return Err(Error::UnsupportedVersion);
        }
        if self.alg != AlgorithmId::Ed25519 {
            return Err(Error::UnsupportedAlgorithm);
        }
        if self.fabric != root {
            return Err(Error::InvalidSignature);
        }
        root.verify(&self.signed_bytes()?, &self.sig)
    }

    /// Whether this is the same entry as `service` under `name` in `fabric`:
    /// what an edit checks before keeping an entry's signature and version.
    pub fn is_for(&self, fabric: NodeId, name: &ServiceName, service: &Service) -> bool {
        self.fabric == fabric && self.name == *name && self.service == *service
    }

    /// The bytes [`sig`](Self::sig) covers.
    fn signed_bytes(&self) -> Result<Vec<u8>> {
        SignedBody {
            format: self.format,
            fabric: self.fabric,
            version: self.version,
            name: &self.name,
            service: &self.service,
            alg: self.alg,
        }
        .signed_bytes()
    }
}

/// The signed portion of a [`SignedEntry`]: every field but `sig`.
#[derive(Serialize)]
struct SignedBody<'a> {
    format: u8,
    fabric: NodeId,
    version: StateVersion,
    name: &'a ServiceName,
    service: &'a Service,
    alg: AlgorithmId,
}

impl SignedBody<'_> {
    /// [`ENTRY_CONTEXT`] ‖ the canonical body: what the root signs.
    fn signed_bytes(&self) -> Result<Vec<u8>> {
        let mut bytes = ENTRY_CONTEXT.to_vec();
        bytes.extend(canonical_bytes(self)?);
        Ok(bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn root() -> NodeIdentity {
        NodeIdentity::from_seed([1u8; 32])
    }

    fn node(b: u8) -> NodeId {
        NodeIdentity::from_seed([b; 32]).node_id()
    }

    fn service() -> Service {
        Service {
            description: "uptime".into(),
            allow: vec![crate::RoleName::new("staff").unwrap()],
            hosts: vec![node(10)],
            readers: vec![],
        }
    }

    fn entry() -> SignedEntry {
        SignedEntry::sign(
            &root(),
            StateVersion(4),
            ServiceName::new("status").unwrap(),
            service(),
        )
        .unwrap()
    }

    #[test]
    fn sign_verify_round_trip() {
        let e = entry();
        e.verify(root().node_id()).unwrap();
        assert_eq!(e.format, ENTRY_V1);
        assert_eq!(e.fabric, root().node_id());
        let back: SignedEntry = serde_json::from_slice(&canonical_bytes(&e).unwrap()).unwrap();
        assert_eq!(back, e);
        back.verify(root().node_id()).unwrap();
    }

    #[test]
    fn signed_bytes_are_domain_separated() {
        let e = entry();
        let bytes = e.signed_bytes().unwrap();
        assert!(bytes.starts_with(b"wires/service-entry/v1\0{\"alg\":\"ed25519\",\"fabric\":"));
        let mut other = crate::head::POLICY_HEAD_CONTEXT.to_vec();
        other.extend_from_slice(&bytes[ENTRY_CONTEXT.len()..]);
        assert!(root().node_id().verify(&other, &e.sig).is_err());
    }

    #[test]
    fn tampering_and_other_fabrics_are_refused() {
        let good = entry();
        let tampers: [fn(&mut SignedEntry); 5] = [
            |e| e.version = StateVersion(5),
            |e| e.name = ServiceName::new("other").unwrap(),
            |e| e.service.hosts.push(node(11)),
            |e| e.service.allow.clear(),
            |e| e.service.description.push('!'),
        ];
        for tamper in tampers {
            let mut t = good.clone();
            tamper(&mut t);
            assert!(
                matches!(t.verify(root().node_id()), Err(Error::InvalidSignature)),
                "{t:?}"
            );
        }
        // Another fabric's root signed it: refused under ours.
        let other = NodeIdentity::from_seed([9u8; 32]);
        let foreign =
            SignedEntry::sign(&other, StateVersion(4), good.name.clone(), service()).unwrap();
        foreign.verify(other.node_id()).unwrap();
        assert!(matches!(
            foreign.verify(root().node_id()),
            Err(Error::InvalidSignature)
        ));
        // Relabelled as ours, its signature doesn't verify.
        let mut relabelled = foreign;
        relabelled.fabric = root().node_id();
        assert!(relabelled.verify(root().node_id()).is_err());

        let mut t = good.clone();
        t.format = ENTRY_V1 + 1;
        assert!(matches!(
            t.verify(root().node_id()),
            Err(Error::UnsupportedVersion)
        ));
    }

    #[test]
    fn is_for_compares_what_an_edit_changes() {
        let e = entry();
        let name = ServiceName::new("status").unwrap();
        assert!(e.is_for(root().node_id(), &name, &service()));
        let mut changed = service();
        changed
            .readers
            .push(crate::RoleName::new("auditor").unwrap());
        assert!(!e.is_for(root().node_id(), &name, &changed));
        assert!(!e.is_for(node(9), &name, &service()));
        assert!(!e.is_for(
            root().node_id(),
            &ServiceName::new("other").unwrap(),
            &service()
        ));
    }

    #[test]
    fn unknown_fields_are_refused() {
        let mut v = serde_json::to_value(entry()).unwrap();
        v["extra"] = serde_json::json!(1);
        assert!(serde_json::from_value::<SignedEntry>(v).is_err());
    }

    proptest! {
        #[test]
        fn any_entry_verifies_and_a_changed_version_never_does(
            version in any::<u64>(),
            other in any::<u64>(),
            description in ".{0,40}",
        ) {
            prop_assume!(version != other);
            let mut svc = service();
            svc.description = description;
            let e = SignedEntry::sign(
                &root(), StateVersion(version), ServiceName::new("s").unwrap(), svc,
            ).unwrap();
            prop_assert!(e.verify(root().node_id()).is_ok());
            let mut t = e;
            t.version = StateVersion(other);
            prop_assert!(t.verify(root().node_id()).is_err());
        }
    }
}
