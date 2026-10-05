//! `labels.json`: the admin's names for nodes, so it types a node id once.
//!
//! Wherever the admin first names a node it may write `label=<node id>`
//! (`wires directory add workbench=3ef7…`, `wires service add … --host
//! workbench=3ef7…`); from then on the bare label names that node (`wires
//! remove workbench`). A bare 64-hex node id is always accepted too.
//!
//! Labels are the admin's alone: never signed, never sent, never in the
//! policy. Nothing on the wire carries one, so they are not identity: the
//! policy names nodes by key.

use std::collections::BTreeMap;

use anyhow::{Context, Result, anyhow, bail};
use library::NodeId;

use super::keystore::{Keystore, create_private_dir, write_private};

/// The labels file in the admin's keystore.
pub(crate) const LABELS_FILE: &str = "labels.json";

/// The longest label.
const MAX_LABEL: usize = 64;

/// The admin's labels: label → node id. See the module docs.
#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(transparent)]
pub(crate) struct Labels(BTreeMap<String, NodeId>);

/// A node as the admin named it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Named {
    /// The node.
    pub(crate) node: NodeId,
    /// Its label, if it has one.
    pub(crate) label: Option<String>,
}

impl std::fmt::Display for Named {
    /// `label (3ef7…)`, or the short id alone.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.label {
            Some(label) => write!(f, "{label} ({}…)", self.node.short()),
            None => write!(f, "{}…", self.node.short()),
        }
    }
}

impl Labels {
    /// Read the labels from `ks`; none when there is no file yet.
    pub(crate) fn load(ks: &Keystore) -> Result<Labels> {
        let path = ks.path(LABELS_FILE);
        match std::fs::read_to_string(&path) {
            Ok(text) => {
                serde_json::from_str(&text).with_context(|| format!("parsing {}", path.display()))
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Labels::default()),
            Err(e) => Err(e).with_context(|| format!("reading {}", path.display())),
        }
    }

    /// Write them to `ks` (mode `0600`).
    pub(crate) fn save(&self, ks: &Keystore) -> Result<()> {
        create_private_dir(&ks.path(""))?;
        let json = serde_json::to_string_pretty(self).context("encoding the labels")?;
        write_private(&ks.path(LABELS_FILE), &format!("{json}\n"))
    }

    /// The node `text` names: `label=<node id>` (binding the label, which
    /// must be free or already name that node), a bare node id, or a bare
    /// label bound before. Call [`save`](Self::save) after a binding.
    ///
    /// ```text
    /// let mut labels = Labels::default();
    /// let n = labels.resolve(&format!("workbench={}", id.hex()))?;
    /// assert_eq!(labels.resolve("workbench")?.node, n.node);
    /// ```
    pub(crate) fn resolve(&mut self, text: &str) -> Result<Named> {
        let text = text.trim();
        if let Some((label, id)) = text.split_once('=') {
            let label = label.trim();
            check_label(label)?;
            let node = NodeId::from_hex(id.trim()).with_context(|| {
                format!("{label}=…: the node id (64 hex characters, as `wires id` prints it)")
            })?;
            match self.0.get(label) {
                Some(held) if *held != node => bail!(
                    "label {label:?} already names {}; pick another label",
                    held.hex()
                ),
                _ => {
                    self.0.insert(label.to_string(), node);
                }
            }
            return Ok(Named {
                node,
                label: Some(label.to_string()),
            });
        }
        if let Some(node) = self.0.get(text) {
            return Ok(Named {
                node: *node,
                label: Some(text.to_string()),
            });
        }
        match NodeId::from_hex(text) {
            Ok(node) => Ok(Named {
                node,
                label: self.label_of(node),
            }),
            Err(_) => Err(anyhow!(
                "{text:?} is neither a label nor a node id: name a node the first time as \
                 <label>=<node id> (its id is what `wires id` prints on it){}",
                match self.0.keys().map(String::as_str).collect::<Vec<_>>() {
                    known if known.is_empty() => String::new(),
                    known => format!("; known labels: {}", known.join(", ")),
                }
            )),
        }
    }

    /// The label of `node`, if it has one.
    pub(crate) fn label_of(&self, node: NodeId) -> Option<String> {
        self.0
            .iter()
            .find(|(_, n)| **n == node)
            .map(|(l, _)| l.clone())
    }
}

/// A label is 1–64 of `[A-Za-z0-9_.-]`, and not a node id.
fn check_label(label: &str) -> Result<()> {
    let ok = !label.is_empty()
        && label.len() <= MAX_LABEL
        && label
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '-'));
    if !ok {
        bail!("{label:?} is not a label (1-64 of letters, digits, `_`, `.` and `-`)");
    }
    if NodeId::from_hex(label).is_ok() {
        bail!("a label must not be a node id");
    }
    Ok(())
}

/// [`Labels::resolve`] for every `text`, against `ks`'s labels, saving any
/// new binding; each node once, in order.
pub(crate) fn resolve_all(ks: &Keystore, texts: &[String]) -> Result<Vec<Named>> {
    let mut labels = Labels::load(ks)?;
    let before = labels.clone();
    let mut out: Vec<Named> = Vec::new();
    for t in texts {
        let named = labels.resolve(t)?;
        if !out.iter().any(|n| n.node == named.node) {
            out.push(named);
        }
    }
    if labels != before {
        labels.save(ks)?;
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use library::NodeIdentity;
    use proptest::prelude::*;

    fn node(b: u8) -> NodeId {
        NodeIdentity::from_seed([b; 32]).node_id()
    }

    #[test]
    fn a_label_is_bound_once_and_named_afterwards() {
        let mut l = Labels::default();
        let n = l.resolve(&format!("workbench={}", node(2).hex())).unwrap();
        assert_eq!(n.node, node(2));
        assert_eq!(l.resolve("workbench").unwrap(), n);
        // The id alone finds its label.
        assert_eq!(
            l.resolve(&node(2).hex()).unwrap().label.as_deref(),
            Some("workbench")
        );
        // Rebinding to the same node is fine; to another, refused.
        l.resolve(&format!("workbench={}", node(2).hex())).unwrap();
        let e = l
            .resolve(&format!("workbench={}", node(3).hex()))
            .unwrap_err();
        assert!(format!("{e:#}").contains("already names"), "{e:#}");
        // An unknown bare label says how to name a node.
        let e = l.resolve("laptop").unwrap_err();
        assert!(format!("{e:#}").contains("<label>=<node id>"), "{e:#}");
        assert!(format!("{e:#}").contains("workbench"), "{e:#}");
    }

    #[test]
    fn bad_labels_and_ids_are_refused() {
        let mut l = Labels::default();
        for bad in [
            format!("={}", node(2).hex()),
            format!("two words={}", node(2).hex()),
            format!("{}={}", node(3).hex(), node(2).hex()),
            format!("a@b={}", node(2).hex()),
            "wb=nothex".to_string(),
        ] {
            assert!(l.resolve(&bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn labels_round_trip_privately() {
        let ks = Keystore::at(crate::testutil::temp_dir());
        assert_eq!(Labels::load(&ks).unwrap(), Labels::default());
        let named = resolve_all(&ks, &[format!("wb={}", node(2).hex()), "wb".into()]).unwrap();
        assert_eq!(named.len(), 1, "each node once");
        assert_eq!(
            Labels::load(&ks).unwrap().label_of(node(2)).as_deref(),
            Some("wb")
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(ks.path(LABELS_FILE))
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o600);
        }
    }

    proptest! {
        /// Any valid label bound to any node names that node afterwards.
        #[test]
        fn a_bound_label_names_its_node(label in "[A-Za-z_.-][A-Za-z0-9_.-]{0,20}", b in any::<u8>()) {
            let mut l = Labels::default();
            l.resolve(&format!("{label}={}", node(b).hex())).unwrap();
            prop_assert_eq!(l.resolve(&label).unwrap().node, node(b));
        }
    }
}
