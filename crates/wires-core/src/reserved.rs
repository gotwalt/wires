use snafu::ensure;

use crate::error::{ReservedTypeWrongModeSnafu, Result};
use crate::wire::MessageKind;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequiredMode {
    Standard,
    SealedTo,
    Public,
}

/// Returns the required mode for a reserved type, or `None` if `type_` is not reserved.
///
/// Reserved types and their modes (from spec §4):
/// - `__cap.grant`           → SealedTo (sealed to the cap recipient)
/// - `__cap.revoke`          → Public   (must be globally readable for enforcement)
/// - `__cap.root_rotation`   → Public   (must be globally readable for adoption)
/// - `__topic.epoch_advance` → SealedTo (one per current member at each rotation)
/// - `__topic.history_grant` → SealedTo (sealed to the new member)
pub fn required_mode_for(type_: &str) -> Option<RequiredMode> {
    match type_ {
        "__cap.grant"           => Some(RequiredMode::SealedTo),
        "__cap.revoke"          => Some(RequiredMode::Public),
        "__cap.root_rotation"   => Some(RequiredMode::Public),
        "__topic.epoch_advance" => Some(RequiredMode::SealedTo),
        "__topic.history_grant" => Some(RequiredMode::SealedTo),
        _ => None,
    }
}

pub fn is_reserved(type_: &str) -> bool {
    required_mode_for(type_).is_some()
}

/// For a reserved `type_`, ensure `kind` is the required mode. For non-reserved
/// types, any mode is allowed.
pub fn check_kind_matches(type_: &str, kind: &MessageKind) -> Result<()> {
    let required = match required_mode_for(type_) {
        None => return Ok(()),
        Some(r) => r,
    };
    let actual = match kind {
        MessageKind::Standard => RequiredMode::Standard,
        MessageKind::SealedTo(_) => RequiredMode::SealedTo,
        MessageKind::Public => RequiredMode::Public,
    };
    ensure!(actual == required, ReservedTypeWrongModeSnafu { reserved_type: type_.to_string() });
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn grant_requires_sealed() {
        check_kind_matches("__cap.grant", &MessageKind::SealedTo([0u8; 32])).unwrap();
        assert!(check_kind_matches("__cap.grant", &MessageKind::Public).is_err());
        assert!(check_kind_matches("__cap.grant", &MessageKind::Standard).is_err());
    }

    #[test]
    fn revoke_requires_public() {
        check_kind_matches("__cap.revoke", &MessageKind::Public).unwrap();
        assert!(check_kind_matches("__cap.revoke", &MessageKind::Standard).is_err());
        assert!(check_kind_matches("__cap.revoke", &MessageKind::SealedTo([0u8; 32])).is_err());
    }

    #[test]
    fn root_rotation_requires_public() {
        check_kind_matches("__cap.root_rotation", &MessageKind::Public).unwrap();
        assert!(check_kind_matches("__cap.root_rotation", &MessageKind::SealedTo([0u8; 32])).is_err());
    }

    #[test]
    fn epoch_advance_requires_sealed() {
        check_kind_matches("__topic.epoch_advance", &MessageKind::SealedTo([0u8; 32])).unwrap();
        assert!(check_kind_matches("__topic.epoch_advance", &MessageKind::Standard).is_err());
    }

    #[test]
    fn history_grant_requires_sealed() {
        check_kind_matches("__topic.history_grant", &MessageKind::SealedTo([0u8; 32])).unwrap();
        assert!(check_kind_matches("__topic.history_grant", &MessageKind::Public).is_err());
    }

    #[test]
    fn user_type_unrestricted() {
        check_kind_matches("home.fridge.temp", &MessageKind::Standard).unwrap();
        check_kind_matches("home.fridge.temp", &MessageKind::Public).unwrap();
        check_kind_matches("home.fridge.temp", &MessageKind::SealedTo([0u8; 32])).unwrap();
    }

    #[test]
    fn is_reserved_check() {
        assert!(is_reserved("__cap.grant"));
        assert!(is_reserved("__topic.epoch_advance"));
        assert!(!is_reserved("home.fridge.temp"));
        assert!(!is_reserved("__cap.unknown"));
    }
}
