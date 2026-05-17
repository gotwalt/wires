import ComposableArchitecture
import CryptoKit
import Dependencies
import Foundation
import LocalAuthentication
import Security

/// Accessibility class for a Keychain entry. The biometric variant is gated
/// by `.biometryCurrentSet` — Face ID / Touch ID is evaluated on every read.
enum KeychainAccessibility: Equatable {
    case afterFirstUnlockThisDeviceOnly
    case afterFirstUnlockThisDeviceOnlyBiometricCurrentSet
}

enum KeychainError: Error, Equatable {
    case notFound
    case biometricCancelled
    case biometricFailed
    case unexpectedStatus(OSStatus)
    case malformedKey
}

/// Thin, closure-based Keychain facade. Service is `"wires"` for all entries
/// so the operator can wipe everything by clearing that service.
@DependencyClient
struct KeychainClient {
    var getData: @Sendable (_ account: String) throws -> Data?
    var setData: @Sendable (_ account: String, _ value: Data, _ accessibility: KeychainAccessibility) throws -> Void
    var deleteData: @Sendable (_ account: String) throws -> Void

    /// Reads the Ed25519 seed at `account` under a `LAContext`, reconstructs
    /// a `Curve25519.Signing.PrivateKey`, signs `message`, and returns the
    /// 64-byte signature. Triggers the system biometric prompt; subsequent
    /// signs within the LocalAuthentication reuse window are silent.
    var signWithBiometric: @Sendable (_ account: String, _ message: Data) async throws -> Data
}

extension KeychainClient: DependencyKey {
    static let liveValue: KeychainClient = .live()

    static func live(service: String = "wires") -> KeychainClient {
        KeychainClient(
            getData: { account in
                try Self.copyData(service: service, account: account)
            },
            setData: { account, value, access in
                try Self.add(service: service, account: account, value: value, access: access)
            },
            deleteData: { account in
                try Self.delete(service: service, account: account)
            },
            signWithBiometric: { account, message in
                try await Self.signWithBiometric(service: service, account: account, message: message)
            }
        )
    }

    // MARK: - Implementation

    private static func copyData(service: String, account: String) throws -> Data? {
        var query: [CFString: Any] = [
            kSecClass: kSecClassGenericPassword,
            kSecAttrService: service,
            kSecAttrAccount: account,
            kSecMatchLimit: kSecMatchLimitOne,
            kSecReturnData: true,
        ]
        query[kSecUseDataProtectionKeychain] = true

        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        switch status {
        case errSecSuccess:
            return item as? Data
        case errSecItemNotFound:
            return nil
        default:
            throw KeychainError.unexpectedStatus(status)
        }
    }

    private static func add(
        service: String,
        account: String,
        value: Data,
        access: KeychainAccessibility
    ) throws {
        try? delete(service: service, account: account)

        var attrs: [CFString: Any] = [
            kSecClass: kSecClassGenericPassword,
            kSecAttrService: service,
            kSecAttrAccount: account,
            kSecValueData: value,
            kSecAttrSynchronizable: false,
            kSecUseDataProtectionKeychain: true,
        ]

        switch access {
        case .afterFirstUnlockThisDeviceOnly:
            attrs[kSecAttrAccessible] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        case .afterFirstUnlockThisDeviceOnlyBiometricCurrentSet:
            var aclError: Unmanaged<CFError>?
            guard let acl = SecAccessControlCreateWithFlags(
                nil,
                kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
                .biometryCurrentSet,
                &aclError
            ) else {
                throw KeychainError.unexpectedStatus(-1)
            }
            attrs[kSecAttrAccessControl] = acl
        }

        let status = SecItemAdd(attrs as CFDictionary, nil)
        guard status == errSecSuccess else {
            throw KeychainError.unexpectedStatus(status)
        }
    }

    private static func delete(service: String, account: String) throws {
        let query: [CFString: Any] = [
            kSecClass: kSecClassGenericPassword,
            kSecAttrService: service,
            kSecAttrAccount: account,
            kSecUseDataProtectionKeychain: true,
        ]
        let status = SecItemDelete(query as CFDictionary)
        if status != errSecSuccess && status != errSecItemNotFound {
            throw KeychainError.unexpectedStatus(status)
        }
    }

    private static func signWithBiometric(
        service: String,
        account: String,
        message: Data
    ) async throws -> Data {
        let context = LAContext()
        context.localizedReason = "Approve with your root key"
        // Reuse a recent successful biometric assertion within ~10s. Lets a
        // pair-approve flow sign cap + envelope after a single prompt.
        context.touchIDAuthenticationAllowableReuseDuration = 10

        var query: [CFString: Any] = [
            kSecClass: kSecClassGenericPassword,
            kSecAttrService: service,
            kSecAttrAccount: account,
            kSecMatchLimit: kSecMatchLimitOne,
            kSecReturnData: true,
            kSecUseAuthenticationContext: context,
            kSecUseDataProtectionKeychain: true,
        ]

        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        switch status {
        case errSecSuccess:
            guard let seed = item as? Data else {
                throw KeychainError.malformedKey
            }
            defer { seed.withUnsafeBytes { _ = $0 } } // keep alive until sign returns
            let key: Curve25519.Signing.PrivateKey
            do {
                key = try Curve25519.Signing.PrivateKey(rawRepresentation: seed)
            } catch {
                throw KeychainError.malformedKey
            }
            let signature = try key.signature(for: message)
            return signature
        case errSecUserCanceled, errSecAuthFailed:
            throw KeychainError.biometricCancelled
        case errSecItemNotFound:
            throw KeychainError.notFound
        default:
            throw KeychainError.unexpectedStatus(status)
        }
    }
}

extension DependencyValues {
    var keychainClient: KeychainClient {
        get { self[KeychainClient.self] }
        set { self[KeychainClient.self] = newValue }
    }
}
