import ComposableArchitecture
import Dependencies
import Foundation
import WiresKit

/// TCA dependency facade over `WiresApp` from `WiresKit`. Reducers stay
/// I/O-free by going through this client; `liveValue` lazily constructs the
/// single underlying `WiresApp` and the `KeychainBackedRootSigner` callback
/// the iOS Keychain uses for biometric-gated root signing.
@DependencyClient
struct WiresClient {
    /// One-shot bootstrap. Subsequent calls are no-ops. Takes the 32-byte
    /// iroh node secret and the `SwiftRootSigner` callback the FFI will use
    /// for every signing operation.
    var bootstrap: @Sendable (_ irohSecret: Data, _ rootSigner: any SwiftRootSigner) async -> Void = { _, _ in }

    var parseHostTicket: @Sendable (_ payload: String) async throws -> HostInfo
    var registerWithHostedService: @Sendable (_ host: HostInfo) async throws -> TenantRegistration
    var registerTopic: @Sendable (_ host: HostInfo, _ topicId: Data) async throws -> Void
    var parsePairRequest: @Sendable (_ payload: String) async throws -> PairRequestPreview
    /// Non-throwing default: empty topic id + zero-byte key. Real impl
    /// returns 32-byte random hex + 32-byte symmetric key.
    var generateTopicIdAndEpoch0: @Sendable () async -> NewTopic = {
        NewTopic(topicIdHex: "", epoch0Key: Data())
    }
    var approvePairRequest: @Sendable (
        _ handle: PendingPairHandle,
        _ grantedScopes: [GrantedScope],
        _ host: HostInfo
    ) async throws -> PairAckRecord
    var discardPairRequest: @Sendable (_ handle: PendingPairHandle) async -> Void = { _ in }
}

enum WiresClientError: Error, Equatable {
    case notBootstrapped
}

/// Actor-isolated holder so the underlying `WiresApp` is created at most
/// once and all clients share it.
private actor WiresAppHolder {
    private var instance: WiresApp?

    func bootstrap(_ irohSecret: Data, _ signer: any SwiftRootSigner) {
        if instance == nil {
            instance = WiresApp.bootstrap(irohSecret: irohSecret, rootSigner: signer)
        }
    }

    func require() throws -> WiresApp {
        guard let instance else { throw WiresClientError.notBootstrapped }
        return instance
    }
}

extension WiresClient: DependencyKey {
    static let liveValue: WiresClient = {
        let holder = WiresAppHolder()
        return WiresClient(
            bootstrap: { secret, signer in
                await holder.bootstrap(secret, signer)
            },
            parseHostTicket: { payload in
                try await holder.require().parseHostTicket(payload: payload)
            },
            registerWithHostedService: { host in
                try await holder.require().registerWithHostedService(host: host)
            },
            registerTopic: { host, topicId in
                try await holder.require().registerTopic(host: host, topicId: topicId)
            },
            parsePairRequest: { payload in
                try await holder.require().parsePairRequest(payload: payload)
            },
            generateTopicIdAndEpoch0: {
                // require() throws if not bootstrapped; we treat that as a
                // programming error here since callers always bootstrap first.
                guard let app = try? await holder.require() else {
                    preconditionFailure("WiresClient.generateTopicIdAndEpoch0 before bootstrap")
                }
                return app.generateTopicIdAndEpoch0()
            },
            approvePairRequest: { handle, scopes, host in
                try await holder.require().approvePairRequest(
                    handle: handle,
                    grantedScopes: scopes,
                    host: host
                )
            },
            discardPairRequest: { handle in
                guard let app = try? await holder.require() else { return }
                app.discardPairRequest(handle: handle)
            }
        )
    }()
}

extension DependencyValues {
    var wiresClient: WiresClient {
        get { self[WiresClient.self] }
        set { self[WiresClient.self] = newValue }
    }
}

// MARK: - Keychain-backed root signer

/// `SwiftRootSigner` implementation that reads the cached root pubkey from
/// Keychain and delegates signing to `KeychainClient.signWithBiometric`.
/// Created at app startup once the household exists.
final class KeychainBackedRootSigner: SwiftRootSigner, @unchecked Sendable {
    enum Account {
        static let signingKey = "wires.root.signingkey"
        static let pubkey = "wires.root.pubkey"
    }

    private let keychain: KeychainClient
    private let cachedPubkey: Data

    init(keychain: KeychainClient, pubkey: Data) {
        self.keychain = keychain
        self.cachedPubkey = pubkey
    }

    /// Try to construct one by reading the cached pubkey from Keychain.
    /// Returns nil if no household has been bootstrapped yet.
    static func tryLoad(keychain: KeychainClient) throws -> KeychainBackedRootSigner? {
        guard let pk = try keychain.getData(Account.pubkey) else { return nil }
        return KeychainBackedRootSigner(keychain: keychain, pubkey: pk)
    }

    func pubkey() -> Data {
        cachedPubkey
    }

    func sign(message: Data) throws -> Data {
        // The Swift Concurrency boundary: SwiftRootSigner.sign is synchronous,
        // but signWithBiometric is async. Wrap with a runblocking pattern via
        // DispatchSemaphore — biometric prompts present synchronously to the
        // user; FFI thread is fine to block since UniFFI dispatches it off
        // the main actor.
        let semaphore = DispatchSemaphore(value: 0)
        var result: Result<Data, Error>!
        Task.detached(priority: .userInitiated) { [keychain] in
            do {
                let sig = try await keychain.signWithBiometric(Account.signingKey, message)
                result = .success(sig)
            } catch {
                result = .failure(error)
            }
            semaphore.signal()
        }
        semaphore.wait()
        return try result.get()
    }
}
