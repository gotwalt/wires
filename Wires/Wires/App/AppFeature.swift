import ComposableArchitecture
import CryptoKit
import Foundation

@Reducer
struct AppFeature {
    @ObservableState
    enum State: Equatable {
        case launching
        case onboarding(OnboardingFeature.State)
        case main(MainFeature.State)
    }

    enum Action {
        case onAppear
        case fabricLoaded(FabricSummary?)
        case onboarding(OnboardingFeature.Action)
        case main(MainFeature.Action)
    }

    struct FabricSummary: Equatable, Sendable {
        let rootPubkeyHex: String
        let fabricRegisteredAt: Date?
    }

    @Dependency(\.fabricClient) var fabric
    @Dependency(\.keychainClient) var keychain
    @Dependency(\.wiresClient) var wires

    var body: some Reducer<State, Action> {
        Reduce { state, action in
            switch action {
            case .onAppear:
                let keychain = self.keychain
                let wires = self.wires
                let fabric = self.fabric
                return .run { send in
                    await prepareWiresApp(keychain: keychain, wires: wires)

                    let snapshot: FabricSummary?
                    if let h = try? await fabric.loadFabric() {
                        snapshot = await MainActor.run {
                            FabricSummary(
                                rootPubkeyHex: h.rootPubkeyHex,
                                fabricRegisteredAt: h.fabricRegisteredAt
                            )
                        }
                    } else {
                        snapshot = nil
                    }
                    await send(.fabricLoaded(snapshot))
                }
            case let .fabricLoaded(summary):
                if let summary, summary.fabricRegisteredAt != nil {
                    state = .main(MainFeature.State(
                        network: NetworkFeature.State(rootPubkeyHex: summary.rootPubkeyHex),
                        settings: SettingsFeature.State(),
                        selectedTab: .network
                    ))
                } else {
                    state = .onboarding(OnboardingFeature.State())
                }
                return .none
            case let .onboarding(.onboardingCompleted(rootPubkeyHex)):
                state = .main(MainFeature.State(
                    network: NetworkFeature.State(rootPubkeyHex: rootPubkeyHex),
                    settings: SettingsFeature.State(),
                    selectedTab: .network
                ))
                return .none

            case .main(.didReset):
                // Either Home (debug reset) or Settings (delete account)
                // wiped the local + remote state. Drop back to .launching
                // and re-run onAppear so prepareWiresApp regenerates keys
                // against the empty Keychain and routes us back through
                // onboarding.
                state = .launching
                return .send(.onAppear)

            case .onboarding, .main:
                return .none
            }
        }
        .ifCaseLet(\.onboarding, action: \.onboarding) { OnboardingFeature() }
        .ifCaseLet(\.main, action: \.main) { MainFeature() }
    }
}

/// One-time startup plumbing: makes sure the Keychain holds an iroh node
/// secret + a root signing keypair, then calls `WiresClient.bootstrap` so
/// downstream FFI calls (`parseHostTicket`, `registerWithHostedService`,
/// `approvePairRequest`, …) work. Idempotent: subsequent calls reuse the
/// stored keys and the underlying `WiresAppHolder.bootstrap` is itself a
/// no-op once an instance exists.
private let irohSecretAccount = "wires.iroh.secret"

@Sendable
private func prepareWiresApp(
    keychain: KeychainClient,
    wires: WiresClient
) async {
    // 1. iroh node secret (32 bytes, plain ACL).
    let irohSecret: Data
    if let existing = try? keychain.getData(account: irohSecretAccount), !existing.isEmpty {
        irohSecret = existing
    } else {
        var fresh = Data(count: 32)
        fresh.withUnsafeMutableBytes { buf in
            if let base = buf.baseAddress {
                _ = SecRandomCopyBytes(kSecRandomDefault, 32, base)
            }
        }
        try? keychain.setData(
            account: irohSecretAccount,
            value: fresh,
            accessibility: .afterFirstUnlockThisDeviceOnly
        )
        irohSecret = fresh
    }

    // 2. Root signing keypair. Seed under biometric ACL; pubkey plain so we
    // can read it on every launch without prompting.
    let hadPubkey = (try? keychain.getData(account: KeychainBackedRootSigner.Account.pubkey)) != nil
    if !hadPubkey {
        let key = Curve25519.Signing.PrivateKey()
        try? keychain.setData(
            account: KeychainBackedRootSigner.Account.signingKey,
            value: key.rawRepresentation,
            accessibility: .afterFirstUnlockThisDeviceOnlyBiometricCurrentSet
        )
        try? keychain.setData(
            account: KeychainBackedRootSigner.Account.pubkey,
            value: key.publicKey.rawRepresentation,
            accessibility: .afterFirstUnlockThisDeviceOnly
        )
    }

    // 3. Build the signer + bootstrap. tryLoad reads the cached pubkey.
    guard let signer = try? KeychainBackedRootSigner.tryLoad(keychain: keychain) else {
        return
    }
    await wires.bootstrap(irohSecret, signer)
}
