import ComposableArchitecture
import CryptoKit
import Foundation

@Reducer
struct AppFeature {
    @ObservableState
    enum State: Equatable {
        case launching
        case bootstrap(BootstrapFeature.State)
        case main(MainFeature.State)
    }

    enum Action {
        case onAppear
        case householdLoaded(HouseholdSummary?)
        case bootstrap(BootstrapFeature.Action)
        case main(MainFeature.Action)
    }

    struct HouseholdSummary: Equatable, Sendable {
        let rootPubkeyHex: String
        let tenantRegisteredAt: Date?
    }

    @Dependency(\.householdClient) var household
    @Dependency(\.keychainClient) var keychain
    @Dependency(\.wiresClient) var wires

    var body: some Reducer<State, Action> {
        Reduce { state, action in
            switch action {
            case .onAppear:
                let keychain = self.keychain
                let wires = self.wires
                let household = self.household
                return .run { send in
                    await prepareWiresApp(keychain: keychain, wires: wires)

                    let snapshot: HouseholdSummary?
                    if let h = try? await household.loadHousehold() {
                        snapshot = await MainActor.run {
                            HouseholdSummary(
                                rootPubkeyHex: h.rootPubkeyHex,
                                tenantRegisteredAt: h.tenantRegisteredAt
                            )
                        }
                    } else {
                        snapshot = nil
                    }
                    await send(.householdLoaded(snapshot))
                }
            case let .householdLoaded(summary):
                if let summary, summary.tenantRegisteredAt != nil {
                    state = .main(MainFeature.State(
                        home: HomeFeature.State(rootPubkeyHex: summary.rootPubkeyHex),
                        settings: SettingsFeature.State(),
                        selectedTab: .network
                    ))
                } else {
                    state = .bootstrap(BootstrapFeature.State())
                }
                return .none
            case let .bootstrap(.bootstrapCompleted(rootPubkeyHex)):
                state = .main(MainFeature.State(
                    home: HomeFeature.State(rootPubkeyHex: rootPubkeyHex),
                    settings: SettingsFeature.State(),
                    selectedTab: .network
                ))
                return .none

            case .main(.home(.didReset)):
                // Home wiped the local + remote state. Drop back to
                // .launching and re-run onAppear so prepareWiresApp
                // regenerates keys against the empty Keychain and routes
                // us back through bootstrap.
                state = .launching
                return .send(.onAppear)

            case .bootstrap, .main:
                return .none
            }
        }
        .ifCaseLet(\.bootstrap, action: \.bootstrap) { BootstrapFeature() }
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
