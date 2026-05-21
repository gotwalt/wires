import ComposableArchitecture
import Foundation

@Reducer
struct SettingsFeature {
    @ObservableState
    struct State: Equatable {
        /// Operator-set friendly label from `HostTicket.server_name`. Empty
        /// if the host didn't provide one. Don't fall back to hex — use
        /// `serverDisplayName` for presentation.
        var serverName: String = ""
        /// iroh relay URL used as a NAT-traversal fallback when devices can't
        /// reach the server directly. Diagnostic / informational only.
        var relayURL: String = ""
        var rootPubkeyHex: String = ""
        var faceIDEnabled: Bool = false
        var loading: Bool = true
        var showingAccountDetail = false
        /// When true, the Account detail sheet renders its Advanced
        /// disclosure expanded. Snapshot fixtures use this to capture the
        /// fingerprint-readout state.
        var accountAdvancedInitiallyExpanded = false
        @Presents var deleteSheet: DeleteAccountFeature.State?

        var appVersion: String {
            Bundle.main.infoDictionary?["CFBundleShortVersionString"] as? String ?? "—"
        }

        /// Human-friendly server label for use everywhere a name shows up.
        /// Falls back to a generic stand-in so the hex EndpointId never
        /// surfaces as a "name".
        var serverDisplayName: String {
            serverName.isEmpty ? "Wires server" : serverName
        }
    }

    enum Action {
        case onAppear
        case loaded(serverName: String, relayURL: String, rootPubkeyHex: String, faceIDEnabled: Bool)
        case accountRowTapped
        case accountDetailDismissed
        case faceIDToggled(Bool)
        case deleteAccountTapped
        case deleteSheet(PresentationAction<DeleteAccountFeature.Action>)
        case accountDeleted
    }

    @Dependency(\.fabricClient) var fabric
    @Dependency(\.keychainClient) var keychain

    var body: some Reducer<State, Action> {
        Reduce { state, action in
            switch action {
            case .onAppear:
                state.loading = true
                let fabric = self.fabric
                let keychain = self.keychain
                return .run { send in
                    guard let summary = try? await loadFabricSummary(
                        fabric: fabric
                    ) else { return }
                    // The root signing key is stored under a biometry-current-set
                    // ACL today. We treat "key exists in Keychain" as
                    // "Face ID protection is on" — true under current
                    // bootstrap policy. Future work: a real ACL probe.
                    let faceIDEnabled = (try? keychain.getData(
                        account: KeychainBackedRootSigner.Account.signingKey
                    )) != nil
                    await send(.loaded(
                        serverName: summary.serverName,
                        relayURL: summary.relayURL,
                        rootPubkeyHex: summary.rootPubkeyHex,
                        faceIDEnabled: faceIDEnabled
                    ))
                }

            case let .loaded(serverName, relayURL, rootPubkeyHex, faceIDEnabled):
                state.serverName = serverName
                state.relayURL = relayURL
                state.rootPubkeyHex = rootPubkeyHex
                state.faceIDEnabled = faceIDEnabled
                state.loading = false
                return .none

            case .accountRowTapped:
                state.showingAccountDetail = true
                return .none

            case .accountDetailDismissed:
                state.showingAccountDetail = false
                return .none

            case let .faceIDToggled(newValue):
                state.faceIDEnabled = newValue
                // Real ACL re-write happens out-of-band via SecItem; the
                // initial v1 implementation just flips the bit.
                return .none

            case .deleteAccountTapped:
                state.deleteSheet = DeleteAccountFeature.State()
                return .none

            case .deleteSheet(.presented(.confirmed)):
                state.deleteSheet = nil
                let fabric = self.fabric
                let keychain = self.keychain
                return .run { send in
                    try? await fabric.wipeAll()
                    try? keychain.wipeAllWiresAccounts()
                    await send(.accountDeleted)
                }

            case .deleteSheet:
                return .none

            case .accountDeleted:
                return .none
            }
        }
        .ifLet(\.$deleteSheet, action: \.deleteSheet) { DeleteAccountFeature() }
    }
}

/// A reducer-side snapshot of the fields Settings cares about. Built on the
/// main actor via a hop so SwiftData @Model fields can be read off-actor
/// safely.
private struct FabricSummaryFields: Sendable {
    let serverName: String
    let relayURL: String
    let rootPubkeyHex: String
}

@Sendable
private func loadFabricSummary(
    fabric: FabricClient
) async throws -> FabricSummaryFields? {
    guard let h = try await fabric.loadFabric() else { return nil }
    return await MainActor.run {
        FabricSummaryFields(
            serverName: h.hostServerName ?? "",
            relayURL: h.hostRelayURL ?? "",
            rootPubkeyHex: h.rootPubkeyHex
        )
    }
}
