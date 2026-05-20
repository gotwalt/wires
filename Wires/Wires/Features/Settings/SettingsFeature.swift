import ComposableArchitecture
import Foundation

@Reducer
struct SettingsFeature {
    @ObservableState
    struct State: Equatable {
        var serverName: String = ""
        var serverURL: String = ""
        var rootPubkeyHex: String = ""
        var faceIDEnabled: Bool = false
        var loading: Bool = true
        var showingAccountDetail = false
        @Presents var deleteSheet: DeleteAccountFeature.State?

        var appVersion: String {
            Bundle.main.infoDictionary?["CFBundleShortVersionString"] as? String ?? "—"
        }
    }

    enum Action {
        case onAppear
        case loaded(serverName: String, serverURL: String, rootPubkeyHex: String, faceIDEnabled: Bool)
        case accountRowTapped
        case accountDetailDismissed
        case faceIDToggled(Bool)
        case deleteAccountTapped
        case deleteSheet(PresentationAction<DeleteAccountFeature.Action>)
        case accountDeleted
    }

    @Dependency(\.householdClient) var household
    @Dependency(\.keychainClient) var keychain

    var body: some Reducer<State, Action> {
        Reduce { state, action in
            switch action {
            case .onAppear:
                state.loading = true
                let household = self.household
                let keychain = self.keychain
                return .run { send in
                    guard let summary = try? await loadHouseholdSummary(
                        household: household
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
                        serverURL: summary.serverURL,
                        rootPubkeyHex: summary.rootPubkeyHex,
                        faceIDEnabled: faceIDEnabled
                    ))
                }

            case let .loaded(serverName, serverURL, rootPubkeyHex, faceIDEnabled):
                state.serverName = serverName
                state.serverURL = serverURL
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
                let household = self.household
                let keychain = self.keychain
                return .run { send in
                    try? await household.wipeAll()
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
private struct HouseholdSummaryFields: Sendable {
    let serverName: String
    let serverURL: String
    let rootPubkeyHex: String
}

@Sendable
private func loadHouseholdSummary(
    household: HouseholdClient
) async throws -> HouseholdSummaryFields? {
    guard let h = try await household.loadHousehold() else { return nil }
    return await MainActor.run {
        // hostEndpointIdHex stands in for serverName until Phase 4 lands
        // the HostTicket.server_name FFI surface.
        HouseholdSummaryFields(
            serverName: h.hostEndpointIdHex ?? "",
            serverURL: h.hostRelayURL ?? "",
            rootPubkeyHex: h.rootPubkeyHex
        )
    }
}
