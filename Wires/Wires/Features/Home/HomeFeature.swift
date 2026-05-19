import ComposableArchitecture
import Foundation
import WiresKit

@Reducer
struct HomeFeature {
    @ObservableState
    struct State: Equatable {
        var rootPubkeyHex: String
        var caps: [CapSummary] = []
        var host: HostInfo?
        var loading = false
        var loadError: String?
        @Presents var oauthSignIn: OAuthSignInFeature.State?
        @Presents var alert: AlertState<Action.Alert>?
    }

    /// Equatable value snapshot of `CapRecord`. We don't pass SwiftData
    /// `@Model` instances across actor boundaries — the snapshot lets the
    /// reducer stay Sendable-friendly.
    struct CapSummary: Equatable, Identifiable, Sendable {
        let id: String  // capIdHex
        let nodePubkeyHex: String
        let nodeAlias: String?
        let topicNames: [String]
        let rights: [String]
        let issuedAt: Date
        let revokedAt: Date?
    }

    struct LoadedSnapshot: Equatable, Sendable {
        let caps: [CapSummary]
        let host: HostInfo?
    }

    @CasePathable
    enum Action {
        case onAppear
        case loaded(LoadedSnapshot)
        case loadFailed(String)
        case connectTapped
        case oauthSignIn(PresentationAction<OAuthSignInFeature.Action>)
        case resetHouseholdTapped
        case alert(PresentationAction<Alert>)
        case resetCompleted
        case resetFailed(String)
        case didReset

        @CasePathable
        enum Alert: Equatable {
            case confirmReset
        }
    }

    @Dependency(\.householdClient) var household
    @Dependency(\.keychainClient) var keychain
    @Dependency(\.wiresClient) var wires

    var body: some Reducer<State, Action> {
        Reduce { state, action in
            switch action {
            case .onAppear:
                state.loading = true
                state.loadError = nil
                let household = self.household
                return .run { send in
                    do {
                        let records = try await household.listCaps()
                        let hh = try await household.loadHousehold()
                        let snapshot = await MainActor.run {
                            LoadedSnapshot(
                                caps: records.map { rec in
                                    CapSummary(
                                        id: rec.capIdHex,
                                        nodePubkeyHex: rec.nodePubkeyHex,
                                        nodeAlias: rec.nodeAlias,
                                        topicNames: rec.topicNames,
                                        rights: rec.rights,
                                        issuedAt: rec.issuedAt,
                                        revokedAt: rec.revokedAt
                                    )
                                },
                                host: hh.flatMap(hostInfo(from:))
                            )
                        }
                        await send(.loaded(snapshot))
                    } catch {
                        await send(.loadFailed(String(describing: error)))
                    }
                }

            case let .loaded(snapshot):
                state.loading = false
                state.caps = snapshot.caps
                state.host = snapshot.host
                return .none

            case let .loadFailed(message):
                state.loading = false
                state.loadError = message
                return .none

            case .connectTapped:
                state.oauthSignIn = .initial()
                return .none

            // Dismissed (success or cancel): clear the sheet and refresh caps
            // so a freshly-installed cap shows up in the list.
            case .oauthSignIn(.presented(.dismissTapped)),
                 .oauthSignIn(.dismiss):
                state.oauthSignIn = nil
                return .send(.onAppear)

            case .oauthSignIn:
                return .none

            case .resetHouseholdTapped:
                state.alert = AlertState {
                    TextState("Reset household?")
                } actions: {
                    ButtonState(role: .destructive, action: .confirmReset) {
                        TextState("Reset")
                    }
                    ButtonState(role: .cancel) {
                        TextState("Cancel")
                    }
                } message: {
                    TextState("Tells the host to drop this tenant, then wipes every local key and database row. The next launch behaves like a fresh install.")
                }
                return .none

            case .alert(.presented(.confirmReset)):
                state.alert = nil
                let host = state.host
                let household = self.household
                let keychain = self.keychain
                let wires = self.wires
                return .run { send in
                    // 1. Tell the host to unregister. Soft-fail: a host that's offline
                    //    or already-forgotten shouldn't block a local reset.
                    if let host {
                        do {
                            _ = try await wires.unregisterTenant(host)
                        } catch {
                            // Logged, not raised.
                            print("[reset] host unregister failed: \(error)")
                        }
                    }
                    // 2. Wipe SwiftData.
                    do { try await household.wipeAll() }
                    catch {
                        await send(.resetFailed("wipe SwiftData: \(error)"))
                        return
                    }
                    // 3. Wipe Keychain.
                    do { try keychain.wipeAllWiresAccounts() }
                    catch {
                        await send(.resetFailed("wipe Keychain: \(error)"))
                        return
                    }
                    // 4. Drop the cached WiresApp so the next bootstrap regenerates.
                    await wires.reset()
                    await send(.resetCompleted)
                }

            case .alert:
                return .none

            case .resetCompleted:
                return .send(.didReset)

            case let .resetFailed(message):
                state.loadError = "Reset failed: \(message)"
                return .none

            case .didReset:
                // AppFeature observes this delegate action and transitions to .launching.
                return .none
            }
        }
        .ifLet(\.$oauthSignIn, action: \.oauthSignIn) {
            OAuthSignInFeature()
        }
        .ifLet(\.$alert, action: \.alert)
    }
}

/// MainActor-only because it reads SwiftData @Model properties.
@MainActor
private func hostInfo(from household: Household) -> HostInfo? {
    guard let endpointIdHex = household.hostEndpointIdHex else { return nil }
    return HostInfo(
        endpointIdHex: endpointIdHex,
        addrs: household.hostDirectAddrs,
        relay: household.hostRelayURL,
        hintExpiresAtMs: household.hostHintExpiresAtMs ?? 0
    )
}
