import ComposableArchitecture
import Foundation
import Testing
import WiresKit
@testable import Wires

@MainActor
struct HomeFeatureTests {
    static let pubkey = String(repeating: "ab", count: 32)

    static let sampleHost = HostInfo(
        endpointIdHex: String(repeating: "cd", count: 32),
        addrs: ["127.0.0.1:11204"],
        relay: nil,
        hintExpiresAtMs: 0,
        serverName: nil
    )

    @Test
    func onAppear_emptyStore_loadsZeroCaps() async {
        let store = TestStore(
            initialState: HomeFeature.State(rootPubkeyHex: Self.pubkey)
        ) {
            HomeFeature()
        } withDependencies: {
            $0.householdClient.listCaps = { [] }
            $0.householdClient.loadHousehold = { nil }
        }

        await store.send(.onAppear) {
            $0.loading = true
        }
        await store.receive(\.loaded) {
            $0.loading = false
            $0.caps = []
            $0.host = nil
        }
    }

    @Test
    func onAppear_populatesCapsFromStore() async {
        let cap = CapRecord(
            capIdHex: String(repeating: "11", count: 16),
            nodePubkeyHex: String(repeating: "22", count: 32),
            nodeAlias: "chat-node: Bob",
            topicNames: ["home.notes"],
            rights: ["read", "write"],
            issuedAt: Date(timeIntervalSince1970: 1_700_000_000)
        )

        let store = TestStore(
            initialState: HomeFeature.State(rootPubkeyHex: Self.pubkey)
        ) {
            HomeFeature()
        } withDependencies: {
            $0.householdClient.listCaps = { [cap] }
            $0.householdClient.loadHousehold = { nil }
        }

        await store.send(.onAppear) {
            $0.loading = true
        }
        await store.receive(\.loaded) {
            $0.loading = false
            $0.caps = [
                HomeFeature.CapSummary(
                    id: cap.capIdHex,
                    nodePubkeyHex: cap.nodePubkeyHex,
                    nodeAlias: cap.nodeAlias,
                    topicNames: cap.topicNames,
                    rights: cap.rights,
                    issuedAt: cap.issuedAt,
                    revokedAt: nil
                )
            ]
            $0.host = nil
        }
    }

    @Test
    func onAppear_listFailure_surfacesError() async {
        struct Boom: Error {}
        let store = TestStore(
            initialState: HomeFeature.State(rootPubkeyHex: Self.pubkey)
        ) {
            HomeFeature()
        } withDependencies: {
            $0.householdClient.listCaps = { throw Boom() }
            $0.householdClient.loadHousehold = { nil }
        }

        await store.send(.onAppear) {
            $0.loading = true
        }
        await store.receive(\.loadFailed) {
            $0.loading = false
            $0.loadError = "Boom()"
        }
    }

    // MARK: - Connect (OAuth sign-in)

    @Test
    func connectTapped_presentsOAuthSignInSheet() async {
        let store = TestStore(
            initialState: HomeFeature.State(rootPubkeyHex: Self.pubkey)
        ) {
            HomeFeature()
        }

        await store.send(.connectTapped) {
            $0.oauthSignIn = .initial()
        }
    }

    @Test
    func oauthSignInDismiss_clearsSheetAndRefreshesCaps() async {
        var initial = HomeFeature.State(rootPubkeyHex: Self.pubkey)
        initial.oauthSignIn = .initial()

        let store = TestStore(initialState: initial) {
            HomeFeature()
        } withDependencies: {
            $0.householdClient.listCaps = { [] }
            $0.householdClient.loadHousehold = { nil }
        }

        await store.send(.oauthSignIn(.presented(.dismissTapped))) {
            $0.oauthSignIn = nil
        }
        await store.receive(\.onAppear) {
            $0.loading = true
            $0.loadError = nil
        }
        await store.receive(\.loaded) {
            $0.loading = false
            $0.caps = []
            $0.host = nil
        }
    }

    // MARK: - Reset household

    private static func resetAlertState() -> AlertState<HomeFeature.Action.Alert> {
        AlertState {
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
    }

    @Test
    func resetHouseholdTapped_presentsConfirmationAlert() async {
        let store = TestStore(
            initialState: HomeFeature.State(rootPubkeyHex: Self.pubkey)
        ) {
            HomeFeature()
        } withDependencies: {
            $0.householdClient.listCaps = { [] }
            $0.householdClient.loadHousehold = { nil }
            $0.householdClient.wipeAll = { }
            $0.keychainClient.wipeAllWiresAccounts = { }
            $0.wiresClient.unregisterTenant = { _ in
                UnregisterResult(ok: true, topicsRemoved: 0)
            }
            $0.wiresClient.reset = { }
        }

        await store.send(.resetHouseholdTapped) {
            $0.alert = Self.resetAlertState()
        }
    }

    @Test
    func cancelAlert_dismissesWithoutAction() async {
        var initial = HomeFeature.State(rootPubkeyHex: Self.pubkey)
        initial.alert = Self.resetAlertState()

        let store = TestStore(initialState: initial) {
            HomeFeature()
        } withDependencies: {
            $0.householdClient.listCaps = { [] }
            $0.householdClient.loadHousehold = { nil }
            $0.householdClient.wipeAll = { }
            $0.keychainClient.wipeAllWiresAccounts = { }
            $0.wiresClient.unregisterTenant = { _ in
                UnregisterResult(ok: true, topicsRemoved: 0)
            }
            $0.wiresClient.reset = { }
        }

        await store.send(.alert(.dismiss)) {
            $0.alert = nil
        }
    }

    @Test
    func confirmReset_runsEffectAndEmitsDidReset() async {
        let wipeAllCalled = LockIsolated(false)
        let wipeKeychainCalled = LockIsolated(false)
        let resetCalled = LockIsolated(false)
        let unregisterCalled = LockIsolated(false)

        var initial = HomeFeature.State(rootPubkeyHex: Self.pubkey)
        initial.host = Self.sampleHost
        initial.alert = Self.resetAlertState()

        let store = TestStore(initialState: initial) {
            HomeFeature()
        } withDependencies: {
            $0.householdClient.listCaps = { [] }
            $0.householdClient.loadHousehold = { nil }
            $0.householdClient.wipeAll = { wipeAllCalled.setValue(true) }
            $0.keychainClient.wipeAllWiresAccounts = { wipeKeychainCalled.setValue(true) }
            $0.wiresClient.unregisterTenant = { _ in
                unregisterCalled.setValue(true)
                return UnregisterResult(ok: true, topicsRemoved: 2)
            }
            $0.wiresClient.reset = { resetCalled.setValue(true) }
        }

        await store.send(.alert(.presented(.confirmReset))) {
            $0.alert = nil
        }
        await store.receive(\.resetCompleted)
        await store.receive(\.didReset)

        #expect(unregisterCalled.value == true)
        #expect(wipeAllCalled.value == true)
        #expect(wipeKeychainCalled.value == true)
        #expect(resetCalled.value == true)
    }
}
