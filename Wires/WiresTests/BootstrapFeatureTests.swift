import ComposableArchitecture
import Foundation
import Testing
import WiresKit
@testable import Wires

@MainActor
struct BootstrapFeatureTests {
    static let rootPubkey = Data((0 ..< 32).map { _ in UInt8(0xab) })
    static let rootPubkeyHex = String(repeating: "ab", count: 32)

    static let sampleHost = HostInfo(
        endpointIdHex: String(repeating: "cd", count: 32),
        addrs: ["127.0.0.1:11204"],
        relay: "https://relay.example/",
        hintExpiresAtMs: 1_700_000_000_000
    )

    static let sampleRegistration = TenantRegistration(
        capsTopicIdHex: String(repeating: "ee", count: 32),
        hostEndpointIdHex: String(repeating: "cd", count: 32),
        serverTimeMs: 1_700_000_001_000
    )

    // MARK: - Scan happy path

    @Test
    func scanHappyPath_decodedHostInfo_movesToConfirm() async {
        let store = TestStore(
            initialState: BootstrapFeature.State()
        ) {
            BootstrapFeature()
        }

        await store.send(.scan(.decodedPayload(Self.sampleHost))) {
            $0.confirmedHost = Self.sampleHost
        }
        #expect(store.state.step == .confirm)
    }

    // MARK: - Paste happy path

    @Test
    func pasteHappyPath_movesToConfirm() async {
        let store = TestStore(
            initialState: BootstrapFeature.State()
        ) {
            BootstrapFeature()
        } withDependencies: {
            $0.wiresClient.parseHostTicket = { _ in Self.sampleHost }
        }

        await store.send(.pasteButtonTapped) {
            $0.pasteSheetPresented = true
        }
        await store.send(.pasteInputChanged("ticket-payload")) {
            $0.pasteInput = "ticket-payload"
        }
        await store.send(.pasteSubmitTapped)
        await store.receive(\.pasteTicketParsed) {
            $0.pasteSheetPresented = false
            $0.pasteInput = ""
            $0.confirmedHost = Self.sampleHost
        }
    }

    // MARK: - Paste parse failure

    @Test
    func pasteParseFailed_keepsSheetOpen_showsError() async {
        let store = TestStore(
            initialState: BootstrapFeature.State()
        ) {
            BootstrapFeature()
        } withDependencies: {
            $0.wiresClient.parseHostTicket = { _ in
                throw WiresError.TicketDecode(message: "bad b64")
            }
        }

        await store.send(.pasteButtonTapped) {
            $0.pasteSheetPresented = true
        }
        await store.send(.pasteInputChanged("garbage")) {
            $0.pasteInput = "garbage"
        }
        await store.send(.pasteSubmitTapped)
        await store.receive(\.pasteTicketParseFailed) {
            $0.pasteError = #"TicketDecode(message: "bad b64")"#
        }
    }

    // MARK: - Register happy path

    @Test
    func registerHappyPath_savesHousehold_transitionsToDone() async {
        let saved = LockIsolated<[Household]>([])
        let store = TestStore(
            initialState: stateOnConfirmStep()
        ) {
            BootstrapFeature()
        } withDependencies: {
            $0.wiresClient.registerWithHostedService = { _ in Self.sampleRegistration }
            $0.keychainClient.getData = { _ in Self.rootPubkey }
            $0.householdClient.saveHousehold = { h in saved.withValue { $0.append(h) } }
        }

        await store.send(.registerButtonTapped) {
            $0.registering = true
        }
        await store.receive(\.registerSucceeded) {
            $0.registering = false
            $0.completed = BootstrapFeature.State.Completed(
                registration: Self.sampleRegistration,
                host: Self.sampleHost,
                rootPubkeyHex: Self.rootPubkeyHex
            )
        }

        #expect(saved.value.count == 1)
        #expect(saved.value.first?.rootPubkeyHex == Self.rootPubkeyHex)
        #expect(store.state.step == .done)
    }

    // MARK: - Register failure then retry

    @Test
    func registerFails_thenRetrySucceeds() async {
        let attemptCount = LockIsolated(0)
        let store = TestStore(
            initialState: stateOnConfirmStep()
        ) {
            BootstrapFeature()
        } withDependencies: {
            $0.wiresClient.registerWithHostedService = { _ in
                let n = attemptCount.withValue { $0 += 1; return $0 }
                if n == 1 {
                    throw WiresError.TenantStream(message: "connection refused")
                }
                return Self.sampleRegistration
            }
            $0.keychainClient.getData = { _ in Self.rootPubkey }
            $0.householdClient.saveHousehold = { _ in }
        }

        await store.send(.registerButtonTapped) { $0.registering = true }
        await store.receive(\.registerFailed) {
            $0.registering = false
            $0.registerError = #"TenantStream(message: "connection refused")"#
        }

        await store.send(.retryRegisterTapped) {
            $0.registering = true
            $0.registerError = nil
        }
        await store.receive(\.registerSucceeded) {
            $0.registering = false
            $0.completed = BootstrapFeature.State.Completed(
                registration: Self.sampleRegistration,
                host: Self.sampleHost,
                rootPubkeyHex: Self.rootPubkeyHex
            )
        }
    }

    // MARK: - Tenant rejected (bad signature) surfaces specific copy

    @Test
    func tenantRejected_surfacesBadSignatureMessage() async {
        let store = TestStore(
            initialState: stateOnConfirmStep()
        ) {
            BootstrapFeature()
        } withDependencies: {
            $0.wiresClient.registerWithHostedService = { _ in
                throw WiresError.TenantRejected(message: "BadSignature")
            }
            $0.keychainClient.getData = { _ in Self.rootPubkey }
            $0.householdClient.saveHousehold = { _ in }
        }

        await store.send(.registerButtonTapped) { $0.registering = true }
        await store.receive(\.registerFailed) {
            $0.registering = false
            $0.registerError = #"TenantRejected(message: "BadSignature")"#
        }
    }

    // MARK: - Continue emits delegate

    @Test
    func continueTapped_emitsBootstrapCompleted() async {
        var state = BootstrapFeature.State()
        state.completed = BootstrapFeature.State.Completed(
            registration: Self.sampleRegistration,
            host: Self.sampleHost,
            rootPubkeyHex: Self.rootPubkeyHex
        )

        let store = TestStore(initialState: state) { BootstrapFeature() }

        await store.send(.continueTapped)
        await store.receive(\.bootstrapCompleted, Self.rootPubkeyHex)
    }

    // MARK: - Helpers

    private func stateOnConfirmStep() -> BootstrapFeature.State {
        var state = BootstrapFeature.State()
        state.confirmedHost = Self.sampleHost
        return state
    }
}
