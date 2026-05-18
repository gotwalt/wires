import ComposableArchitecture
import Foundation
import WiresKit

@Reducer
struct BootstrapFeature {
    @ObservableState
    struct State: Equatable {
        var scan = ScanFeature<HostInfo>.State()
        var pasteSheetPresented = false
        var pasteInput = ""
        var pasteError: String?

        var confirmedHost: HostInfo?
        var registering = false
        var registerError: String?

        var completed: Completed?

        struct Completed: Equatable {
            let registration: TenantRegistration
            let host: HostInfo
            let rootPubkeyHex: String
        }

        enum Step: Equatable { case scan, confirm, done }

        var step: Step {
            if completed != nil { return .done }
            if confirmedHost != nil { return .confirm }
            return .scan
        }
    }

    @CasePathable
    enum Action {
        case scan(ScanFeature<HostInfo>.Action)

        case pasteButtonTapped
        case pasteSheetDismissed
        case pasteInputChanged(String)
        case pasteSubmitTapped
        case pasteTicketParsed(HostInfo)
        case pasteTicketParseFailed(String)

        case registerButtonTapped
        case backFromConfirmTapped
        case registerSucceeded(State.Completed)
        case registerFailed(String)
        case retryRegisterTapped
        case dismissRegisterErrorTapped

        case continueTapped

        /// Delegate fired when the user accepts the completed registration.
        /// AppFeature listens and transitions to .home.
        case bootstrapCompleted(rootPubkeyHex: String)
    }

    @Dependency(\.wiresClient) var wires
    @Dependency(\.householdClient) var household
    @Dependency(\.keychainClient) var keychain

    private static let rootPubkeyAccount = "wires.root.pubkey"

    var body: some Reducer<State, Action> {
        Scope(state: \.scan, action: \.scan) {
            ScanFeature<HostInfo>(parse: { payload in
                @Dependency(\.wiresClient) var wires
                return try await wires.parseHostTicket(payload)
            })
        }

        Reduce { state, action in
            switch action {
            // MARK: - Scan child events

            case let .scan(.decodedPayload(host)):
                state.confirmedHost = host
                state.registerError = nil
                return .none

            case .scan:
                return .none

            // MARK: - Paste sheet

            case .pasteButtonTapped:
                state.pasteInput = ""
                state.pasteError = nil
                state.pasteSheetPresented = true
                return .none

            case .pasteSheetDismissed:
                state.pasteSheetPresented = false
                return .none

            case let .pasteInputChanged(value):
                state.pasteInput = value
                state.pasteError = nil
                return .none

            case .pasteSubmitTapped:
                let payload = state.pasteInput
                return .run { send in
                    do {
                        let host = try await wires.parseHostTicket(payload)
                        await send(.pasteTicketParsed(host))
                    } catch {
                        await send(.pasteTicketParseFailed(String(describing: error)))
                    }
                }

            case let .pasteTicketParsed(host):
                state.pasteSheetPresented = false
                state.pasteInput = ""
                state.pasteError = nil
                state.confirmedHost = host
                state.registerError = nil
                return .none

            case let .pasteTicketParseFailed(message):
                state.pasteError = message
                return .none

            // MARK: - Confirm step

            case .backFromConfirmTapped:
                state.confirmedHost = nil
                state.registerError = nil
                state.registering = false
                return .none

            case .registerButtonTapped, .retryRegisterTapped:
                guard let host = state.confirmedHost else { return .none }
                state.registering = true
                state.registerError = nil
                let wires = self.wires
                let household = self.household
                let keychain = self.keychain
                let pubkeyAccount = Self.rootPubkeyAccount
                return .run { send in
                    do {
                        let registration = try await wires.registerWithHostedService(host)
                        guard let pubkeyData = try keychain.getData(account: pubkeyAccount) else {
                            await send(.registerFailed("Root pubkey missing from Keychain"))
                            return
                        }
                        let pubkeyHex = pubkeyData.map { String(format: "%02x", $0) }.joined()
                        let h = Household(
                            rootPubkeyHex: pubkeyHex,
                            hostEndpointIdHex: registration.hostEndpointIdHex,
                            hostDirectAddrs: host.addrs,
                            hostRelayURL: host.relay,
                            hostHintExpiresAtMs: host.hintExpiresAtMs,
                            capsTopicIdHex: registration.capsTopicIdHex,
                            tenantRegisteredAt: .now
                        )
                        try await household.saveHousehold(h)
                        await send(.registerSucceeded(.init(
                            registration: registration,
                            host: host,
                            rootPubkeyHex: pubkeyHex
                        )))
                    } catch {
                        await send(.registerFailed(String(describing: error)))
                    }
                }

            case let .registerSucceeded(completed):
                state.registering = false
                state.registerError = nil
                state.completed = completed
                return .none

            case let .registerFailed(message):
                state.registering = false
                state.registerError = message
                return .none

            case .dismissRegisterErrorTapped:
                state.registerError = nil
                return .none

            // MARK: - Done step

            case .continueTapped:
                guard let completed = state.completed else { return .none }
                return .send(.bootstrapCompleted(rootPubkeyHex: completed.rootPubkeyHex))

            case .bootstrapCompleted:
                return .none
            }
        }
    }
}
