import ComposableArchitecture
import Foundation
import LocalAuthentication
import WiresKit

@Reducer
struct OnboardingFeature {
    @ObservableState
    struct State: Equatable {
        var step: Step = .welcome
        var scan = ScanFeature<HostInfo>.State()

        var pasteSheetPresented = false
        var pasteInput = ""
        var pasteError: String?

        var confirmedHost: HostInfo?
        var registering = false
        var registerError: String?

        var faceIDError: String?
        var faceIDEnabling = false

        var completed: Completed?

        struct Completed: Equatable {
            let registration: FabricRegistration
            let host: HostInfo
            let rootPubkeyHex: String
        }

        enum Step: Equatable {
            case welcome, scan, confirm, faceID, done
        }
    }

    @CasePathable
    enum Action {
        case getStartedTapped
        case scan(ScanFeature<HostInfo>.Action)
        case pasteButtonTapped
        case pasteSheetDismissed
        case pasteInputChanged(String)
        case pasteSubmitTapped
        case pasteTicketParsed(HostInfo)
        case pasteTicketParseFailed(String)

        case confirmRegisterTapped
        case confirmBackTapped
        case registerSucceeded(State.Completed)
        case registerFailed(String)

        case faceIDSetupTapped
        case faceIDSkipTapped
        case faceIDResolved(Bool)
        case faceIDFailed(String)

        case continueTapped

        /// Delegate fired when the user finishes the ceremony. AppFeature listens.
        case onboardingCompleted(rootPubkeyHex: String)
    }

    @Dependency(\.wiresClient) var wires
    @Dependency(\.fabricClient) var fabric
    @Dependency(\.keychainClient) var keychain

    private static let rootPubkeyAccount = KeychainBackedRootSigner.Account.pubkey

    var body: some Reducer<State, Action> {
        Scope(state: \.scan, action: \.scan) {
            ScanFeature<HostInfo>(parse: { payload in
                @Dependency(\.wiresClient) var wires
                return try await wires.parseHostTicket(payload)
            })
        }

        Reduce { state, action in
            switch action {
            case .getStartedTapped:
                state.step = .scan
                return .none

            case let .scan(.decodedPayload(host)):
                state.confirmedHost = host
                state.step = .confirm
                return .none

            case .scan:
                return .none

            case .pasteButtonTapped:
                state.pasteInput = ""
                state.pasteError = nil
                state.pasteSheetPresented = true
                return .none

            case .pasteSheetDismissed:
                state.pasteSheetPresented = false
                return .none

            case let .pasteInputChanged(text):
                state.pasteInput = text
                state.pasteError = nil
                return .none

            case .pasteSubmitTapped:
                let payload = state.pasteInput
                let wires = self.wires
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
                state.step = .confirm
                return .none

            case let .pasteTicketParseFailed(message):
                state.pasteError = message
                return .none

            case .confirmRegisterTapped:
                guard let host = state.confirmedHost else { return .none }
                state.registering = true
                state.registerError = nil
                let wires = self.wires
                let fabric = self.fabric
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
                        let h = Fabric(
                            rootPubkeyHex: pubkeyHex,
                            hostEndpointIdHex: registration.hostEndpointIdHex,
                            hostServerName: host.serverName,
                            hostDirectAddrs: host.addrs,
                            hostRelayURL: host.relay,
                            hostHintExpiresAtMs: host.hintExpiresAtMs,
                            capsTopicIdHex: registration.capsTopicIdHex,
                            fabricRegisteredAt: .now
                        )
                        try await fabric.saveFabric(h)
                        await send(.registerSucceeded(.init(
                            registration: registration,
                            host: host,
                            rootPubkeyHex: pubkeyHex
                        )))
                    } catch {
                        await send(.registerFailed(String(describing: error)))
                    }
                }

            case .confirmBackTapped:
                state.confirmedHost = nil
                state.registering = false
                state.registerError = nil
                state.step = .scan
                return .none

            case let .registerSucceeded(completed):
                state.registering = false
                state.registerError = nil
                state.completed = completed
                state.step = .faceID
                return .none

            case let .registerFailed(message):
                state.registering = false
                state.registerError = message
                return .none

            case .faceIDSetupTapped:
                state.faceIDEnabling = true
                state.faceIDError = nil
                return .run { send in
                    let context = LAContext()
                    var error: NSError?
                    if context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &error) {
                        do {
                            let ok = try await context.evaluatePolicy(
                                .deviceOwnerAuthenticationWithBiometrics,
                                localizedReason: "Protect your Wires account"
                            )
                            await send(.faceIDResolved(ok))
                        } catch {
                            await send(.faceIDFailed(String(describing: error)))
                        }
                    } else {
                        await send(.faceIDFailed(error?.localizedDescription ?? "Face ID unavailable"))
                    }
                }

            case .faceIDSkipTapped:
                state.step = .done
                return .none

            case let .faceIDResolved(ok):
                state.faceIDEnabling = false
                if ok { state.step = .done }
                else { state.faceIDError = "Face ID was not approved." }
                return .none

            case let .faceIDFailed(message):
                state.faceIDEnabling = false
                state.faceIDError = message
                return .none

            case .continueTapped:
                guard let c = state.completed else { return .none }
                return .send(.onboardingCompleted(rootPubkeyHex: c.rootPubkeyHex))

            case .onboardingCompleted:
                return .none
            }
        }
    }
}
