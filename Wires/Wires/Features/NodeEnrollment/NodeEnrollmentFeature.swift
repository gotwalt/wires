import ComposableArchitecture
import Foundation
import WiresKit

/// Three-step stack: scan a pair-request QR → review and approve →
/// confirm. Presented as a sheet from `HomeFeature`.
@Reducer
struct NodeEnrollmentFeature {
    @ObservableState
    enum State: Equatable {
        case scan(ScanStepState)
        case approve(ApprovalFeature.State)
        case done(DoneStepState)

        static func initial(host: HostInfo) -> Self {
            .scan(ScanStepState(host: host))
        }
    }

    struct ScanStepState: Equatable {
        /// Carried forward so the approve step has somewhere to dial.
        let host: HostInfo
        var scan = ScanFeature<PairRequestPreview>.State()
    }

    struct DoneStepState: Equatable {
        let ack: PairAckRecord
        let preview: PairRequestPreview
    }

    @CasePathable
    enum Action {
        case scan(ScanFeature<PairRequestPreview>.Action)
        case approve(ApprovalFeature.Action)
        case continueTapped
        case dismissTapped

        /// Delegate: fires once we're fully done. HomeFeature listens.
        case completed(PairAckRecord)
    }

    var body: some Reducer<State, Action> {
        Reduce { state, action in
            switch action {
            case let .scan(.decodedPayload(preview)):
                guard case let .scan(scanState) = state else { return .none }
                state = .approve(ApprovalFeature.State(
                    preview: preview,
                    host: scanState.host
                ))
                return .none

            case .scan:
                return .none

            case let .approve(.approveCompleted(ack)):
                guard case let .approve(approveState) = state else { return .none }
                state = .done(DoneStepState(ack: ack, preview: approveState.preview))
                return .none

            case .approve:
                return .none

            case .continueTapped:
                guard case let .done(done) = state else { return .none }
                return .send(.completed(done.ack))

            case .dismissTapped, .completed:
                return .none
            }
        }
        .ifCaseLet(\.scan, action: \.scan) {
            Scope(state: \.scan, action: \.self) {
                ScanFeature<PairRequestPreview>(parse: { payload in
                    @Dependency(\.wiresClient) var wires
                    return try await wires.parsePairRequest(payload)
                })
            }
        }
        .ifCaseLet(\.approve, action: \.approve) {
            ApprovalFeature()
        }
    }
}
