import ComposableArchitecture
import Testing
@testable import Wires

@Suite("DeleteAccountFeature")
struct DeleteAccountFeatureTests {
    @Test("confirm button stays disabled until 'delete' is typed")
    func confirmRequiresExactMatch() async {
        let store = await TestStore(initialState: DeleteAccountFeature.State()) {
            DeleteAccountFeature()
        }
        #expect(store.state.confirmEnabled == false)
        await store.send(.confirmTextChanged("delet")) {
            $0.confirmText = "delet"
            $0.confirmEnabled = false
        }
        await store.send(.confirmTextChanged("delete")) {
            $0.confirmText = "delete"
            $0.confirmEnabled = true
        }
        await store.send(.confirmTextChanged("Delete")) {
            $0.confirmText = "Delete"
            $0.confirmEnabled = false  // case-sensitive
        }
    }
}
