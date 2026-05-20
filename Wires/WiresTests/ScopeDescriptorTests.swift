import Testing
@testable import Wires

@Suite("ScopeDescriptor")
struct ScopeDescriptorTests {
    @Test("allGranted reflects detail rows in lockstep")
    func allGranted() {
        let s1 = ScopeDescriptor(
            id: "family",
            label: "family",
            summary: "Read messages · Send messages",
            detail: [
                .init(label: "Read", granted: true, kind: .read),
                .init(label: "Send", granted: true, kind: .write),
            ]
        )
        #expect(s1.allGranted == true)

        let s2 = ScopeDescriptor(
            id: "family",
            label: "family",
            summary: "Read messages · Send messages",
            detail: [
                .init(label: "Read", granted: true, kind: .read),
                .init(label: "Send", granted: false, kind: .write),
            ]
        )
        #expect(s2.allGranted == false)
    }

    @Test("settingAllGranted toggles every detail row")
    func settingAllGranted() {
        var s = ScopeDescriptor(
            id: "family",
            label: "family",
            summary: "Read messages · Send messages",
            detail: [
                .init(label: "Read", granted: true, kind: .read),
                .init(label: "Send", granted: true, kind: .write),
            ]
        )
        s.setAllGranted(false)
        #expect(s.detail.allSatisfy { !$0.granted })

        s.setAllGranted(true)
        #expect(s.detail.allSatisfy { $0.granted })
    }
}
