import Testing
@testable import Wires

@Suite("ServiceCategory")
struct ServiceCategoryTests {
    @Test("each case maps to a unique SF Symbol name")
    func sfSymbolMapping() {
        let symbols = ServiceCategory.allCases.map(\.sfSymbol)
        #expect(Set(symbols).count == symbols.count)
    }

    @Test("unknown fallback is questionmark.app.dashed")
    func unknownGlyph() {
        #expect(ServiceCategory.unknown.sfSymbol == "questionmark.app.dashed")
    }
}
