import Foundation

/// Process-wide register of which fixture is active. Set once at app
/// launch by `LaunchFixture.install(named:)`. Views consult `isActive`
/// to skip work that would clobber seeded state (e.g. HomeView's
/// onAppear).
///
/// In production builds nothing writes to this; `activeFixture` stays
/// nil and `isActive` is always false. Internal-only.
enum FixtureRuntime {
    static let shared = Storage()

    final class Storage {
        var activeFixture: LaunchFixture?
        var malformedFixtureName: String?
    }

    static var isActive: Bool { shared.activeFixture != nil }
}
