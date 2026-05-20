import ComposableArchitecture
import SwiftUI

struct MainView: View {
    @Bindable var store: StoreOf<MainFeature>

    var body: some View {
        TabView(selection: $store.selectedTab.sending(\.tabSelected)) {
            NetworkView(store: store.scope(state: \.network, action: \.network))
                .tabItem {
                    Label("Network", systemImage: "circle.hexagongrid")
                }
                .tag(MainFeature.State.Tab.network)

            SettingsView(store: store.scope(state: \.settings, action: \.settings))
                .tabItem {
                    Label("Settings", systemImage: "gearshape")
                }
                .tag(MainFeature.State.Tab.settings)
        }
        .tint(AppColors.indigoPrimary)
    }
}
