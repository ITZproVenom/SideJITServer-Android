import SwiftUI

@main
struct SideJITControlApp: App {
    @StateObject private var model = AppModel()

    var body: some Scene {
        WindowGroup {
            RootView().environmentObject(model)
        }
    }
}

struct RootView: View {
    @EnvironmentObject private var model: AppModel

    var body: some View {
        TabView {
            StatusView()
                .tabItem { Label("Server", systemImage: "antenna.radiowaves.left.and.right") }
            JitView()
                .tabItem { Label("JIT", systemImage: "bolt.fill") }
            DiagnosticsView()
                .tabItem { Label("Log", systemImage: "text.alignleft") }
        }
        .onAppear { model.startPolling() }
        .onDisappear { model.stopPolling() }
    }
}
