import SwiftUI

struct DiagnosticsView: View {
    @EnvironmentObject private var model: AppModel

    var body: some View {
        NavigationView {
            ScrollView {
                Text(model.diagnostics.isEmpty ? "Pull to load the server log." : model.diagnostics)
                    .font(.system(.caption, design: .monospaced))
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .textSelection(.enabled)
                    .padding()
            }
            .refreshable { await model.refreshDiagnostics() }
            .navigationTitle("Log")
            .toolbar {
                Button("Reload") { Task { await model.refreshDiagnostics() } }
            }
        }
        .navigationViewStyle(.stack)
        .task { await model.refreshDiagnostics() }
    }
}
