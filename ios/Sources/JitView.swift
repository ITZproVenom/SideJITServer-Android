import SwiftUI

struct JitView: View {
    @EnvironmentObject private var model: AppModel
    @State private var bundleId: String = ""

    var body: some View {
        NavigationView {
            Form {
                Section {
                    TextField("com.example.app", text: $bundleId)
                        .textInputAutocapitalization(.never)
                        .autocorrectionDisabled()
                    Button {
                        Task { await model.enableJit(bundleId) }
                    } label: {
                        if model.busy {
                            HStack { ProgressView(); Text("Working").padding(.leading, 6) }
                        } else {
                            Text("Enable JIT")
                        }
                    }
                    .disabled(model.busy || bundleId.trimmingCharacters(in: .whitespaces).isEmpty)
                } header: {
                    Text("Bundle identifier")
                } footer: {
                    Text("The app must already be installed on this device and the server must have a tunnel open.")
                }

                if let result = model.lastResult {
                    Section("Last answer") {
                        Text(result).font(.system(.footnote, design: .monospaced))
                    }
                }

                if !model.recents.isEmpty {
                    Section("Recent") {
                        ForEach(model.recents, id: \.self) { recent in
                            Button(recent) {
                                bundleId = recent
                                Task { await model.enableJit(recent) }
                            }
                        }
                        .onDelete { offsets in
                            offsets.map { model.recents[$0] }.forEach(model.forget)
                        }
                    }
                }
            }
            .navigationTitle("JIT")
        }
        .navigationViewStyle(.stack)
    }
}
