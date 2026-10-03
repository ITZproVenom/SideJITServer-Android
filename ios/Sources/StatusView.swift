import SwiftUI

struct StatusView: View {
    @EnvironmentObject private var model: AppModel

    var body: some View {
        NavigationView {
            Form {
                Section {
                    TextField("192.168.1.13:8080", text: $model.address)
                        .textInputAutocapitalization(.never)
                        .autocorrectionDisabled()
                        .keyboardType(.URL)
                        .onSubmit { Task { await model.refreshStatus() } }
                } header: {
                    Text("Android device")
                } footer: {
                    Text("The address SideJITServer shows on the Android screen. Port 8080 is assumed if you leave it off.")
                }

                if let error = model.statusError {
                    Section("Not reachable") {
                        Text(error).foregroundColor(.secondary)
                    }
                }

                if let status = model.status {
                    Section("Device") {
                        row("Paired", status.paired.map { $0 ? "yes" : "no" })
                        row("Name", status.device)
                        row("Identifier", status.udid)
                        row("Address", status.peerHost)
                        row("Listener port", status.listenerPort.map(String.init))
                    }
                    Section("Tunnel") {
                        row("Tunnel", status.tunnel)
                        row("JIT", status.jit)
                    }
                    if let stack = status.stack, !stack.isEmpty {
                        Section("Stack") {
                            Text(stack).font(.system(.footnote, design: .monospaced))
                        }
                    }
                }
            }
            .navigationTitle("SideJIT Control")
            .refreshable { await model.refreshStatus() }
        }
        .navigationViewStyle(.stack)
    }

    @ViewBuilder
    private func row(_ label: String, _ value: String?) -> some View {
        HStack {
            Text(label)
            Spacer()
            Text(value ?? "unknown")
                .foregroundColor(.secondary)
                .multilineTextAlignment(.trailing)
        }
    }
}
