import Foundation
import SwiftUI

@MainActor
final class AppModel: ObservableObject {
    /// Stored by hand rather than with AppStorage: AppStorage does not publish changes from
    /// inside an ObservableObject, so views bound to it would not redraw.
    @Published var address: String = UserDefaults.standard.string(forKey: "serverAddress") ?? "" {
        didSet { UserDefaults.standard.set(address, forKey: "serverAddress") }
    }
    @Published private var recentStore: String = UserDefaults.standard.string(forKey: "recentBundleIds") ?? "" {
        didSet { UserDefaults.standard.set(recentStore, forKey: "recentBundleIds") }
    }

    @Published var status: ServerStatus?
    @Published var statusError: String?
    @Published var diagnostics: String = ""
    @Published var busy = false
    @Published var lastResult: String?

    private let client = ServerClient()
    private var poller: Task<Void, Never>?

    var recents: [String] {
        recentStore.split(separator: "\n").map(String.init).filter { !$0.isEmpty }
    }

    func remember(_ bundleId: String) {
        let trimmed = bundleId.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { return }
        var list = recents.filter { $0.caseInsensitiveCompare(trimmed) != .orderedSame }
        list.insert(trimmed, at: 0)
        recentStore = list.prefix(12).joined(separator: "\n")
    }

    func forget(_ bundleId: String) {
        recentStore = recents.filter { $0 != bundleId }.joined(separator: "\n")
    }

    func startPolling() {
        poller?.cancel()
        poller = Task { [weak self] in
            while !Task.isCancelled {
                await self?.refreshStatus()
                try? await Task.sleep(nanoseconds: 3_000_000_000)
            }
        }
    }

    func stopPolling() {
        poller?.cancel()
        poller = nil
    }

    func refreshStatus() async {
        guard !address.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
            status = nil
            statusError = "Set the address of the Android device first."
            return
        }
        do {
            status = try await client.status(address)
            statusError = nil
        } catch {
            status = nil
            statusError = error.localizedDescription
        }
    }

    func refreshDiagnostics() async {
        do {
            diagnostics = try await client.diagnostics(address)
        } catch {
            diagnostics = error.localizedDescription
        }
    }

    func enableJit(_ bundleId: String) async {
        busy = true
        defer { busy = false }
        do {
            let body = try await client.enableJit(address, bundleId: bundleId)
            remember(bundleId)
            lastResult = body.isEmpty ? "The server accepted the request." : body
        } catch {
            lastResult = error.localizedDescription
        }
    }
}
