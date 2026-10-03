import Foundation

/// What `/status` on the Android server reports.
struct ServerStatus: Decodable {
    let paired: Bool?
    let device: String?
    let udid: String?
    let peerHost: String?
    let listenerPort: Int?
    let tunnel: String?
    let jit: String?
    let stack: String?
}

enum ServerError: LocalizedError {
    case noAddress
    case badAddress(String)
    case http(Int, String)
    case transport(String)

    var errorDescription: String? {
        switch self {
        case .noAddress:
            return "No server address set yet."
        case .badAddress(let text):
            return "\(text) is not an address this app can reach."
        case .http(let code, let body):
            return body.isEmpty ? "The server answered \(code)." : "The server answered \(code): \(body)"
        case .transport(let message):
            return message
        }
    }
}

/// Talks to the SideJITServer HTTP API on the Android device.
///
/// Everything here is a plain HTTP request to the same routes the server already serves to
/// SideStore and LiveContainer. This app adds no capability of its own; if the server cannot
/// do something, neither can this.
actor ServerClient {
    private let session: URLSession

    init() {
        let configuration = URLSessionConfiguration.ephemeral
        configuration.timeoutIntervalForRequest = 20
        configuration.waitsForConnectivity = false
        session = URLSession(configuration: configuration)
    }

    private func base(_ address: String) throws -> URL {
        let trimmed = address.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { throw ServerError.noAddress }
        let withScheme = trimmed.contains("://") ? trimmed : "http://\(trimmed)"
        guard var components = URLComponents(string: withScheme) else {
            throw ServerError.badAddress(trimmed)
        }
        if components.port == nil { components.port = 8080 }
        guard let url = components.url, components.host?.isEmpty == false else {
            throw ServerError.badAddress(trimmed)
        }
        return url
    }

    private func get(_ address: String, path: String) async throws -> (Int, Data) {
        let url = try base(address).appendingPathComponent(path, isDirectory: path.hasSuffix("/"))
        do {
            let (data, response) = try await session.data(from: url)
            let code = (response as? HTTPURLResponse)?.statusCode ?? 0
            return (code, data)
        } catch {
            throw ServerError.transport(error.localizedDescription)
        }
    }

    func status(_ address: String) async throws -> ServerStatus {
        let (code, data) = try await get(address, path: "status")
        guard code == 200 else {
            throw ServerError.http(code, String(data: data, encoding: .utf8) ?? "")
        }
        do {
            return try JSONDecoder().decode(ServerStatus.self, from: data)
        } catch {
            throw ServerError.transport("The server sent a status this app could not read.")
        }
    }

    func diagnostics(_ address: String) async throws -> String {
        let (code, data) = try await get(address, path: "diag")
        guard code == 200 else {
            throw ServerError.http(code, String(data: data, encoding: .utf8) ?? "")
        }
        return String(data: data, encoding: .utf8) ?? ""
    }

    /// Asks the server to enable JIT for a bundle identifier, using the route SideStore uses.
    func enableJit(_ address: String, bundleId: String) async throws -> String {
        let trimmed = bundleId.trimmingCharacters(in: .whitespacesAndNewlines)
        let escaped = trimmed.addingPercentEncoding(withAllowedCharacters: .alphanumerics.union(CharacterSet(charactersIn: ".-_")))
            ?? trimmed
        let (code, data) = try await get(address, path: "\(escaped)/")
        let body = String(data: data, encoding: .utf8) ?? ""
        guard code == 200 else { throw ServerError.http(code, body) }
        return body
    }
}
