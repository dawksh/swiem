import Foundation

public enum ProviderType { case http(String), wss(String) }

public struct Provider {
    public let type: ProviderType
    public init(type: ProviderType) { self.type = type }
    public func send(method: String, params: [Any], completion: @escaping (Result<Any, Error>) -> Void) {
        switch type {
        case .http(let url):
            let payload: [String: Any] = ["jsonrpc": "2.0", "method": method, "params": params, "id": 1]
            let body = try! JSONSerialization.data(withJSONObject: payload)
            var req = URLRequest(url: URL(string: url)!)
            req.httpMethod = "POST"
            req.setValue("application/json", forHTTPHeaderField: "Content-Type")
            req.httpBody = body
            URLSession.shared.dataTask(with: req) { data, _, err in
                if let err = err { completion(.failure(err)); return }
                guard let data = data,
                      let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
                    completion(.failure(NSError(domain: "rpc", code: 0)))
                    return
                }
                if let result = json["result"] { completion(.success(result)) }
                else { completion(.failure(NSError(domain: "rpc", code: 1))) }
            }.resume()
        case .wss(_):
            completion(.failure(NSError(domain: "wss", code: 0)))
        }
    }
}

public func jsonRpcProvider(_ url: String) -> Provider {
    Provider(type: .http(url))
}

public func wssProvider(_ url: String) -> Provider {
    Provider(type: .wss(url))
} 