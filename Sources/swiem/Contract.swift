import Foundation

public struct Contract {
    public let address: String
    public let provider: Provider
    public init(address: String, provider: Provider) {
        self.address = address
        self.provider = provider
    }
}

public func contract(address: String, provider: Provider) -> Contract {
    Contract(address: address, provider: provider)
}

public func readContract(contract: Contract, abi: [[String:Any]], function: String, params: [Any], completion: @escaping (Result<Any, Error>) -> Void) {
    let methodAbi = abi.first { ($0["name"] as? String) == function }!
    let types = (methodAbi["inputs"] as! [[String:Any]]).map { $0["type"] as! String }
    let selector = keccak256((function + "(" + types.joined(separator: ",") + ")").data(using: .utf8)!).prefix(4)
    let encodedArgs = params.enumerated().map { i, v in encodeAbiArg(type: types[i], value: v) }.reduce(Data(), +)
    let data = selector + encodedArgs
    let call: [String: Any] = ["to": contract.address, "data": "0x" + data.map { String(format: "%02x", $0) }.joined()]
    contract.provider.send(method: "eth_call", params: [call, "latest"], completion: completion)
}

public func writeContract(contract: Contract, abi: [[String:Any]], function: String, params: [Any], wallet: Wallet, completion: @escaping (Result<Any, Error>) -> Void) {
    let methodAbi = abi.first { ($0["name"] as? String) == function }!
    let types = (methodAbi["inputs"] as! [[String:Any]]).map { $0["type"] as! String }
    let selector = keccak256((function + "(" + types.joined(separator: ",") + ")").data(using: .utf8)!).prefix(4)
    let encodedArgs = params.enumerated().map { i, v in encodeAbiArg(type: types[i], value: v) }.reduce(Data(), +)
    let data = selector + encodedArgs
    let to = try! Address(hex: contract.address)
    let tx = EthereumTransaction(nonce: .zero, gasPrice: .zero, gasLimit: .zero, to: to, value: .zero, data: data, chainId: 1)
    let raw = try! wallet.sendTransaction(tx: tx)
    contract.provider.send(method: "eth_sendRawTransaction", params: ["0x" + raw.map { String(format: "%02x", $0) }.joined()], completion: completion)
} 