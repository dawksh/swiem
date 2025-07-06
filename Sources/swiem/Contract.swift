import Foundation

public struct Contract {
    public let address: String
    public let abi: Data
    public init(address: String, abi: Data) {
        self.address = address
        self.abi = abi
    }
}

public func contract(address: String, abi: Data) -> Contract {
    Contract(address: address, abi: abi)
}

public func readContract(contract: Contract, function: String, params: [Any]) -> Data? {
    nil
}

public func writeContract(contract: Contract, function: String, params: [Any], privateKey: Data) -> Data? {
    nil
} 