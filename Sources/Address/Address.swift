import Foundation
import web3

public struct Address {
    public let data: Data
    
    public init(data: Data) throws {
        guard data.count == 20 else {
            throw AddressError.invalidLength
        }
        self.data = data
    }
    
    public init(hex: String) throws {
        let cleanHex = hex.hasPrefix("0x") ? String(hex.dropFirst(2)) : hex
        guard let data = Data(hex: cleanHex), data.count == 20 else {
            throw AddressError.invalidHex
        }
        self.data = data
    }
    
    public init(publicKey: Data) throws {
        let hash = Web3.Utils.keccak256(publicKey.dropFirst())
        self.data = hash.suffix(20)
    }
    
    public var hex: String {
        return "0x" + data.map { String(format: "%02x", $0) }.joined()
    }
    
    public var checksummed: String {
        let address = hex.dropFirst(2)
        let hash = Web3.Utils.keccak256(address.data(using: .utf8)!)
        
        return "0x" + zip(address, hash).map { char, hashByte in
            let char = String(char)
            let hashNibble = (hashByte >> 4) & 0x0F
            let shouldUppercase = hashNibble >= 8
            return shouldUppercase ? char.uppercased() : char.lowercased()
        }.joined()
    }
    
    public var isValid: Bool {
        return data.count == 20
    }
}

public enum AddressError: Error {
    case invalidLength
    case invalidHex
}

private extension Data {
    init?(hex: String) {
        let chars = Array(hex)
        let bytes = stride(from: 0, to: chars.count, by: 2).map {
            String(chars[$0..<min($0 + 2, chars.count)])
        }
        
        self = bytes.compactMap { byte in
            UInt8(byte, radix: 16)
        }
    }
} 