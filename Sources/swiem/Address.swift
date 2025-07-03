import Foundation
import UncommonCrypto
import CryptoSwift

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
        let hash = keccak256(publicKey.dropFirst())
        self.data = hash.suffix(20)
    }
    
    public var hex: String {
        return "0x" + data.map { String(format: "%02x", $0) }.joined()
    }
    
    public var checksummed: String {
        let address = hex.dropFirst(2)
        let hash = keccak256(address.data(using: .utf8)!)
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
        let bytes = stride(from: 0, to: chars.count, by: 2).compactMap {
            UInt8(String(chars[$0..<Swift.min($0 + 2, chars.count)]), radix: 16)
        }
        guard bytes.count * 2 == chars.count else { return nil }
        self.init(bytes)
    }
}

func keccak256(_ data: Data) -> Data {
    data.sha3(.keccak256)
} 