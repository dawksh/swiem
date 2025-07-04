import Foundation

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
        guard publicKey.count == 65, publicKey.first == 0x04 else {
            throw AddressError.invalidLength
        }
        let pk = Data(publicKey.dropFirst())
        let hash = keccak256(pk)
        self.data = hash.suffix(20)
    }
    
    public var hex: String {
        return "0x" + data.map { String(format: "%02x", $0) }.joined()
    }
    
    public var checksummed: String {
        let address = hex.dropFirst(2).lowercased()
        let hash = keccak256(address.data(using: .utf8)!)
        let checksummed = address.enumerated().map { i, c in
            let nibble = (hash[i / 2] >> (i % 2 == 0 ? 4 : 0)) & 0x0F
            return nibble >= 8 ? String(c).uppercased() : String(c)
        }.joined()
        return "0x" + checksummed
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