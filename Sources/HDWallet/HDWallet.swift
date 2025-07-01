import Foundation
import CommonCrypto

public struct HDWallet {
    public let seed: Data
    public let masterKey: HDKey
    
    public init(seed: Data) throws {
        self.seed = seed
        self.masterKey = try HDKey(seed: seed)
    }
    
    public func derive(path: String) throws -> HDKey {
        return try masterKey.derive(path: path)
    }
    
    public func deriveAccount(index: UInt32, change: UInt32 = 0) throws -> HDKey {
        let path = "m/44'/60'/\(index)'/\(change)/0"
        return try derive(path: path)
    }
}

public struct HDKey {
    public let privateKey: Data
    public let publicKey: Data
    public let chainCode: Data
    
    public init(seed: Data) throws {
        let hmac = HMAC(key: "Bitcoin seed".data(using: .utf8)!, data: seed)
        let hash = hmac.digest()
        
        self.privateKey = hash.prefix(32)
        self.chainCode = hash.suffix(32)
        self.publicKey = Data() // Will be computed when needed
    }
    
    public init(privateKey: Data, chainCode: Data) throws {
        self.privateKey = privateKey
        self.chainCode = chainCode
        self.publicKey = Data() // Will be computed when needed
    }
    
    public func derive(path: String) throws -> HDKey {
        let components = path.split(separator: "/")
        var currentKey = self
        
        for component in components.dropFirst() {
            let isHardened = component.hasSuffix("'")
            let indexString = String(component.dropLast(isHardened ? 1 : 0))
            guard let index = UInt32(indexString) else {
                throw HDWalletError.invalidPath
            }
            
            currentKey = try currentKey.deriveChild(index: index, hardened: isHardened)
        }
        
        return currentKey
    }
    
    private func deriveChild(index: UInt32, hardened: Bool) throws -> HDKey {
        let data: Data
        if hardened {
            data = Data([0]) + privateKey + index.bigEndian.data
        } else {
            data = publicKey + index.bigEndian.data
        }
        
        let hmac = HMAC(key: chainCode, data: data)
        let hash = hmac.digest()
        
        let childPrivateKey = try addPrivateKeys(privateKey, hash.prefix(32))
        let childChainCode = hash.suffix(32)
        
        return try HDKey(privateKey: childPrivateKey, chainCode: childChainCode)
    }
    
    private func addPrivateKeys(_ key1: Data, _ key2: Data) throws -> Data {
        // Simple addition for now - this is a simplified implementation
        var result = Data()
        var carry: UInt8 = 0
        
        for i in 0..<32 {
            let byte1 = i < key1.count ? key1[i] : 0
            let byte2 = i < key2.count ? key2[i] : 0
            let sum = byte1 + byte2 + carry
            result.append(sum & 0xFF)
            carry = sum >> 8
        }
        
        return result
    }
}

public enum HDWalletError: Error {
    case invalidPath
    case invalidSeed
}

private struct HMAC {
    private let key: Data
    private let data: Data
    
    init(key: Data, data: Data) {
        self.key = key
        self.data = data
    }
    
    func digest() -> Data {
        let blockSize = 64
        let keyPadded: Data
        
        if key.count > blockSize {
            keyPadded = SHA256.hash(key)
        } else if key.count < blockSize {
            keyPadded = key + Data(repeating: 0, count: blockSize - key.count)
        } else {
            keyPadded = key
        }
        
        let outerKeyPad = keyPadded.map { $0 ^ 0x5c }
        let innerKeyPad = keyPadded.map { $0 ^ 0x36 }
        
        let innerHash = SHA256.hash(innerKeyPad + data)
        return SHA256.hash(outerKeyPad + innerHash)
    }
}

private struct SHA256 {
    static func hash(_ data: Data) -> Data {
        var hash = [UInt8](repeating: 0, count: Int(CC_SHA256_DIGEST_LENGTH))
        data.withUnsafeBytes { buffer in
            _ = CC_SHA256(buffer.baseAddress, CC_LONG(data.count), &hash)
        }
        return Data(hash)
    }
}

private extension UInt32 {
    var bigEndian: UInt32 {
        return self.bigEndian
    }
    
    var data: Data {
        return withUnsafeBytes(of: self) { Data($0) }
    }
} 