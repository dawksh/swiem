import Foundation
import CommonCrypto
import BigInt
import secp256k1

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
        self.publicKey = try secp256k1_derivePublicKey(privateKey: self.privateKey)
    }
    
    public init(privateKey: Data, chainCode: Data) throws {
        self.privateKey = privateKey
        self.chainCode = chainCode
        self.publicKey = try secp256k1_derivePublicKey(privateKey: privateKey)
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
        let n = BigUInt(Data([
            0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
            0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFE,
            0xBA,0xAE,0xDC,0xE6,0xAF,0x48,0xA0,0x3B,
            0xBF,0xD2,0x5E,0x8C,0xD0,0x36,0x41,0x41
        ]))
        let k1 = BigUInt(key1)
        let k2 = BigUInt(key2)
        let sum = (k1 + k2) % n
        guard sum > 0 && sum < n else { throw HDWalletError.invalidSeed }
        let sumData = sum.serialize().leftPadding(toLength: 32)
        return sumData
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
    var data: Data {
        withUnsafeBytes(of: self.bigEndian) { Data($0) }
    }
}

private extension Data {
    func leftPadding(toLength: Int) -> Data {
        count >= toLength ? self : Data(repeating: 0, count: toLength - count) + self
    }
} 