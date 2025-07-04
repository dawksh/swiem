import Foundation
import secp256k1
import Security

public struct Wallet {
    public let privateKey: Data
    public let publicKey: Data
    public let address: Address
    
    public init(privateKey: Data) throws {
        self.privateKey = privateKey
        self.publicKey = try secp256k1_derivePublicKey(privateKey: privateKey)
        self.address = try Address(publicKey: publicKey)
    }
    
    public init(mnemonic: Mnemonic, path: String = "m/44'/60'/0'/0/0") throws {
        let seed = mnemonic.seed()
        let hdWallet = try HDWallet(seed: seed)
        let hdKey = try hdWallet.derive(path: path)
        self.privateKey = hdKey.privateKey
        self.publicKey = try secp256k1_derivePublicKey(privateKey: hdKey.privateKey)
        self.address = try Address(publicKey: publicKey)
    }
    
    public init(mnemonicWords: [String], path: String = "m/44'/60'/0'/0/0") throws {
        let mnemonic = try Mnemonic(mnemonicWords.joined(separator: " "))
        try self.init(mnemonic: mnemonic, path: path)
    }
    
    public var privateKeyHex: String {
        return "0x" + privateKey.map { String(format: "%02x", $0) }.joined()
    }
    
    public var publicKeyHex: String {
        return "0x" + publicKey.map { String(format: "%02x", $0) }.joined()
    }
    
    public var addressHex: String {
        return address.hex
    }
    
    public var checksummedAddress: String {
        return address.checksummed
    }
    
    public static func randomPrivateKey() throws -> Data {
        while true {
            var key = Data(count: 32)
            let result = key.withUnsafeMutableBytes {
                SecRandomCopyBytes(kSecRandomDefault, 32, $0.baseAddress!)
            }
            if result == errSecSuccess, isValidSecp256k1PrivateKey(key) {
                return key
            }
        }
    }
}

enum WalletError: Error { case invalidPrivateKey }

func isValidSecp256k1PrivateKey(_ key: Data) -> Bool {
    guard key.count == 32 else { return false }
    if key.allSatisfy({ $0 == 0 }) { return false }
    let n: [UInt8] = [
        0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
        0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFE,
        0xBA,0xAE,0xDC,0xE6,0xAF,0x48,0xA0,0x3B,
        0xBF,0xD2,0x5E,0x8C,0xD0,0x36,0x41,0x41
    ]
    return key.lexicographicallyPrecedes(Data(n))
}

func secp256k1_derivePublicKey(privateKey: Data) throws -> Data {
    guard isValidSecp256k1PrivateKey(privateKey) else { throw WalletError.invalidPrivateKey }
    var ctx = secp256k1_context_create(UInt32(SECP256K1_CONTEXT_SIGN))!
    defer { secp256k1_context_destroy(ctx) }
    var pk = secp256k1_pubkey()
    let result = privateKey.withUnsafeBytes { (ptr: UnsafeRawBufferPointer) -> Int32 in
        guard let base = ptr.bindMemory(to: UInt8.self).baseAddress else { return 0 }
        return secp256k1_ec_pubkey_create(ctx, &pk, base)
    }
    guard result == 1 else { throw WalletError.invalidPrivateKey }
    var output = [UInt8](repeating: 0, count: 65)
    var outputLen: size_t = 65
    secp256k1_ec_pubkey_serialize(ctx, &output, &outputLen, &pk, UInt32(SECP256K1_EC_UNCOMPRESSED))
    return Data(output[0..<Int(outputLen)])
} 