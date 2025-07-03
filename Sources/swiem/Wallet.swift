import Foundation
import secp256k1

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
}

func secp256k1_derivePublicKey(privateKey: Data) throws -> Data {
    var ctx = secp256k1_context_create(UInt32(SECP256K1_CONTEXT_SIGN))!
    defer { secp256k1_context_destroy(ctx) }
    var pk = secp256k1_pubkey()
    let result = privateKey.withUnsafeBytes { (ptr: UnsafeRawBufferPointer) -> Int32 in
        guard let base = ptr.bindMemory(to: UInt8.self).baseAddress else { return 0 }
        return secp256k1_ec_pubkey_create(ctx, &pk, base)
    }
    guard result == 1 else { throw NSError(domain: "secp256k1", code: -1) }
    var output = [UInt8](repeating: 0, count: 65)
    var outputLen: size_t = 65
    secp256k1_ec_pubkey_serialize(ctx, &output, &outputLen, &pk, UInt32(SECP256K1_EC_UNCOMPRESSED))
    return Data(output[0..<Int(outputLen)])
} 