import Foundation
import secp256k1
import Security
import BigInt

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
    
    public static func randomMnemonic() throws -> Mnemonic {
        try Mnemonic.random()
    }
    
    public func signMessage(_ message: Data) throws -> (v: UInt8, r: Data, s: Data) {
        let prefix = "\u{19}Ethereum Signed Message:\n" + String(message.count)
        let prefixed = prefix.data(using: .utf8)! + message
        let hash = keccak256(prefixed)
        var ctx = secp256k1_context_create(UInt32(SECP256K1_CONTEXT_SIGN))!
        defer { secp256k1_context_destroy(ctx) }
        var signature = secp256k1_ecdsa_recoverable_signature()
        let result = privateKey.withUnsafeBytes { keyPtr in
            hash.withUnsafeBytes { msgPtr in
                guard let keyBase = keyPtr.bindMemory(to: UInt8.self).baseAddress,
                      let msgBase = msgPtr.bindMemory(to: UInt8.self).baseAddress else { return 0 }
                return Int(secp256k1_ecdsa_sign_recoverable(ctx, &signature, msgBase, keyBase, nil, nil))
            }
        }
        guard result == 1 else { throw WalletError.invalidPrivateKey }
        var output = [UInt8](repeating: 0, count: 64)
        var recid: Int32 = 0
        secp256k1_ecdsa_recoverable_signature_serialize_compact(ctx, &output, &recid, &signature)
        let r = Data(output[0..<32])
        let s = Data(output[32..<64])
        let v = UInt8(recid) + 27
        return (v, r, s)
    }
    
    public func signMessageCompact(_ message: Data) throws -> Data {
        let prefix = "\u{19}Ethereum Signed Message:\n" + String(message.count)
        let prefixed = prefix.data(using: .utf8)! + message
        let hash = keccak256(prefixed)
        var ctx = secp256k1_context_create(UInt32(SECP256K1_CONTEXT_SIGN))!
        defer { secp256k1_context_destroy(ctx) }
        var signature = secp256k1_ecdsa_recoverable_signature()
        let result = privateKey.withUnsafeBytes { keyPtr in
            hash.withUnsafeBytes { msgPtr in
                guard let keyBase = keyPtr.bindMemory(to: UInt8.self).baseAddress,
                      let msgBase = msgPtr.bindMemory(to: UInt8.self).baseAddress else { return 0 }
                return Int(secp256k1_ecdsa_sign_recoverable(ctx, &signature, msgBase, keyBase, nil, nil))
            }
        }
        guard result == 1 else { throw WalletError.invalidPrivateKey }
        var output = [UInt8](repeating: 0, count: 64)
        var recid: Int32 = 0
        secp256k1_ecdsa_recoverable_signature_serialize_compact(ctx, &output, &recid, &signature)
        var sig = Data(output)
        sig.append(UInt8(recid) + 27)
        return sig
    }
    
    public func signTypedData712(domainHash: Data, structHash: Data) throws -> (v: UInt8, r: Data, s: Data) {
        let prefix = Data([0x19, 0x01])
        let hash = keccak256(prefix + domainHash + structHash)
        var ctx = secp256k1_context_create(UInt32(SECP256K1_CONTEXT_SIGN))!
        defer { secp256k1_context_destroy(ctx) }
        var signature = secp256k1_ecdsa_recoverable_signature()
        let result = privateKey.withUnsafeBytes { keyPtr in
            hash.withUnsafeBytes { msgPtr in
                guard let keyBase = keyPtr.bindMemory(to: UInt8.self).baseAddress,
                      let msgBase = msgPtr.bindMemory(to: UInt8.self).baseAddress else { return 0 }
                return Int(secp256k1_ecdsa_sign_recoverable(ctx, &signature, msgBase, keyBase, nil, nil))
            }
        }
        guard result == 1 else { throw WalletError.invalidPrivateKey }
        var output = [UInt8](repeating: 0, count: 64)
        var recid: Int32 = 0
        secp256k1_ecdsa_recoverable_signature_serialize_compact(ctx, &output, &recid, &signature)
        let r = Data(output[0..<32])
        let s = Data(output[32..<64])
        let v = UInt8(recid) + 27
        return (v, r, s)
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

public struct TypedData {
    public let types: [String: [[String: String]]]
    public let primaryType: String
    public let domain: [String: Any]
    public let message: [String: Any]
}

func encodeType(_ types: [String: [[String: String]]], _ primaryType: String) -> String {
    let deps = findTypeDependencies(types, primaryType).sorted()
    return ([primaryType] + deps.filter { $0 != primaryType }).map { t in
        let fields = types[t]!.map { "\($0["type"]!) \($0["name"]!)" }.joined(separator: ",")
        return "\(t)(\(fields))"
    }.joined()
}

func findTypeDependencies(_ types: [String: [[String: String]]], _ primaryType: String, _ found: Set<String> = []) -> [String] {
    var result = found
    if result.contains(primaryType) { return Array(result) }
    result.insert(primaryType)
    for field in types[primaryType] ?? [] {
        let t = field["type"]!
        if types[t] != nil { result = result.union(findTypeDependencies(types, t, result)) }
    }
    return Array(result)
}

func typeHash(_ types: [String: [[String: String]]], _ primaryType: String) -> Data {
    keccak256(encodeType(types, primaryType).data(using: .utf8)!)
}

func encodeData(_ types: [String: [[String: String]]], _ primaryType: String, _ data: [String: Any]) -> Data {
    var enc = typeHash(types, primaryType)
    for field in types[primaryType]! {
        let t = field["type"]!
        let n = field["name"]!
        let v = data[n]!
        enc.append(encodeValue(types, t, v))
    }
    return enc
}

func encodeValue(_ types: [String: [[String: String]]], _ t: String, _ v: Any) -> Data {
    if types[t] != nil { return keccak256(encodeData(types, t, v as! [String: Any])) }
    if t == "string" { return keccak256((v as! String).data(using: .utf8)!) }
    if t == "bytes" { return keccak256(v as! Data) }
    if t == "address" { return (v as! Address).data.leftPadding(toLength: 32) }
    if t == "bool" { return (v as! Bool ? BigUInt(1) : BigUInt(0)).serialize().leftPadding(toLength: 32) }
    if t.hasPrefix("uint") || t.hasPrefix("int") { return (v as! BigUInt).serialize().leftPadding(toLength: 32) }
    if t.hasPrefix("bytes") { return (v as! Data).leftPadding(toLength: 32) }
    return Data(count: 32)
}

func structHash(_ types: [String: [[String: String]]], _ primaryType: String, _ data: [String: Any]) -> Data {
    keccak256(encodeData(types, primaryType, data))
}

func domainSeparator(_ types: [String: [[String: String]]], _ domain: [String: Any]) -> Data {
    structHash(types, "EIP712Domain", domain)
}

extension Wallet {
    public func signTypedData(_ typed: TypedData) throws -> (v: UInt8, r: Data, s: Data) {
        let dHash = domainSeparator(typed.types, typed.domain)
        let sHash = structHash(typed.types, typed.primaryType, typed.message)
        return try signTypedData712(domainHash: dHash, structHash: sHash)
    }
}

private extension Data {
    func leftPadding(toLength: Int) -> Data {
        count >= toLength ? self : Data(repeating: 0, count: toLength - count) + self
    }
} 