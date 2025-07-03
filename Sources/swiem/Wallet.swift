import Foundation
import web3

public struct Wallet {
    public let privateKey: Data
    public let publicKey: Data
    public let address: Address
    
    public init(privateKey: Data) throws {
        self.privateKey = privateKey
        let pk = try EthereumPrivateKey(privateKey: privateKey)
        self.publicKey = pk.publicKey.raw
        self.address = try Address(publicKey: publicKey)
    }
    
    public init(mnemonic: Mnemonic, path: String = "m/44'/60'/0'/0/0") throws {
        let seed = mnemonic.seed()
        let hdWallet = try HDWallet(seed: seed)
        let hdKey = try hdWallet.derive(path: path)
        
        self.privateKey = hdKey.privateKey
        self.publicKey = hdKey.publicKey
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