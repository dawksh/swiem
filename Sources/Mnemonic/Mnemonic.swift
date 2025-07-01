import Foundation
import Bip39

public struct Mnemonic {
    public let words: [String]
    public let entropy: Data
    
    public init(words: [String]) throws {
        self.words = words
        self.entropy = try Bip39.entropy(from: words)
    }
    
    public init(entropy: Data) throws {
        self.entropy = entropy
        self.words = try Bip39.mnemonic(from: entropy)
    }
    
    public init(strength: Int = 128) throws {
        let entropy = try Bip39.generateEntropy(strength: strength)
        self.entropy = entropy
        self.words = try Bip39.mnemonic(from: entropy)
    }
    
    public func toSeed(passphrase: String = "") -> Data {
        return Bip39.seed(from: words, passphrase: passphrase)
    }
    
    public var isValid: Bool {
        return Bip39.isValid(mnemonic: words)
    }
} 