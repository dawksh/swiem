import Foundation
import Bip39

public struct Mnemonic {
    public let phrase: String
    public let bip39: Bip39.Mnemonic
    public init(_ phrase: String) throws {
        self.phrase = phrase
        self.bip39 = try Bip39.Mnemonic(mnemonic: phrase.components(separatedBy: " "))
    }
    public static func random() throws -> Mnemonic {
        let m = try Bip39.Mnemonic()
        return try Mnemonic(m.mnemonic().joined(separator: " "))
    }
    public var entropy: Data { Data(bip39.entropy) }
    public func seed(password: String = "") -> Data { Data(bip39.seed(password: password)) }
    public var isValid: Bool { Bip39.Mnemonic.isValid(phrase: phrase.components(separatedBy: " ")) }
} 