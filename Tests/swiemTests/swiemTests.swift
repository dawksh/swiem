import XCTest
@testable import swiem

final class swiemTests: XCTestCase {
    func testMnemonicGeneration() throws {
        let mnemonic = try Mnemonic(strength: 128)
        XCTAssertEqual(mnemonic.words.count, 12)
        XCTAssertTrue(mnemonic.isValid)
    }
    
    func testMnemonicValidation() throws {
        let validWords = ["abandon", "abandon", "abandon", "abandon", "abandon", "abandon", "abandon", "abandon", "abandon", "abandon", "abandon", "about"]
        let mnemonic = try Mnemonic(words: validWords)
        XCTAssertTrue(mnemonic.isValid)
    }
    
    func testAddressValidation() throws {
        let validAddress = try Address(hex: "0x9858EfFD232B4033E47d90003D41EC34Caea1e14")
        XCTAssertTrue(validAddress.isValid)
        
        XCTAssertThrowsError(try Address(hex: "0x123"))
    }
    
    func testAddressChecksum() throws {
        let address = try Address(hex: "0x9858effd232b4033e47d90003d41ec34caea1e14")
        XCTAssertEqual(address.checksummed, "0x9858EfFD232B4033E47d90003D41EC34Caea1e14")
    }
}
