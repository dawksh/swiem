import XCTest
@testable import swiem

final class swiemTests: XCTestCase {

    // Mnemonic Tests

    func testMnemonicGeneration() throws {
        let mnemonic = try Mnemonic.random()
        XCTAssertEqual(mnemonic.words.count, 12)
        XCTAssertTrue(mnemonic.isValid)
    }
    
    func testMnemonicValidation() throws {
        let validWords = ["abandon", "abandon", "abandon", "abandon", "abandon", "abandon", "abandon", "abandon", "abandon", "abandon", "abandon", "about"]
        let mnemonic = try Mnemonic(words: validWords)
        XCTAssertTrue(mnemonic.isValid)
    }

}
