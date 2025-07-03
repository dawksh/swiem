import XCTest
@testable import swiem

final class swiemTests: XCTestCase {

    /*

    Mnemonic

    - [x] Mnemonic Generation
    - [x] Mnemonic Validation

    */

    func testMnemonicGeneration() throws {
        let mnemonic = try Mnemonic.random()
        XCTAssertEqual(mnemonic.phrase.components(separatedBy: " ").count, 12)
        XCTAssertTrue(mnemonic.isValid)
    }
    
    func testMnemonicValidation() throws {
        let validWords = ["abandon", "abandon", "abandon", "abandon", "abandon", "abandon", "abandon", "abandon", "abandon", "abandon", "abandon", "about"]
        let mnemonic = try Mnemonic(validWords.joined(separator: " "))
        XCTAssertTrue(mnemonic.isValid)
    }

}
