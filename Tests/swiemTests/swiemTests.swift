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


    /*
    
    Address
    
    - [x] Address Generation
    - [x] Address Validation
    
    */

    func testAddressGeneration() throws {
        let address = try Address(hex: "0x28172273cc1e0395f3473ec6ed062b6fdfb15940")
        print(address)
        XCTAssertEqual(address.checksummed, "0x28172273CC1E0395F3473EC6eD062B6fdFb15940")
    }
    
    func testAddressValidation() throws {
        let validAddress = try Address(hex: "0x9858EfFD232B4033E47d90003D41EC34Caea1e14")
        XCTAssertTrue(validAddress.isValid)
    }

    /*

    Wallet

    - [ ] Wallet Generation
    - [ ] Wallet Validation
    
    */

    func testWalletGenerationFromMnemonic() throws {
        let words = ["abandon", "abandon", "abandon", "abandon", "abandon", "abandon", "abandon", "abandon", "abandon", "abandon", "abandon", "about"]
        let mnemonic = try Mnemonic(words.joined(separator: " "))
        print("mnemonic:", mnemonic.phrase)
        let wallet = try Wallet(mnemonic: mnemonic)
        print("privateKey:", wallet.privateKeyHex)
        print("publicKey:", wallet.publicKeyHex)
        XCTAssertEqual(wallet.privateKey.count, 32)
        XCTAssertEqual(wallet.publicKey.count, 65)
        XCTAssertTrue(wallet.address.isValid)
    }
}
