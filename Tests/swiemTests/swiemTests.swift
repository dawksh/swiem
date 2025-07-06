import XCTest
@testable import swiem
import BigInt

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
        let seed = mnemonic.seed()
        let hdWallet = try HDWallet(seed: seed)
        let hdKey = try hdWallet.derive(path: "m/44'/60'/0'/0/0")
        let privateKey = hdKey.privateKey
        _ = try Wallet(privateKey: privateKey)
        XCTAssertEqual(privateKey.count, 32)
        XCTAssertTrue(isValidSecp256k1PrivateKey(privateKey))
    }

    func testMinimalSecp256k1() throws {
        let privateKeyHex = "353f27c157022f59b5620db8f348a47994a3100547618619f5032b1bab0167ed"
        let privateKey = Data(hex: privateKeyHex)!
        let publicKey = try secp256k1_derivePublicKey(privateKey: privateKey)
        XCTAssertEqual(privateKey.count, 32)
        XCTAssertEqual(publicKey.count, 65)
    }

    func testMinimalAddressFromPublicKey() throws {
        let publicKeyHex = "04886d67a47bd30b43b4358f4ce72568dba1c52331c1793bf6b5a916f5dd6b298fc63acf986d7774b5776023103f0890ff4fe80b90be9e328453bace0984e76bbe"
        let publicKey = Data(hex: publicKeyHex)!
        do {
            let address = try Address(publicKey: publicKey)
            XCTAssertEqual(address.data.count, 20)
        } catch {
            XCTFail("Address(publicKey:) threw error: \(error)")
        }
    }

    func testMinimalKeccak256() throws {
        let input = Data([0x01, 0x02, 0x03, 0x04])
        let hash = keccak256(input)
        XCTAssertEqual(hash.count, 32)
    }

    func testRandomPrivateKeyGeneration() throws {
        let key = try Wallet.randomPrivateKey()
        XCTAssertEqual(key.count, 32)
        XCTAssertTrue(isValidSecp256k1PrivateKey(key))
    }

    func testRandomMnemonicGeneration() throws {
        let mnemonic = try Wallet.randomMnemonic()
        XCTAssertEqual(mnemonic.phrase.components(separatedBy: " ").count, 12)
        XCTAssertTrue(mnemonic.isValid)
    }

    func testSignMessage() throws {
        let privateKeyHex = "353f27c157022f59b5620db8f348a47994a3100547618619f5032b1bab0167ed"
        let privateKey = Data(hex: privateKeyHex)!
        let wallet = try Wallet(privateKey: privateKey)
        let message = "hello".data(using: .utf8)!
        let (v, r, s) = try wallet.signMessage(message)
        XCTAssertEqual(r.count, 32)
        XCTAssertEqual(s.count, 32)
        XCTAssertTrue(v == 27 || v == 28)
    }

    func testSignMessageCompact() throws {
        let privateKeyHex = "353f27c157022f59b5620db8f348a47994a3100547618619f5032b1bab0167ed"
        let privateKey = Data(hex: privateKeyHex)!
        let wallet = try Wallet(privateKey: privateKey)
        let message = "hello".data(using: .utf8)!
        let sig = try wallet.signMessageCompact(message)
        XCTAssertEqual(sig.count, 65)
        let v = sig[64]
        XCTAssertTrue(v == 27 || v == 28)
    }

    func testSignTypedData712() throws {
        let privateKeyHex = "353f27c157022f59b5620db8f348a47994a3100547618619f5032b1bab0167ed"
        let privateKey = Data(hex: privateKeyHex)!
        let wallet = try Wallet(privateKey: privateKey)
        let types: [String: [[String: String]]] = [
            "EIP712Domain": [
                ["name": "name", "type": "string"],
                ["name": "version", "type": "string"],
                ["name": "chainId", "type": "uint256"],
                ["name": "verifyingContract", "type": "address"]
            ],
            "Person": [
                ["name": "name", "type": "string"],
                ["name": "wallet", "type": "address"]
            ]
        ]
        let domain: [String: Any] = [
            "name": "Ether Mail",
            "version": "1",
            "chainId": BigUInt(1),
            "verifyingContract": try Address(hex: "0xCcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC")
        ]
        let message: [String: Any] = [
            "name": "Bob",
            "wallet": try Address(hex: "0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB")
        ]
        let typed = TypedData(types: types, primaryType: "Person", domain: domain, message: message)
        let (v, r, s) = try wallet.signTypedData(typed)
        XCTAssertEqual(r.count, 32)
        XCTAssertEqual(s.count, 32)
        XCTAssertTrue(v == 27 || v == 28)
    }

    func testSendTransaction() throws {
        let privateKeyHex = "353f27c157022f59b5620db8f348a47994a3100547618619f5032b1bab0167ed"
        let privateKey = Data(hex: privateKeyHex)!
        let wallet = try Wallet(privateKey: privateKey)
        let to = try Address(hex: "0x9858EfFD232B4033E47d90003D41EC34Caea1e14")
        let tx = EthereumTransaction(
            nonce: 1,
            gasPrice: 1000000000,
            gasLimit: 21000,
            to: to,
            value: 1000000000000000000,
            data: Data(),
            chainId: 1
        )
        let raw = try wallet.sendTransaction(tx: tx)
        XCTAssertFalse(raw.isEmpty)
    }

    func testWriteContract() throws {
        let privateKeyHex = "353f27c157022f59b5620db8f348a47994a3100547618619f5032b1bab0167ed"
        let privateKey = Data(hex: privateKeyHex)!
        let wallet = try Wallet(privateKey: privateKey)
        let to = try Address(hex: "0xCcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC")
        let abi: [[String:Any]] = [[
            "name": "transfer",
            "type": "function",
            "inputs": [
                ["name": "to", "type": "address"],
                ["name": "amount", "type": "uint256"]
            ]
        ]]
        let args: [Any] = [try Address(hex: "0x9858EfFD232B4033E47d90003D41EC34Caea1e14"), BigUInt(1000)]
        let raw = try wallet.writeContract(method: "transfer", to: to, abi: abi, args: args, nonce: 1, gasPrice: 1000000000, gasLimit: 60000, value: 0, chainId: 1)
        XCTAssertFalse(raw.isEmpty)
    }
}

extension Data {
    init?(hex: String) {
        let len = hex.count
        var data = Data(capacity: len / 2)
        var i = hex.startIndex
        while i < hex.endIndex {
            let j = hex.index(i, offsetBy: 2)
            guard j <= hex.endIndex else { return nil }
            let byte = hex[i..<j]
            if let b = UInt8(byte, radix: 16) {
                data.append(b)
            } else {
                return nil
            }
            i = j
        }
        self = data
    }
}
