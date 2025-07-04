# 🧱 Swiem: Building a Viem-Equivalent Ethereum Library in Swift

This document outlines a step-by-step guide to building a **Viem-equivalent Ethereum utility library in Swift**. Inspired by [Viem](https://viem.sh) and [ethers.js](https://docs.ethers.org), this Swift package aims to provide wallet management, ABI encoding/decoding, transaction signing, and JSON-RPC communication.

## Components

### Mnemonic
- Generates and validates BIP-39 mnemonics.
- Converts mnemonics to entropy and seed.
- Methods/properties:
  - `init(_ phrase: String) throws`
  - `static func random() throws -> Mnemonic`
  - `var phrase: String`
  - `var entropy: Data`
  - `func seed(password: String = "") -> Data`
  - `var isValid: Bool`
- Example:
  ```swift
  let mnemonic = try Mnemonic.random()
  let isValid = mnemonic.isValid
  let seed = mnemonic.seed()
  ```

### HDWallet
- Implements BIP-32 hierarchical deterministic wallets.
- Derives keys from a seed and path.
- Methods/properties:
  - `init(seed: Data) throws`
  - `func derive(path: String) throws -> HDKey`
  - `func deriveAccount(index: UInt32, change: UInt32 = 0) throws -> HDKey`
  - `var seed: Data`
  - `var masterKey: HDKey`
- HDKey:
  - `init(seed: Data) throws`
  - `init(privateKey: Data, chainCode: Data) throws`
  - `func derive(path: String) throws -> HDKey`
  - `var privateKey: Data`
  - `var publicKey: Data`
  - `var chainCode: Data`
- Example:
  ```swift
  let hdWallet = try HDWallet(seed: seed)
  let hdKey = try hdWallet.derive(path: "m/44'/60'/0'/0/0")
  ```

### Address
- Handles Ethereum address creation and validation.
- Supports checksummed and hex formats.
- Methods/properties:
  - `init(data: Data) throws`
  - `init(hex: String) throws`
  - `init(publicKey: Data) throws`
  - `var data: Data`
  - `var hex: String`
  - `var checksummed: String`
  - `var isValid: Bool`
- Example:
  ```swift
  let address = try Address(hex: "0x...")
  let checksummed = address.checksummed
  ```

### Wallet
- Manages private/public keys and addresses.
- Instantiates from private key or mnemonic.
- Generates random private keys and mnemonics.
- Methods/properties:
  - `init(privateKey: Data) throws`
  - `init(mnemonic: Mnemonic, path: String = "m/44'/60'/0'/0/0") throws`
  - `init(mnemonicWords: [String], path: String = "m/44'/60'/0'/0/0") throws`
  - `var privateKey: Data`
  - `var publicKey: Data`
  - `var address: Address`
  - `var privateKeyHex: String`
  - `var publicKeyHex: String`
  - `var addressHex: String`
  - `var checksummedAddress: String`
  - `static func randomPrivateKey() throws -> Data`
  - `static func randomMnemonic() throws -> Mnemonic`
- Example:
  ```swift
  let wallet = try Wallet(privateKey: privateKey)
  let address = wallet.addressHex
  ```

### Keccak
- Provides keccak256 hashing.
- Methods:
  - `func keccak256(_ data: Data) -> Data`
- Example:
  ```swift
  let hash = keccak256(data)
  ```
