import Foundation

private let keccak256RoundConstants: [UInt64] = [
    0x0000000000000001, 0x0000000000008082, 0x800000000000808A, 0x8000000080008000,
    0x000000000000808B, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
    0x000000000000008A, 0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
    0x000000008000808B, 0x800000000000008B, 0x8000000000008089, 0x8000000000008003,
    0x8000000000008002, 0x8000000000000080, 0x000000000000800A, 0x800000008000000A,
    0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008
]

private func rotl(_ x: UInt64, _ n: UInt64) -> UInt64 {
    (x << n) | (x >> (64 - n))
}

public func keccak256(_ data: Data) -> Data {
    var state = [UInt64](repeating: 0, count: 25)
    let rate = 136
    let capacity = 64
    let outputLength = 32
    var padded = data + Data([0x01])
    while padded.count % rate != rate - 1 { padded.append(0) }
    padded.append(0x80)
    for chunk in stride(from: 0, to: padded.count, by: rate) {
        for i in 0..<(rate/8) {
            let sub = padded.subdata(in: chunk + i*8 ..< chunk + (i+1)*8)
            state[i] ^= UInt64(littleEndian: sub.withUnsafeBytes { $0.load(as: UInt64.self) })
        }
        for round in 0..<24 {
            var c = [UInt64](repeating: 0, count: 5)
            for x in 0..<5 { c[x] = (0..<5).reduce(0) { $0 ^ state[x + 5*$1] } }
            for x in 0..<5 {
                let d = c[(x+4)%5] ^ rotl(c[(x+1)%5], 1)
                for y in 0..<5 { state[x+5*y] ^= d }
            }
            var b = [UInt64](repeating: 0, count: 25)
            for x in 0..<5 {
                for y in 0..<5 {
                    b[y + 5*((2*x+3*y)%5)] = rotl(state[x+5*y], UInt64([0,1,62,28,27,36,44,6,55,20,3,10,43,25,39,41,45,15,21,8,18,2,61,56,14][x+5*y]))
                }
            }
            for x in 0..<5 {
                for y in 0..<5 {
                    state[x+5*y] = b[x+5*y] ^ ((~b[((x+1)%5)+5*y]) & b[((x+2)%5)+5*y])
                }
            }
            state[0] ^= keccak256RoundConstants[round]
        }
    }
    var out = Data()
    for i in 0..<(outputLength/8) {
        out.append(Data(from: state[i].littleEndian))
    }
    return out.prefix(outputLength)
}

private extension Data {
    init(from value: UInt64) {
        var v = value
        self.init(bytes: &v, count: 8)
    }
} 