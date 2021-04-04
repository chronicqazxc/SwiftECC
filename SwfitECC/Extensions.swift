//
//  Extensions.swift
//  SwfitECC
//
//  Created by YuHan Hsiao on 2021/04/02.
//

import Foundation

extension Data {
    init(hex: String) {
        self.init(Array<UInt8>(hex: hex))
    }
    
    var bytes: [UInt8] {
        return Array(self)
    }

    func toHexString() -> String {
        return bytes.toHexString()
    }
}

extension Array where Element == UInt8 {
    init(hex: String) {
        self.init(reserveCapacity: hex.unicodeScalars.lazy.underestimatedCount)
        var buffer: UInt8?
        var skip = hex.hasPrefix("0x") ? 2 : 0
        for char in hex.unicodeScalars.lazy {
            guard skip == 0 else {
                skip -= 1
                continue
            }
            guard char.value >= 48 && char.value <= 102 else {
                removeAll()
                return
            }
            let v: UInt8
            let c: UInt8 = UInt8(char.value)
            switch c {
            case let c where c <= 57:
                v = c - 48
            case let c where c >= 65 && c <= 70:
                v = c - 55
            case let c where c >= 97:
                v = c - 87
            default:
                removeAll()
                return
            }
            if let b = buffer {
                append(b << 4 | v)
                buffer = nil
            } else {
                buffer = v
            }
        }
        if let b = buffer {
            append(b)
        }
    }
    
    init(reserveCapacity: Int) {
        self = []
        self.reserveCapacity(reserveCapacity)
    }

    func toHexString() -> String {
        return `lazy`.reduce("") {
            var s = String($1, radix: 16)
            if s.count == 1 {
                s = "0" + s
            }
            return $0 + s
        }
    }
}

extension String {
    var bytes: Array<UInt8> {
        return data(using: String.Encoding.utf8, allowLossyConversion: true)?.bytes ?? Array(utf8)
    }
}
