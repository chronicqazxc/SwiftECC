//
//  ECC.swift
//  SwfitECC
//
//  Created by YuHan Hsiao on 2021/04/02.
//

import Foundation
import openssl

class ECC {
    internal var privateKey: [UInt8]
    internal var publicKey: [UInt8]
    internal var ecckeydata :Data
    
    static func generate(_ type: CurveType) -> ECC {
        var publicKeySec, privateKeySec: SecKey?
        let keyattribute = [
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits as String : 256
            ] as CFDictionary
        SecKeyGeneratePair(keyattribute, &publicKeySec, &privateKeySec)

        var error: Unmanaged<CFError>?
        let keyData = SecKeyCopyExternalRepresentation(privateKeySec!, &error)
        let data = keyData! as Data
        
        var privateKeyBytes = data.bytes
        privateKeyBytes.removeFirst()
        let pointSize = privateKeyBytes.count / 3
        let dBytes = privateKeyBytes[pointSize*2..<pointSize*3]
        return eccFromPrivateKey(Data(dBytes), curve: type)
    }

    public class func eccFromPrivateKey(_ privateKey: Data, curve: CurveType) -> ECC {
        let privKeyBN = BN_new()!
        let key = EC_KEY_new()
        let ctx = BN_CTX_new()

        var curveName: Int32
        switch curve {
        case .r1:
            curveName = NID_X9_62_prime256v1
        case .k1:
            curveName = NID_secp256k1
        }

        let group = EC_GROUP_new_by_curve_name(curveName)
        EC_KEY_set_group(key, group)

        var recoveredPubKeyHex = ""
        privateKey.withUnsafeBytes { rawBufferPointer in
            let bufferPointer = rawBufferPointer.bindMemory(to: UInt8.self)
            guard let pkbytes = bufferPointer.baseAddress else {
                return
            }

            BN_bin2bn(pkbytes, Int32(privateKey.count), privKeyBN)
            EC_KEY_set_private_key(key, privKeyBN)
            let pubKeyPoint = EC_POINT_new(group)
            EC_POINT_mul(group, pubKeyPoint, privKeyBN, nil, nil, ctx)

            let xBN = BN_new()!
            let yBN = BN_new()!
            EC_POINT_get_affine_coordinates_GFp(group, pubKeyPoint, xBN, yBN, nil)

            let xBNHex = BNToHexString(bignum: xBN)
            let yBNHex = BNToHexString(bignum: yBN)

            BN_free(xBN)
            BN_free(yBN)
            EC_POINT_free(pubKeyPoint)
            recoveredPubKeyHex = "04" + xBNHex + yBNHex
        }
        EC_GROUP_free(group)
        BN_CTX_free(ctx)
        EC_KEY_free(key)
        BN_free(privKeyBN)
        
        return ECC(ecckeydata: Data(hex: recoveredPubKeyHex) + privateKey)
    }

    private class func BNToHexString(bignum: UnsafeMutablePointer<BIGNUM>) -> String {
        let bnstr = BN_bn2hex(bignum)!
        let hex = String(cString: bnstr)
        let pad = max(64, hex.count)
        let padded = String(repeatElement("0", count: pad - hex.count) + hex)
        CRYPTO_free(bnstr)
        return padded
    }
    
    private init(ecckeydata: Data) {
        self.ecckeydata = ecckeydata
        var privateKeyBytes = ecckeydata.bytes
        privateKeyBytes.removeFirst()
        let pointSize = privateKeyBytes.count / 3
        let xBytes = privateKeyBytes[0..<pointSize]
        let yBytes = privateKeyBytes[pointSize..<pointSize*2]
        let dBytes = privateKeyBytes[pointSize*2..<pointSize*3]
        self.privateKey  = Array(dBytes)
        self.publicKey = Array(xBytes+yBytes)
    }
    
    func secp256r1ECDH(remotePublicKey: Data) -> [UInt8] {
        let publicKey = Data.init(hex: "04")
        let remotePublicSecKey = SecKeyCreateWithData(publicKey + remotePublicKey as CFData, [
            kSecAttrKeyType as String: kSecAttrKeyTypeEC,
            kSecAttrKeyClass as String: kSecAttrKeyClassPublic,
            SecKeyKeyExchangeParameter.requestedSize.rawValue as String: 64
            ] as CFDictionary, nil)!
        
        let privateSecKey = SecKeyCreateWithData(ecckeydata as CFData, [
            kSecAttrKeyType as String: kSecAttrKeyTypeEC,
            SecKeyKeyExchangeParameter.requestedSize.rawValue as String: 32,
            kSecAttrKeyClass as String: kSecAttrKeyClassPrivate,
            ] as CFDictionary, nil)!
        
        var error: Unmanaged<CFError>?
        let keyPairAttr:[String : Any] = [:]

        let sharedSecret = SecKeyCopyKeyExchangeResult(privateSecKey, SecKeyAlgorithm.ecdhKeyExchangeStandard, remotePublicSecKey, keyPairAttr as CFDictionary, &error)
        let bytes = [UInt8](sharedSecret! as Data)
        return bytes
    }
}

public enum CurveType: String {
    case r1 = "R1"
    case k1 = "K1"
    public init(_ curve: String) throws {
        switch curve.uppercased() {
        case "R1":
            self = .r1
        case "K1":
            self = .k1
        default:
            self = .k1
            break
        }
    }
}
