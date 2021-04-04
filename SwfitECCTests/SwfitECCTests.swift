//
//  SwfitECCTests.swift
//  SwfitECCTests
//
//  Created by YuHan Hsiao on 2021/04/02.
//

import XCTest
@testable import SwfitECC

class SwfitECCTests: XCTestCase {

    override func setUpWithError() throws {
        // Put setup code here. This method is called before the invocation of each test method in the class.
    }

    override func tearDownWithError() throws {
        // Put teardown code here. This method is called after the invocation of each test method in the class.
    }

    func testExample() throws {
        // This is an example of a functional test case.
        // Use XCTAssert and related functions to verify your tests produce the correct results.
    }

    func testPerformanceExample() throws {
        // This is an example of a performance test case.
        self.measure {
            // Put the code you want to measure the time of here.
        }
    }
    
    func testECHD() {
        let privateKey1 = "72d7b87886ff52d96793b65101ab87feaf1476a9a2e4736bd3ba4e94586a4f72"
        let ecc1 = ECC.eccFromPrivateKey(Data(hex: privateKey1), curve: .r1)
        let privateKey2 = "178f6a659a8364bac267f7e67947cf1e78e1365a67fff58a8b85988e8eb9c597"
        let ecc2 = ECC.eccFromPrivateKey(Data(hex: privateKey2), curve: .r1)
        let ecdh1 = ecc1.secp256r1ECDH(remotePublicKey: Data(ecc2.publicKey))
        let ecdh2 = ecc2.secp256r1ECDH(remotePublicKey: Data(ecc1.publicKey))
        XCTAssertEqual(ecdh1, ecdh2)
    }
}
