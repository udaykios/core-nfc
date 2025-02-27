//
//  ContentView.swift
//  DNAKIT
//
//  Created by Quin Design on 25/02/25.
//

import SwiftUI
import CoreNFC
import CryptoSwift
import CommonCrypto
import CryptoKit
import OpenSSL

struct NFCReaderView: View {
    @StateObject private var viewModel = NFCReaderViewModel()
    
    var body: some View {
        VStack(spacing: 20) {
            
            Text(viewModel.status)
                .bold()
                .padding()
                .multilineTextAlignment(.center)
            
            Text(viewModel.scanResult)
                .padding()
                .multilineTextAlignment(.center)
            
            Button(action: {
                viewModel.startScanning()
            }) {
                Text("Scan NFC Tag")
                    .font(.headline)
                    .padding()
                    .frame(maxWidth: .infinity)
                    .background(Color.blue)
                    .foregroundColor(.white)
                    .clipShape(RoundedRectangle(cornerRadius: 10))
            }
            .padding()
        }
        .padding()
        .onAppear{
            /*
            let KSesAuthENC = "1309C877509E5A215007FF0ED19CA564"
            let A55A = "A55A"
            let ti = "9D00C4DF"
            let cmdctr = "0100"
            let data = "0000000000000000"

            // Convert hex strings to Data
            guard let keyData = hexStringToData(KSesAuthENC),
                  let plainTextData = hexStringToData(A55A + ti + cmdctr + data) else {
                print("Invalid hex input")
                exit(1)
            }

            // Perform AES Encryption
            if let encryptedData = aesEcbEncrypt(plainText: plainTextData, key: keyData) {
                let encryptedHex = encryptedData.map { String(format: "%02X", $0) }.joined()
                print("Encrypted Output: \(encryptedHex)") // Should print: 3E27082AB2ACC1EF55C57547934E9962
            } else {
                print("Encryption failed")
            }
            
           let ivc = "3E27082AB2ACC1EF55C57547934E9962"
           let cmddata = "4000E0C1F121200000430000430000"
           let paading = "80"
            
            
            let kSesAuthMAC = "4C6626F5E72EA694202139295C7A7FC7"
            let cmdCounter = "0100"
            //let ti = "9D00C4DF"
            let cmd = "5F"
            let cmdHeader = "02"
            
            let ivElv = "61B6D97903566E84C3AE5274467E89EA"

            // Concatenate command data
            let combinedCmdEIvHex = cmd + cmdCounter + ti + cmdHeader + ivElv

            // Convert hex strings to Data
            guard let keyData = hexStringToData(kSesAuthMAC),
                  let combinedData = hexStringToData(combinedCmdEIvHex) else {
                print("Invalid hex input")
                exit(1)
            }

            // Perform AES CMAC Encryption
            
            let padding = "80"
            
            let ip = cmddata + paading
            guard let input = hexStringToData(ip),
                  let key = hexStringToData(KSesAuthENC),
                  let ivv =  hexStringToData(ivElv)
            else {
                print("Invalid hex input")
                exit(1)
            }
            
            if let macOutput = encryptAES(input: input, key: key, iv: ivv){
                let macHex = macOutput.map { String(format: "%02X", $0) }.joined()
                print("CMAC Output: \(macHex)") // Expected: 61B6D97903566E84C3AE5274467E89EA
            } else {
                print("CMAC Encryption failed")
            }
            
            
            if let macOutputs = aesCMACEncrypt(data: combinedData, key: keyData){
                let macHex = macOutputs.map { String(format: "%02X", $0) }.joined()
                print("CMAC Output: \(macHex)") // Expected: 7BD75F991CB7A2C18DA09EEF047A8D04
            } else {
                print("CMAC Encryption failed")
            }
             */
        }
        
    }

    func encryptAES(input: Data, key: Data, iv: Data) -> Data? {
        guard key.count == kCCKeySizeAES128 || key.count == kCCKeySizeAES192 || key.count == kCCKeySizeAES256 else { return nil }
        guard iv.count == kCCBlockSizeAES128 else { return nil }

        let dataLength = input.count
        let bufferSize = dataLength + kCCBlockSizeAES128
        var buffer = Data(count: bufferSize)
        
        var numBytesEncrypted: size_t = 0
        
        let cryptStatus = buffer.withUnsafeMutableBytes { bufferBytes in
            input.withUnsafeBytes { inputBytes in
                key.withUnsafeBytes { keyBytes in
                    iv.withUnsafeBytes { ivBytes in
                        CCCrypt(
                            CCOperation(kCCEncrypt),
                            CCAlgorithm(kCCAlgorithmAES),
                            CCOptions(0),
                            keyBytes.baseAddress, key.count,
                            ivBytes.baseAddress,
                            inputBytes.baseAddress, dataLength,
                            bufferBytes.baseAddress, bufferSize,
                            &numBytesEncrypted
                        )
                    }
                }
            }
        }
        
        guard cryptStatus == kCCSuccess else { return nil }
        return buffer.prefix(numBytesEncrypted)
    }

    func hexStringToData(_ hex: String) -> Data? {
        var data = Data()
        var hexStr = hex
        if hexStr.count % 2 != 0 { return nil } // Ensure even-length hex string

        while hexStr.count > 0 {
            let subIndex = hexStr.index(hexStr.startIndex, offsetBy: 2)
            let byteString = String(hexStr[..<subIndex])
            hexStr = String(hexStr[subIndex...])
            if let byte = UInt8(byteString, radix: 16) {
                data.append(byte)
            } else {
                return nil
            }
        }
        return data
    }
    func aesCMACEncrypt(data: Data, key: Data) -> Data? { //latest
        guard key.count == 16 else {
            print("Key must be 16 bytes for AES-128 CMAC.")
            return nil
        }

        var context = CMAC_CTX_new()
        defer { CMAC_CTX_free(context) }

        var mac = [UInt8](repeating: 0, count: 16)
        var macLength: size_t = 0

        key.withUnsafeBytes { keyBytes in
            CMAC_Init(context, keyBytes.baseAddress, key.count, EVP_aes_128_cbc(), nil)
            data.withUnsafeBytes { dataBytes in
                CMAC_Update(context, dataBytes.baseAddress, data.count)
            }
            CMAC_Final(context, &mac, &macLength)
        }

        return Data(mac.prefix(macLength))
    }
    func aesCmacEncryptf(data: Data, key: Data) -> Data? {
        do {
            let cmac = try CMAC(key: key.bytes).authenticate(data.bytes)
            return Data(cmac)
        } catch {
            print("CMAC Encryption Error: \(error)")
            return nil
        }
    }
    func aesEcbEncrypt(plainText: Data, key: Data) -> Data? {
        let keyLength = kCCKeySizeAES128 // Adjust as needed (AES-128, AES-192, AES-256)
        guard key.count == keyLength else { return nil }

        let dataLength = plainText.count
        let bufferSize = dataLength + kCCBlockSizeAES128
        var buffer = Data(count: bufferSize)

        var numBytesEncrypted: size_t = 0
        let status = buffer.withUnsafeMutableBytes { bufferBytes in
            plainText.withUnsafeBytes { plainTextBytes in
                key.withUnsafeBytes { keyBytes in
                    CCCrypt(
                        CCOperation(kCCEncrypt),
                        CCAlgorithm(kCCAlgorithmAES),
                        CCOptions(kCCOptionECBMode | kCCOptionECBMode),
                        keyBytes.baseAddress, keyLength,
                        nil, // No IV for ECB mode
                        plainTextBytes.baseAddress, dataLength,
                        bufferBytes.baseAddress, bufferSize,
                        &numBytesEncrypted
                    )
                }
            }
        }

        guard status == kCCSuccess else { return nil }
        return buffer.prefix(numBytesEncrypted)
    }
}
