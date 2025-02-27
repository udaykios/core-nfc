//
//  NFCReader.swift
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

class NFCReaderViewModel: NSObject, ObservableObject, NFCTagReaderSessionDelegate {
    
    @Published var scanResult: String = "Tap the button to scan"
    @Published var status: String = ""
        private var session: NFCTagReaderSession?
    
    func startScanning() {
        guard NFCTagReaderSession.readingAvailable else {
            DispatchQueue.main.async {
                self.scanResult = "NFC reading not available"
            }
            return
        }
        
        session = NFCTagReaderSession(pollingOption: .iso14443, delegate: self)
        session?.alertMessage = "Hold your iPhone near the NFC tag"
        session?.begin()
    }
    
    func tagReaderSessionDidBecomeActive(_ session: NFCTagReaderSession) {
        print("NFC session started")
    }
  
    func readNFCFile(afterAuthenticating tag: NFCISO7816Tag) {
        let dna = DnaCommunicator()
        dna.trace = true
        dna.debug = true
        dna.tagConfiguration = TagConfiguration()
        dna.tag = tag

        dna.begin { error in
            if let error = error {
                print("Failed to initialize DNA: \(error.localizedDescription)")
                return
            }

            print("Authentication starting...")
            dna.authenticateEV2First(keyNum: 0) { success, authError in
                if !success || authError != nil {
                    print("Authentication failed: \(authError?.localizedDescription ?? "Unknown error")")
                    return
                }

                print("Authentication successful! Fetching file settings...")
              

                let fileNumber: UInt8 = 0x02  // Change this to match your actual file number
                self.fetchFileSettings(dna: dna, fileNumber: fileNumber)

            }
        }
    }

    func fetchFileSettings(dna: DnaCommunicator, fileNumber: UInt8) {
        dna.getFileSettings(fileNum: fileNumber) { settings, err in
            if let err = err {
                print("❌ Failed to get file settings: \(err.localizedDescription)")
                return
            }

            guard let settings = settings else {
                print("⚠️ File settings not found")
                return
            }

            print("✅ File Settings Retrieved:")
            print("  - File Number: \(fileNumber)")
            print("  - File Size: \(settings.fileSize ?? 0)")
            print("  - Communication Mode: \(settings.communicationMode)")
            print("  - readPermission Rights: \(settings.readPermission)")
            print("  - writePermission Rights: \(settings.writePermission)")
            
            
            
            let fileSize = settings.fileSize ?? 0
            if fileSize == 0 {
                print("❗ Invalid file size, aborting read.")
                return
            }
            //let newCommMode: UInt8 = 0x00 // Plain mode (0x00), MAC mode (0x01), or Enciphered (0x03)
            var newAccessRights = Data([0xEE, 0xEE]) // old access rights
            //let newAccessRights =  Data([0x00, 0xE0])    // new access rights
            print("keyDataClass.shared.macENCKey==\(keyDataClass.shared.macENCKey)===keyDataClass.shared.macKey\(keyDataClass.shared.macKey)======\(keyDataClass.shared.ti)")
            
            let requiresAuth = (settings.writePermission == Permission.KEY_0) // if it all false else true
            
            if requiresAuth {
                newAccessRights = Data([0xEE, 0xEE])
            } else {
                newAccessRights =  Data([0x00, 0xE0])
            }
            
            self.configureFileSettings(isoDep: dna.tag!,
                                       enc: Data(keyDataClass.shared.macENCKey),
                                       mac: Data(keyDataClass.shared.macKey),
                                       ti: Data(keyDataClass.shared.ti),
                                       requireAuth: requiresAuth,
                                       newFileAccess: newAccessRights) { result in
                switch result {
                case .success(let response):
                    if response.toHexString().hasPrefix("9100") {
                        self.session?.invalidate()
                        print("✅ File settings updated successfully! Response: \(response.toHexString())")
                        self.status = requiresAuth ?  "Write protection disabled" : "Write protection enabled"
                    }else {
                        self.session?.invalidate(errorMessage: "Authentication failed. Try again.")
                        print("❌ Failed to update file settings:\(response.toHexString())")
                    }
                case .failure(let error):
                    print("❌ Failed to update file settings: \(error.localizedDescription)")
                }
            }

          
        }
    }
    func updateFileSettings(dna: DnaCommunicator, fileNumber: UInt8, newFileAccess: [UInt8], completion: @escaping (Error?) -> Void) {
        let finalCommand: [UInt8] = [fileNumber] + [0x90, 0x5F, 0x00, 0x00, 0x04, 0x02, 0x00] + newFileAccess + [0x00]

        dna.nxpMacCommand(command: finalCommand[1], header: Array(finalCommand[2...6]), data: Array(finalCommand[7...])) { result, err in
            if let err = err {
                print("❌ Failed to update file settings: \(err.localizedDescription)")
                completion(err)
            } else {
                print("✅ File settings updated successfully!===\(result)")
                completion(nil)
            }
        }
    }
    
   
    func configureFileSettings(
        isoDep: NFCISO7816Tag,
        enc: Data,
        mac: Data,
        ti: Data,
        requireAuth: Bool,
        newFileAccess: Data,
        completion: @escaping (Result<Data, Error>) -> Void
    ) {
        let fileAccess = newFileAccess

        if requireAuth {
            let cmd: [UInt8] = [0x5F]
            let cmdHeader: [UInt8] = [0x02]
            let cmdCtr: [UInt8] = [0x01, 0x00]
            let padding: [UInt8] = [0x80]

            let ivInput = Data([0xA5, 0x5A]) + ti + Data(cmdCtr) + Data(repeating: 0x00, count: 8)
            guard let iv = aesEcbEncryptFF(plainText: ivInput, key: enc) else {
               // completion(.failure(NFCError.invalidEncryption))
                return
            }
            let cmdData = Data([0x00]) + fileAccess
            let paddedCmdData = padTo16Bytes(data: cmdData + Data(padding))
            
            guard let eIv = encryptAESFF(input: paddedCmdData, key: enc, iv: iv) else {
              //  completion(.failure(NFCError.invalidEncryption))
                return
            }

            let combinedCmdEIv = Data(cmd) + Data(cmdCtr) + ti + Data(cmdHeader) + eIv

            guard let macCombinedCmdEIv = aesCMACEncryptFF(data: combinedCmdEIv, key: mac) else {
              //  completion(.failure(NFCError.invalidMac))
                return
            }
            let macT = Data(macCombinedCmdEIv).enumerated().filter { $0.offset % 2 != 0 }.map { $0.element }

            let finalCmd: [UInt8] = [0x90, 0x5F, 0x00, 0x00, UInt8(eIv.count + macT.count + 1), 0x02] + eIv + macT + [0x00]

            isoDep.sendCommand(apdu: NFCISO7816APDU(data: Data(finalCmd))!) { response, sw1, sw2, error in
                if let error = error {
                    completion(.failure(error))
                } else {
                    let responseData = Data([sw1, sw2]) + response
                    completion(.success(responseData))
                }
            }
        } else {
         //   90F5000009026597A457C8CD442C00 905F0000190261B6D97903566E84C3AE5274467E89EAD799 B7C1A0EF7A0400
            let finalCmd: [UInt8] = [0x90, 0x5F, 0x00, 0x00, 0x04, 0x02, 0x00] + newFileAccess + [0x00]

            isoDep.sendCommand(apdu: NFCISO7816APDU(data: Data(finalCmd))!) { response, sw1, sw2, error in
                if let error = error {
                    completion(.failure(error))
                } else {
                    let responseData = Data([sw1, sw2]) + response
                    completion(.success(responseData))
                }
            }
        }
    }
    func aesEcbEncryptFF(plainText: Data, key: Data) -> Data? {
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
    func encryptAESFF(input: Data, key: Data, iv: Data) -> Data? {
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
    func aesCMACEncryptFF(data: Data, key: Data) -> Data? { //latest
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
    func aesEcbEncrypt(data: Data, key: Data) -> Data? {
        let keySymmetric = SymmetricKey(data: key)
        let encrypted = try? AES.GCM.seal(data, using: keySymmetric).combined
        return encrypted
    }
    private func encryptAES_CBC(data: Data, key: Data, iv: Data) -> Data? {
        return cryptAES(operation: CCOperation(kCCEncrypt), data: data, key: key, iv: iv)
    }
    
    private func decryptAES_CBC(data: Data, key: Data, iv: Data) -> Data? {
        return cryptAES(operation: CCOperation(kCCDecrypt), data: data, key: key, iv: iv)
    }
    
    private func cryptAES(operation: CCOperation, data: Data, key: Data, iv: Data) -> Data? {
        guard key.count == kCCKeySizeAES128 else { return nil }
        guard iv.count == kCCBlockSizeAES128 else { return nil }
        
        let bufferSize = data.count + kCCBlockSizeAES128
        var buffer = Data(count: bufferSize)
        var numBytesProcessed: size_t = 0
        
        let status = buffer.withUnsafeMutableBytes { bufferBytes in
            data.withUnsafeBytes { dataBytes in
                key.withUnsafeBytes { keyBytes in
                    iv.withUnsafeBytes { ivBytes in
                        CCCrypt(
                            operation, CCAlgorithm(kCCAlgorithmAES), 0,
                            keyBytes.baseAddress, key.count, ivBytes.baseAddress,
                            dataBytes.baseAddress, data.count,
                            bufferBytes.baseAddress, bufferSize, &numBytesProcessed
                        )
                    }
                }
            }
        }
        
        guard status == kCCSuccess else { return nil }
        return buffer.prefix(numBytesProcessed)
    }
    func encryptAES(data: Data, key: Data, iv: Data) -> Data? {
        let keySymmetric = SymmetricKey(data: key)
        let sealedBox = try? AES.GCM.seal(data, using: keySymmetric, nonce: AES.GCM.Nonce(data: iv))
        return sealedBox?.combined
    }
    func padTo16Bytes(data: Data) -> Data {
        let paddingSize = 16 - (data.count % 16)
        return data + Data(repeating: 0x00, count: paddingSize)
    }
    func cMacEncryptF(data: Data, key: Data) -> Data? {
        let blockSize = kCCBlockSizeAES128 // 16 bytes
        let zeroIV = Data(repeating: 0x00, count: blockSize)
        
        guard let l = aesEncryptBlock(block: zeroIV, key: key) else { return nil }
        
        // Generate subkeys K1 and K2
        let k1 = generateSubkey(l)
        let k2 = generateSubkey(k1)
        
        // Padding
        var dataPadded = data
        if data.count % blockSize == 0 {
            dataPadded = xorOperation(data1: dataPadded, data2: k1)
        } else {
            let padding = Data([0x80] + [UInt8](repeating: 0x00, count: blockSize - (data.count % blockSize) - 1))
            dataPadded.append(padding)
            dataPadded = xorOperation(data1: dataPadded, data2: k2)
        }
        
        // Final CMAC calculation (AES-CBC with zero IV)
        return aesEncryptBlock(block: dataPadded, key: key)
    }
    func generateSubkey(_ data: Data) -> Data {
        let blockSize = kCCBlockSizeAES128
        let msb = data.first! & 0x80 != 0
        var subkey = data.dropFirst() + [0x00] // Left shift by 1 bit
        
        if msb {
            subkey[subkey.count - 1] ^= 0x87 // XOR with the Rb constant
        }
        return Data(subkey)
    }
    func xorOperation(data1: Data, data2: Data) -> Data {
        return Data(zip(data1, data2).map { $0 ^ $1 })
    }
    
    /// Encrypts a 16-byte block using AES-128 (CBC mode with a zero IV)

    func aesEncryptBlock(block: Data, key: Data) -> Data? {
        let blockSize = kCCBlockSizeAES128 // 16 bytes

        // ✅ Ensure key is 16 bytes
//        guard key.count == blockSize else {
//            print("❌ AES encryption failed: Key size is \(key.count) bytes, expected 16")
//            return nil
//        }
//
//        // ✅ Ensure block is 16 bytes
//        guard block.count == blockSize else {
//            print("❌ AES encryption failed: Block size is \(block.count) bytes, expected 16")
//            return nil
//        }

        var encryptedData = Data(count: blockSize)
        var numBytesEncrypted: size_t = 0

        let status = encryptedData.withUnsafeMutableBytes { encryptedBytes in
            block.withUnsafeBytes { blockBytes in
                key.withUnsafeBytes { keyBytes in
                    CCCrypt(
                                        CCOperation(kCCEncrypt),
                                        CCAlgorithm(kCCAlgorithmAES),
                                        CCOptions(kCCOptionECBMode), // No padding for CMAC
                                        keyBytes.baseAddress?.assumingMemoryBound(to: UInt8.self), key.count,
                                        nil, // No IV for ECB mode
                                        blockBytes.baseAddress?.assumingMemoryBound(to: UInt8.self), blockSize,
                                        encryptedBytes.baseAddress?.assumingMemoryBound(to: UInt8.self), blockSize,
                                        &numBytesEncrypted
                                    )
                }
            }
        }

        // ✅ Check if CCCrypt was successful
        guard status == kCCSuccess else {
            print("❌ AES encryption failed: CCCrypt returned status \(status)")
            return nil
        }

        print("✅ AES encryption successful: \(encryptedData.map { String(format: "%02X", $0) }.joined())")
        return encryptedData
    }


    
    func tagReaderSession(_ session: NFCTagReaderSession, didDetect tags: [NFCTag]) {
        guard let tag = tags.first else {
            session.invalidate(errorMessage: "No tag detected")
            return
        }
        
        session.connect(to: tag) { error in
            if let error = error {
                session.invalidate(errorMessage: "Connection failed: \(error.localizedDescription)")
                return
            }
            
            if case let .iso7816(isoTag) = tag {
                print("Tag detected: \(isoTag)")
                self.readNFCFile(afterAuthenticating: isoTag) //
            }
                else {
                session.invalidate(errorMessage: "Unsupported tag type")
            }
        }
    }
    
    func tagReaderSession(_ session: NFCTagReaderSession, didInvalidateWithError error: Error) {
        DispatchQueue.main.async {
            self.scanResult = "Session ended: \(error.localizedDescription)"
        }
    }
}






class keyDataClass: ObservableObject {
    static  var shared = keyDataClass()
    @Published var macKey = [UInt8]()
    @Published var macENCKey = [UInt8]()
    @Published var ti = [UInt8]()
}
