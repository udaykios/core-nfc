//
//  DNACommunicator.swift
//  DNAKIT
//
//  Created by Quin Design on 25/02/25.
//

import Foundation
import CoreNFC
import CryptoSwift

public struct NxpCommandResult {
    var data: [UInt8]
    var statusMajor: UInt8
    var statusMinor: UInt8
    
    static func emptyResult() -> NxpCommandResult {
        return NxpCommandResult(data: [], statusMajor: 0, statusMinor: 0)
    }
}

public class DnaCommunicator {
    public var tag: NFCISO7816Tag?
    public var tagConfiguration: TagConfiguration?
    public var activeKeyNumber: UInt8 = 0
    var activeTransactionIdentifier: [UInt8] = [0,0,0,0]
    var commandCounter: Int = 0
    var sessionEncryptionMode: EncryptionMode?
    
    public var trace: Bool = false
    public var debug: Bool = false
    
    // Should move these somewhere else
    public static let SELECT_MODE_ANY: UInt8 = 0x00
    public static let SELECT_MODE_CHILD_DF: UInt8 = 0x01
    public static let SELECT_MODE_CHILD_EF: UInt8 = 0x02
    public static let SELECT_MODE_PARENT_DF: UInt8 = 0x03
    public static let SELECT_MODE_NAME: UInt8 = 0x04

    public static let CC_FILE_NUMBER: UInt8 = 0x01
    public static let CC_FILE_ID: Int = 0xe103
    public static let NDEF_FILE_NUMBER: UInt8 = 0x02
    public static let NDEF_FILE_ID: Int = 0xe104
    public static let DATA_FILE_NUMBER: UInt8 = 0x03
    public static let DATA_FILE_ID: Int = 0xe105
    public static let PICC_FILE_ID: Int = 0x3f00
    public static let DF_FILE_ID: Int = 0xe110
    public static let DF_NAME: [UInt8] = [0xD2, 0x76, 0x00, 0x00, 0x85, 0x01, 0x01]

    public init() {
        
    }
    
    func debugPrint(_ value: String) {
        if debug {
            print(value)
        }
    }
    
    func makeErrorIfNotExpectedStatus(_ result: NxpCommandResult, error: Error? = nil) -> Error? {
        if result.statusMajor != 0x91 || (result.statusMinor != 0x00 && result.statusMinor != 0xaf) {
            return Helper.makeError(102, "Unexpected status: \(String(format:"%02X", result.statusMajor)) / \(String(format:"%02X", result.statusMinor))")
        }
        return nil
    }
    
    func getRandomBytes(ofLength: Int) -> [UInt8] {
        return Helper.randomBytes(ofLength: ofLength)
    }
    
    func isoTransceive(packet: [UInt8], completion: @escaping (NxpCommandResult, Error?) -> Void) {
        let data = Helper.dataFromBytes(bytes: packet)
        let apdu = NFCISO7816APDU(data: data)
        Helper.logBytes("Outbound", packet)

        if let apdu = apdu {
            tag!.sendCommand(apdu: apdu) {data, sw1, sw2, err in
                let bytes = Helper.bytesFromData(data: data)
                let result = NxpCommandResult(data: bytes, statusMajor: sw1, statusMinor: sw2)
                if self.trace {
                    Helper.logBytes("Inbound", bytes + [sw1] + [sw2])
                }
                if err != nil {
                    self.debugPrint("An error occurred: \(String(describing: err))")
                }
                completion(result, err)
            }
        } else {
            debugPrint("APDU Failure: Attempt")
            
            completion(NxpCommandResult.emptyResult(), Helper.makeError(100, "APDU Failure"))
        }
    }
            
    func nxpNativeCommand(command: UInt8, header: [UInt8], data: [UInt8]?, macData: [UInt8]? = nil, completion: @escaping (NxpCommandResult, Error?) -> Void) {
        let data = data ?? [UInt8]()
        var packet: [UInt8] = [
            0x90,
            command,
            0x00,
            0x00,
            UInt8(header.count + data.count + (macData?.count ?? 0))
        ]
        packet.append(contentsOf: header)
        packet.append(contentsOf: data)
        if let macData = macData {
            packet.append(contentsOf: macData)
        }
        packet.append(0x00)
        
        isoTransceive(packet: packet) { result, err in
            completion(result, err)
        }
    }
    
    public func nxpPlainCommand(command: UInt8, header: [UInt8], data: [UInt8]?, completion: @escaping (NxpCommandResult, Error?) -> Void) {
        nxpNativeCommand(command: command, header: header, data: data) {result, err in
            self.commandCounter += 1
            completion(result, err)
        }
    }
    
    public func nxpMacCommand(command: UInt8, header: [UInt8], data: [UInt8]?, completion: @escaping (NxpCommandResult, Error?) -> Void) {
        let data = data ?? [UInt8]()
        var macInputData: [UInt8] = [
            command,
            UInt8(commandCounter % 256), UInt8(commandCounter / 256),
            activeTransactionIdentifier[0], activeTransactionIdentifier[1], activeTransactionIdentifier[2], activeTransactionIdentifier[3],
        ]
        macInputData.append(contentsOf: header)
        macInputData.append(contentsOf: data)
        let macData = sessionEncryptionMode!.generateMac(message: macInputData)
        
        nxpNativeCommand(command: command, header: header, data: data, macData: macData) { result, err in
            self.commandCounter += 1
            if result.data.count < 8 {
                // No MAC available for this command
                let noDataResult = NxpCommandResult(data: [UInt8](), statusMajor: result.statusMajor, statusMinor: result.statusMinor)

                completion(noDataResult, err)
                return
            }
            
            let dataBytes = (result.data.count > 8) ? result.data[0...(result.data.count - 9)] : []
            let macBytes = result.data[(result.data.count - 8)...(result.data.count - 1)]
            
            // Check return MAC
            var returnMacInputData: [UInt8] = [
                result.statusMinor,
                UInt8(self.commandCounter % 256), UInt8(self.commandCounter / 256),
                self.activeTransactionIdentifier[0], self.activeTransactionIdentifier[1], self.activeTransactionIdentifier[2], self.activeTransactionIdentifier[3],
            ]
            returnMacInputData.append(contentsOf: dataBytes)
            let returnMacData = self.sessionEncryptionMode!.generateMac(message: returnMacInputData)
            
            let finalResult = NxpCommandResult(data: [UInt8](dataBytes), statusMajor: result.statusMajor, statusMinor: result.statusMinor)
            
            if !returnMacData.elementsEqual(macBytes) {
                self.debugPrint("Invalid MAC! (\(returnMacData)) / (\(macBytes)")
                completion(finalResult, Helper.makeError(101, "Invalid MAC"))
                return
            }
            
            completion(finalResult, nil)
        }
    }
    
    public func nxpEncryptedCommand(command: UInt8, header: [UInt8], data: [UInt8]?, completion: @escaping (NxpCommandResult, Error?) -> Void) {
        let data = data ?? [UInt8]()
        if trace {
            Helper.logBytes("Unencryped outgoing data", data)
        }
        let encryptedData = data.count == 0 ? [UInt8]() : sessionEncryptionMode!.encryptData(message: data)
        nxpMacCommand(command: command, header: header, data: encryptedData) {result, err in
            let decryptedResultData = result.data.count == 0 ? [UInt8]() : self.sessionEncryptionMode!.decryptData(message: result.data)
            let finalResult = NxpCommandResult(data: decryptedResultData, statusMajor: result.statusMajor, statusMinor: result.statusMinor)
            if self.trace {
                Helper.logBytes("Unencrypted incoming data", finalResult.data)
            }
            completion(finalResult, err)
        }
    }
    
    public func nxpSwitchedCommand(mode: CommuncationMode, command: UInt8, header: [UInt8], data: [UInt8], completion: @escaping (NxpCommandResult, Error?) -> Void) {
        if mode == CommuncationMode.FULL {
            nxpEncryptedCommand(command: command, header: header, data: data) { result, err in
                completion(result, err)
            }
        } else if mode == CommuncationMode.MAC {
            nxpMacCommand(command: command, header: header, data: data) { result, err in
                    completion(result, err)
            }
        } else {
            nxpPlainCommand(command: command, header: header, data: data) { result, err in
                    completion(result, err)
            }
        }
    }
    
    public func isoSelectFileByFileId(mode: UInt8, fileId: Int, completion: @escaping (Error?) -> Void) {
        let packet: [UInt8] = [
            0x00, // class
            0xa4, // ISOSelectFile
            0x00, // select by file identifier (1, 2, 3, and 4 have various meanings as well)
            0x0c, // Don't return FCI
            0x02, // Length of file identifier
            UInt8(fileId / 256),  // File identifier
            UInt8(fileId % 256),
            0x00 // Length of expected response
        ]
        
        isoTransceive(packet: packet) { result, err in
            completion(err)
        }
    }
    
    public func begin(completion: @escaping (Error?) -> Void) {
        // Looks like iOS has already selected the application
        // This is required on Android but fails on iOS,
        // so we're keeping the API but skipping the actual behavior
        /*
        isoSelectFileByFileId(mode: SELECT_MODE_CHILD_DF, fileId: DF_FILE_ID) { err in
            completion(err)
        }
         */
        completion(nil)
    }
    
    public func writeTagConfiguration(tagConfiguration: TagConfiguration, completion: @escaping (Error?) -> Void) {
        
    }
}

public extension DnaCommunicator {
    func authenticateEV2First(keyNum: UInt8, keyData: [UInt8]? = nil, completion: @escaping (Bool, Error?) -> Void) -> Void {
        guard let keyData = keyData ?? tagConfiguration?.keys[Int(keyNum)] else { completion(false, nil); return }
        
        // STAGE 1 Authentication (pg. 46)
        nxpNativeCommand(command: 0x71, header: [keyNum, 0x00], data: []) { result, err in
            
            if err != nil {
                self.debugPrint("Err: \(String(describing: err))")
                completion(false, err)
                return
            }
            
            if(result.statusMajor != 0x91) {
                self.debugPrint("Wrong status Major")
                completion(false, Helper.makeError(103, "Wrong status major: \(result.statusMajor)"))
                return
            }
            
            if(result.statusMinor == 0xad) {
                self.debugPrint("Requested retry")
                // Unsure - retry? pg. 52
                completion(false, Helper.makeError(104, "Don't know how to handle retries"))
                return
            }
            
            if(result.statusMinor != 0xaf) {
                self.debugPrint("Bad status minor: \(result.statusMinor)")
                completion(false, Helper.makeError(105, "Wrong status minor: \(result.statusMinor)"))
                return
            }
            
            if(result.data.count != 16) {
                self.debugPrint("Incorrect data count")
                completion(false, Helper.makeError(106, "Incorrect data size"))
                return
            }
            
            let encryptedChallengeB = result.data
            let challengeB = Helper.simpleAesDecrypt(key: keyData, data: encryptedChallengeB)
            let challengeBPrime = Helper.rotateLeft(Array(challengeB[0...]))
            let challengeA = self.getRandomBytes(ofLength: 16)
            self.debugPrint("Challenge A: \(challengeA)")
            let combinedChallenge = Helper.simpleAesEncrypt(key: keyData, data: (challengeA + challengeBPrime))
            
            // STAGE 2 (pg. 47)
            self.nxpNativeCommand(command: 0xaf, header: combinedChallenge, data: nil) {innerResult, err in
                
                if err != nil {
                    completion(false, err)
                    return
                }
                
                if innerResult.statusMajor != 0x91 {
                    completion(false, Helper.makeError(107, "Bad status major"))
                    return
                }
                
                if(innerResult.statusMinor != 0x00) {
                    completion(false, Helper.makeError(108, "Bad status minor"))
                    return
                }
                
                let resultData = Helper.simpleAesDecrypt(key: keyData, data: innerResult.data)
                let ti = Array(resultData[0...3])
                let challengeAPrime = Array(resultData[4...19])
                let pdCap = resultData[20...25]
                let pcCap = resultData[26...31]
                let newChallengeA = Helper.rotateRight(challengeAPrime)
                
                if !newChallengeA.elementsEqual(challengeA) {
                    self.debugPrint("Challenge A response not valid")
                    completion(false, Helper.makeError(109, "Invalid Challenge A response"))
                }
                
                keyDataClass.shared.ti = ti
                
                self.debugPrint("Data: TI: \(ti), challengeA: \(newChallengeA), pdCap: \(pdCap), pcCap: \(pcCap)")
                
                // Activate Session
                self.activeKeyNumber = keyNum
                self.commandCounter = 0
                self.activeTransactionIdentifier = ti
                
                self.debugPrint("Starting AES encryption")
                self.sessionEncryptionMode = AESEncryptionMode(communicator: self, key: keyData, challengeA: challengeA, challengeB: challengeB)
                
                completion(true, nil)
            }
        }
    }
}
public extension DnaCommunicator {
    func getChipUid(completion: @escaping ([UInt8], Error?) -> Void) {
        nxpEncryptedCommand(command: 0x51, header: [], data: []) { result, err in
            let err = err ?? self.makeErrorIfNotExpectedStatus(result)
            if err != nil {
                completion([], err)
                return
            }
            completion(Array(result.data[0...6]), err)
        }
    }
}
public extension DnaCommunicator {
    func writeFileData(fileNum: UInt8, data: [UInt8], mode: CommuncationMode? = nil, offset: Int = 0, completion: @escaping (Error?) -> Void) {
        // Pg. 75
        
        // Auto-detect mode if not specified
        if mode == nil {
            getFileSettings(fileNum: fileNum) { settings, err in
                if err != nil {
                    completion(err)
                } else {
                    self.writeFileData(fileNum: fileNum, data: data, mode: settings?.communicationMode, offset: offset) { err in
                        completion(err)
                    }
                }
            }
            return
        }
        
        let dataSizeBytes = Helper.byteArrayLE(from: Int32(data.count))[0...2]
        let offsetBytes = Helper.byteArrayLE(from: Int32(offset))[0...2]
        
        nxpSwitchedCommand(mode: mode!, command: 0x8d, header: [fileNum] + offsetBytes + dataSizeBytes, data: data) { result, err in
            completion(self.makeErrorIfNotExpectedStatus(result, error: err))
        }
    }
    
    func readFileData(fileNum: UInt8, length: Int, mode: CommuncationMode? = nil, offset: Int = 0, completion: @escaping ([UInt8], Error?) -> Void) {
        // Pg. 73
        
        // Auto-detect mode if not specified
        if mode == nil {
            getFileSettings(fileNum: fileNum) { settings, err in
                if err != nil {
                    completion([], err)
                } else {
                    self.readFileData(fileNum: fileNum, length: length, mode: settings?.communicationMode, offset: offset) { data, err in
                        completion(data, err)
                    }
                }
            }
            return
        }
        
        let offsetBytes = Helper.byteArrayLE(from: Int32(offset))[0...2]
        let lengthBytes = Helper.byteArrayLE(from: Int32(length))
        
        nxpSwitchedCommand(mode: mode!, command: 0xad, header: [fileNum] + offsetBytes + lengthBytes, data: []) { result, err in
            completion(result.data, self.makeErrorIfNotExpectedStatus(result, error: err))
        }
    }
    
    func getFileSettings(fileNum: UInt8, completion: @escaping (FileSettings?, Error?) -> Void) {
        // Pg. 69
        
        nxpMacCommand(command: 0xf5, header: [fileNum], data: []) { result, err in
            
            let settings = FileSettings(fromResultData:result)
            completion(settings, self.makeErrorIfNotExpectedStatus(result, error: err))
        }
    }
}

public extension DnaCommunicator {
    
    func getKeyVersion(keyNum: UInt8, completion: @escaping (UInt8, Error?) -> Void) {
        nxpMacCommand(command: 0x64, header: [keyNum], data: nil) { result, err in
            let resultValue = result.data.count < 1 ? 0 : result.data[0]
            completion(resultValue, err ?? self.makeErrorIfNotExpectedStatus(result))
        }
    }
    
    func changeKey(keyNum: UInt8, oldKey: [UInt8], newKey: [UInt8], keyVersion: UInt8, completion: @escaping (Bool, Error?) -> Void) {
        if activeKeyNumber != 0 {
            debugPrint("Not sure if changing keys when not authenticated as key0 is allowed - documentation is unclear")
        }
        
        if(keyNum == 0) {
            // If we are changing key0, can just send the request
            // This may need to check if keyNum == activeKeyNumber.  Documentation is unclear
            nxpEncryptedCommand(command: 0xc4, header: [keyNum], data: newKey + [keyVersion]) { result, err in
                let err = err ?? self.makeErrorIfNotExpectedStatus(result)
                completion(err == nil, err)
            }
        } else {
            // Weird validation methodology
            let crc = Helper.crc32(newKey)
            let xorkey = Helper.xor(oldKey, newKey)
            nxpEncryptedCommand(command: 0xc4, header: [keyNum], data:xorkey + [keyVersion] + crc) { result, err in
                let err = err ?? self.makeErrorIfNotExpectedStatus(result)
                completion(err == nil, err)
            }
        }
    }
}
