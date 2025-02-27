//
//  FileConfiguario.swift
//  DNAKIT
//
//  Created by Quin Design on 25/02/25.
//

import Foundation

public enum CommuncationMode: UInt8, Codable {
    case PLAIN = 0
    case MAC = 1
    case PLAIN_ALT = 2
    case FULL = 3
}

public enum Permission: UInt8, Codable {
    case KEY_0 = 0
    case KEY_1 = 1
    case KEY_2 = 2
    case KEY_3 = 3
    case KEY_4 = 4
    case ALL = 0xe
    case NONE = 0xf
    
    public func displayValue() -> String {
        switch self {
        case .KEY_0:
            return "Key 0"
        case .KEY_1:
            return "Key 1"
        case .KEY_2:
            return "Key 2"
        case .KEY_3:
            return "Key 3"
        case .KEY_4:
            return "Key 4"
        case .ALL:
            return "All"
        case .NONE:
            return "None"
        }
    }
}

public enum FileSpecifier: UInt8, Codable {
    case CC_FILE = 1      // 32 bytes  (pg. 10)
    case NDEF_FILE = 2    // 256 bytes
    case PROPRIETARY = 3  // 128 bytes
    
    public func size() -> Int {
        switch self {
        case .CC_FILE:
            return 32
        case .NDEF_FILE:
            return 256
        case .PROPRIETARY:
            return 128
        }
    }
    
    public func displayValue() -> String {
        switch self {
        case .CC_FILE:
            return "CC File"
        case .NDEF_FILE:
            return "NDEF File"
        case .PROPRIETARY:
            return "Proprietary File"
        }
    }
}

public class FileConfiguration: Codable {
    public var fileSpecifier: FileSpecifier = .NDEF_FILE
    public var fileData: [UInt8] = []
    public var fileSettings = FileSettings()
     
    //     val SDM_READ_COUNTER_NO_MIRRORING = 16777215
    
    public init() {
        
    }
}

public class FileSettings: Codable {
    public var sdmEnabled: Bool = false
    public var communicationMode: CommuncationMode = .PLAIN // Should be calculated
    public var readPermission: Permission = .ALL
    public var writePermission: Permission = .ALL
    public var readWritePermission: Permission = .ALL
    public var changePermission: Permission = .ALL
    public var fileSize: Int? // Should be calculated
    public var sdmOptionUid: Bool = true
    public var sdmOptionReadCounter: Bool = true
    public var sdmOptionReadCounterLimit: Bool = false
    public var sdmOptionEncryptFileData: Bool = false
    public var sdmOptionUseAscii: Bool = false
    public var sdmMetaReadPermission: Permission = .ALL
    public var sdmFileReadPermission: Permission = .ALL
    public var sdmReadCounterRetrievalPermission: Permission = .ALL
    public var sdmUidOffset: Int?
    public var sdmReadCounterOffset: Int?
    public var sdmPiccDataOffset: Int?
    public var sdmMacInputOffset: Int?
    public var sdmMacOffset: Int?
    public var sdmEncOffset: Int?
    public var sdmEncLength: Int?
    public var sdmReadCounterLimit: Int?
    
    public var fileType: UInt8? // Basically read-only
    
    init() {
        
    }
    
    convenience init(fromResultData: NxpCommandResult) {
        // Pg. 13
        
        self.init()
        let data = fromResultData.data
        fileType = data[0] //crash 
        let options = data[1]
        sdmEnabled = Helper.getBitLSB(options, 6)
        
        communicationMode = .PLAIN
        if Helper.getBitLSB(options, 1) && Helper.getBitLSB(options, 0) {
            communicationMode = .FULL
        }
        if Helper.getBitLSB(options, 0) && Helper.getBitLSB(options, 0) {
            communicationMode = .MAC
        }
        
        
        readPermission = Permission(rawValue: Helper.leftNibble(data[2]))!
        writePermission = Permission(rawValue: Helper.rightNibble(data[2]))!
        readWritePermission = Permission(rawValue: Helper.leftNibble(data[3]))!
        changePermission = Permission(rawValue: Helper.rightNibble(data[3]))!
        
        fileSize = Helper.bytesToIntLE(Array(data[4...6]))
        
        var currentOffset = 7
        
        if sdmEnabled {
            let sdmOptions = data[currentOffset]
            currentOffset += 1
            
            sdmOptionUid = Helper.getBitLSB(sdmOptions, 7)
            sdmOptionReadCounter = Helper.getBitLSB(sdmOptions, 6)
            sdmOptionReadCounterLimit = Helper.getBitLSB(sdmOptions, 5)
            sdmOptionEncryptFileData = Helper.getBitLSB(sdmOptions, 4)
            sdmOptionUseAscii = Helper.getBitLSB(sdmOptions, 0)
            
            let sdmAccessRights1 = data[currentOffset]
            currentOffset += 1
            let sdmAccessRights2 = data[currentOffset]
            currentOffset += 1
            sdmMetaReadPermission = Permission(rawValue: Helper.leftNibble(sdmAccessRights1))!
            sdmFileReadPermission = Permission(rawValue: Helper.rightNibble(sdmAccessRights1))!
            sdmReadCounterRetrievalPermission = Permission(rawValue: Helper.rightNibble(sdmAccessRights2))!
            
            if sdmMetaReadPermission == .ALL {
                if sdmOptionUid {
                    sdmUidOffset = Helper.bytesToIntLE(Array(data[currentOffset...(currentOffset + 2)]))
                    currentOffset += 3
                }
                if sdmOptionReadCounter {
                    sdmReadCounterOffset = Helper.bytesToIntLE(Array(data[currentOffset...(currentOffset + 2)]))
                    currentOffset += 3
                }
            } else {
                if sdmMetaReadPermission != .NONE {
                    sdmPiccDataOffset = Helper.bytesToIntLE(Array(data[currentOffset...(currentOffset + 2)]))
                    currentOffset += 3
                }
            }
            if sdmFileReadPermission != .NONE {
                sdmMacInputOffset = Helper.bytesToIntLE(Array(data[currentOffset...(currentOffset + 2)]))
                currentOffset += 3
                
                if sdmOptionEncryptFileData {
                    sdmEncOffset = Helper.bytesToIntLE(Array(data[currentOffset...(currentOffset+2)]))
                    currentOffset += 3
                    sdmEncLength = Helper.bytesToIntLE(Array(data[currentOffset...(currentOffset+2)]))
                    currentOffset += 3
                }
                
                sdmMacOffset = Helper.bytesToIntLE(Array(data[currentOffset...(currentOffset+2)]))
                currentOffset += 3
            }
            if sdmOptionReadCounterLimit {
                sdmReadCounterLimit = Helper.bytesToIntLE(Array(data[currentOffset...(currentOffset+2)]))
                currentOffset += 3
            }
        }
    }
}
public class TagConfiguration: Codable {
    public var name: String?
    
    public var ndefFileConfiguration: FileConfiguration?
    public var privateFileConfiguration: FileConfiguration?

    public var optEnableLrp: Bool = false
    public var optUseRandomId: Bool = false
    public var optEnableStrongBackModulation: Bool = true
    public var optUseFailCounter: Bool = false
    public var failCounterLimit: Int = 1000
    public var failCounterDecrement: Int = 10
    public var resetSdmCounter: Bool = false
    
    public var keys: [[UInt8]] = [
        [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
    ]
    
    public init() {
        
    }
    
    public func toJSON() -> String {
        do {
            let encoder = JSONEncoder()
            let data = try encoder.encode(self)
            return String(data:data, encoding: .utf8)!
        } catch {
            print("Unexpected error encoding to JSON!")
            return ""
        }
    }
    
    public static func fromJSON(_ json:String) -> TagConfiguration? {
        do {
            let decoder = JSONDecoder()
            let config = try decoder.decode(TagConfiguration.self, from: json.data(using: .utf8)!)
            return config
        } catch {
            print("Failed decoding JSON")
            return nil
        }
    }
}
