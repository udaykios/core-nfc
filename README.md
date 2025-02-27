# NFC Reader for NTAG

This project is a Swift-based NFC reader designed to interact with NTAG NFC chips. The app reads and modifies file settings on the NFC chip while handling authentication and encryption using various cryptographic methods.

## Features
- Reads NTAG NFC chips.
- Handles authentication using EV2First.
- Fetches and updates file settings, including access permissions.
- Supports AES encryption (ECB, CBC, and CMAC).
- Configurable write protection settings.

## Requirements
- iOS 15.0+
- Xcode 15+
- iPhone with NFC support

## Dependencies
This project uses:
- `CryptoSwift`
- `CryptoKit`
- `CommonCrypto`
- `OpenSSL`

## Installation
1. Clone the repository:
   ```sh
   git clone https://github.com/udaykios/core-nfc
   cd NFC-Reader
   ```
2. Open the project in Xcode.
3. Ensure dependencies are installed via Swift Package Manager.
4. Build and run the project on an NFC-compatible iPhone.

## Usage
1. Launch the app and tap the scan button.
2. Hold the iPhone near an NTAG NFC chip.
3. The app will authenticate, fetch file settings, and display the results.
4. If needed, update file permissions to enable or disable write protection.

## Configuration
### Authentication
Authentication is handled using EV2First. Modify the `authenticateEV2First` method if needed:
```swift
dna.authenticateEV2First(keyNum: 0) { success, authError in
    if !success || authError != nil {
        print("Authentication failed")
        return
    }
    print("Authentication successful")
}
```

### Reading NFC Data
```swift
let fileNumber: UInt8 = 0x02
self.fetchFileSettings(dna: dna, fileNumber: fileNumber)
```

### Updating File Permissions
```swift
let newAccessRights = Data([0x00, 0x00]) // Example for enabling write protection give actual values
self.configureFileSettings(isoDep: dna.tag!, newFileAccess: newAccessRights) { result in
    switch result {
    case .success(let response):
        print("File settings updated successfully: \(response.toHexString())")
    case .failure(let error):
        print("Failed to update file settings: \(error.localizedDescription)")
    }
}
```


