//: [Previous](@previous)
import Foundation

enum PlaygroundError: Error {
    case message(String)
}

do {
    /*:
     ## Decrypting Data using ECIES
     In this Playground example, we are going to decrypt ciphertext data using the ECIES encryption scheme
     and then print the resultant plaintext string. Our ciphertext can be created by the [Encrypt example](Encrypt) in this playground or [our cross-platform Go example](https://github.com/jedda/ecies-go-example).
     */
    /*:
     ### Importing the EC Private Key
     Firstly, lets import in an existing private key. I've provided one below, but you can generate your own keypair by [using the commands under Keys in the Introduction](Introduction).
     
     To import this key from the PEM representation, we will use some very simple operations to drop the header and footer off (BEGIN & END lines) as well as remove the newlines. What we will end up with is the DER ASN.1 representation of the key in Base64 encoding.
     */
    let privateKeyPEM = """
-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIE8vNIElmwxSR+Zhl5NooE+FEupEgFbPbn0q3hMIbd2BoAoGCCqGSM49
AwEHoUQDQgAE7qMGCWG0L7HYAptVhIbLyx3cFzhd5EXZ09MpVpZmBGS7yCId5WQY
Ktmy3gTC245ivlEZ759ZPFgstYMgQoZrsg==
-----END EC PRIVATE KEY-----
""".split(separator: "\n")
        .dropFirst()
        .dropLast()
        .joined()
    //: Now we decode the DER data from a Base64 String to Data.
    guard let privateKeyPEMData = Data(base64Encoded: privateKeyPEM) else {
        throw PlaygroundError.message("Error whilst decoding private key DER from Base64")
    }
    /*:
     Now we need to get the raw bytes of the key to provide to SecKeyCreateWithData().
     Unfortunately, Swift/Foundation doesn't have a built in ASN deserialiser, so this is a very simplistic mangling
     of the raw data to get the bytes we need. In production, you'd likely need to do a far better job than this.
     There is an implementation from Apple [here](https://github.com/apple/swift-asn1) that I haven't tried.
     Alternatively, you could use the derRepresentation and pemRepresentation methods in CryptoKit to convert the key.
     For the simplicity of keeping this a Playground with no external dependencies, and maintaining the ability to create our keys in OpenSSL, we do the following (i know it's nasty).
     
     When generated with the openssl commands above, we have a structure header, then the private bytes, then an object identifier, then the public bytes. For the key sizes P-256, P-384 and P-521, we can get the raw bytes as follows:
     */
    var rawPrivateKeyData: Data = Data()
    switch (privateKeyPEMData.count) {
    case 121: // P-256 private key DER size
        // for P-256 (secp256r1, prime256v1) keys, the length is 65 bytes
        rawPrivateKeyData.append(privateKeyPEMData[56...120]) // public key bytes
        rawPrivateKeyData.append(privateKeyPEMData[7...38]) // private key bytes
    case 167: // P-384 private key DER size
        // for P-384 (secp384r1) keys, the length is 97 bytes
        rawPrivateKeyData.append(privateKeyPEMData[70...166]) // public key bytes
        rawPrivateKeyData.append(privateKeyPEMData[7...54]) // private key bytes
    case 223: // P-521 private key DER size
        rawPrivateKeyData.append(privateKeyPEMData[90...222]) // public key bytes
        rawPrivateKeyData.append(privateKeyPEMData[8...73]) // private key bytes
    default:
        throw PlaygroundError.message("Unknown DER key length: \(privateKeyPEMData.count)")
    }
    //: Now that we have our raw key bytes in `rawPrivateKeyData`, we can create our private `SecKey` for "decryption". Remember that nothing gets decrypted with this key. It's used in an EC Diffie-Hellman exchange with the  ephemeral key in the ciphertext to compute a shared key known only to the sender and recipient.
    var secKeyError: Unmanaged<CFError>?
    guard let privateSecKey = SecKeyCreateWithData(rawPrivateKeyData as CFData, [
        kSecAttrKeyType: kSecAttrKeyTypeECSECPrimeRandom,
        kSecAttrKeyClass: kSecAttrKeyClassPrivate,
    ] as NSDictionary , &secKeyError) else {
        throw PlaygroundError.message("Error in SecKeyCreateWithData() - \(String(describing: secKeyError))")
    }
    /*:
     ### Setting up for Decryption
     Now we can setup our algorithm for decryption. There are a couple of things to note here:
     
     Currently, there are variable IV and non-variable IV versions of each SecKeyAlgorithm.
     Non-variable IV will use 0000000000000000 as the IV, and variable will use 16 bytes derived from the KDF.
     It is obviously reccomended to use the variable IV algorithms where possible.
     
     For our example, we will use the following `SecKeyAlgorithm`:
     
     `.eciesEncryptionCofactorVariableIVX963SHA384AESGCM`
     
     Selecting this algorithm will perform the following when decrypting data (assuming a P-256 key):
     
     - It will extract the sender's ephemeral public key from the ciphertext.
     - It will perform a Elliptic-Curve Diffie-Hellman (ECDH) key agreement using the ephemeral public key and the known private key to generate a shared secret.
     - It will use the X9.63 Key Derivation Function with underlying SHA-384 hashing to generate a derived key 32 bits in length.
     - It will use the first 16 bits of the derived key as the AES key (16 bits for AES-128) and the last 16 bits as an IV/nonce for AES-GCM.
     */
    let algorithm: SecKeyAlgorithm = .eciesEncryptionCofactorVariableIVX963SHA384AESGCM
    //:We check that this algorithm is supported for decryption using the private key that we have provided.
    guard SecKeyIsAlgorithmSupported(privateSecKey, .decrypt, algorithm) else {
        throw PlaygroundError.message("\(algorithm) is not supported for decryption with this key.")
    }
    /*: And we of course need some ciphertext to decrypt. We have encoded it as a Base64 string for portability. I've provided an example below, but you can use the Encrypt playground page or my [cross-platform Go implmementation](https://github.com/jedda/ecies-go-example) to encrypt your own data and replace it here:
     */
    let ciphertext = "BNYuilyA9qKhJ51iaNFzMJXe7Z3pUG62o3vPfud3LEJbw2f1yMLEKF+V+6GQNNbk4Vjw2IHpEaZSB2If/ibZCS08AC6l/eUzMhW11k0Qr5mxggMHwV0aB1K8p/1J4bcy7n/4plUAEyA="
    //: Now decode our Base64 into Data to be decrypted;
    guard let ciphertextData = Data(base64Encoded: ciphertext) else {
        throw PlaygroundError.message("Error whilst decoding ciphertext from Base64")
    }
    /*:
     ### Decrypting our Data
     Now we pass our key, algorithm and ciphertext through to SecKeyCreateDecryptedData() in order to perform our decryption. If successful, we will get plaintext back as a Data object.
     */
    var decryptionError: Unmanaged<CFError>?
    guard let decryptedData = SecKeyCreateDecryptedData(privateSecKey, algorithm, ciphertextData as CFData, &decryptionError) as Data? else {
        throw PlaygroundError.message("Error in SecKeyCreateDecryptedData(): \(String(describing: decryptionError))")
    }
    //: Finally, we convert the plaintext data back to a string and print it.
    if let plaintext = String(data: decryptedData, encoding: .utf8) {
        print("The decrypted plaintext is:\n\(plaintext)")
    }
    
} catch PlaygroundError.message(let message){
    print(message)
}
/*:
 [Introduction](Introduction)
 
 [Encrypt Example](Encrypt)
 */
