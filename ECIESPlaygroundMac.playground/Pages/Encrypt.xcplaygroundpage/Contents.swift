import Foundation

enum PlaygroundError: Error {
    case message(String)
}

do {
/*:
 ## Encrypting Data using ECIES
 In this Playground example, we are going to encrypt a message using the ECIES encryption scheme
 and then print the resultant ciphertext as a Base64 string. This will allow us to easily copy this
 ciphertext string (and the appropriate key) to either our Decrypt example, or to [our cross-platform Go example](https://github.com/jedda/ecies-go-example).
 */
/*:
 ### Importing the EC Public Key
 Firstly, lets import in an existing public key. I've provided one below, but you can generate your own keypair by [using the commands under Keys in the Introduction](Introduction).
 
 To import this key from the PEM representation, we will use some very simple operations to drop the header and footer off (BEGIN & END lines) as well as remove the newlines. What we will end up with is the DER ASN.1 representation of the key in Base64 encoding.
*/

let publicKeyPEM = """
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE7qMGCWG0L7HYAptVhIbLyx3cFzhd
5EXZ09MpVpZmBGS7yCId5WQYKtmy3gTC245ivlEZ759ZPFgstYMgQoZrsg==
-----END PUBLIC KEY-----
""".split(separator: "\n")
    .dropFirst()
    .dropLast()
    .joined()
//: Now we decode the DER data from a Base64 String to Data.
guard let publicKeyPEMData = Data(base64Encoded: publicKeyPEM) else {
    throw PlaygroundError.message("Error whilst decoding public key DER from Base64")
}
/*:
 Now we need to get the raw bytes of the key to provide to SecKeyCreateWithData().
 Unfortunately, Swift/Foundation doesn't have a built in ASN deserialiser, so this is a very simplistic mangling
 of the raw data to get the bytes we need. In production, you'd likely need to do a far better job than this.
 There is an implementation from Apple [here](https://github.com/apple/swift-asn1) that I haven't tried.
 Alternatively, you could use the derRepresentation and pemRepresentation methods in CryptoKit to convert the key.
 For the simplicity of keeping this a Playground with no external dependencies, and maintaining the ability to create our keys in OpenSSL, we do the following (i know it's nasty).
 
 When generated with the openssl commands above, the first part of the public key DER representation is the
 structure header. Our raw key bytes are at the end, so we take the suffix of the key length and we should
 end up with just the raw bytes of the public key.
 */
var rawPublicKeyData: Data
switch (publicKeyPEMData.count) {
case 91: // P-256 DER size
    // for P-256 (secp256r1, prime256v1) keys, the length is 65 bytes
    rawPublicKeyData = publicKeyPEMData.suffix(65)
case 120: // P-384 DER size
    // for P-384 (secp384r1) keys, the length is 97 bytes
    rawPublicKeyData = publicKeyPEMData.suffix(97)
case 158: // P-521 DER size
    //var rawPublicKeyData = publicKeyPEMData.suffix(133)
    rawPublicKeyData = publicKeyPEMData.suffix(133)
default:
    throw PlaygroundError.message("Unknown DER key length: \(publicKeyPEMData.count)")
}
//: Now that we have our raw key bytes in `rawPublicKeyData`, we can create our `SecKey` for "encryption". Remember that nothing gets encrypted with this key. It's used to create an ephemeral key is used in an EC Diffie-Hellman exchange with the private pair to compute and then derive a shared symmetric key known only to the sender and recipient.
var secKeyError: Unmanaged<CFError>?
guard let publicSecKey = SecKeyCreateWithData(rawPublicKeyData as CFData, [
    kSecAttrKeyType: kSecAttrKeyTypeECSECPrimeRandom,
    kSecAttrKeyClass: kSecAttrKeyClassPublic,
] as NSDictionary , &secKeyError) else {
    throw PlaygroundError.message("Error in SecKeyCreateWithData() - \(String(describing: secKeyError))")
}
/*:
 ### Setting up for Encryption
 Now we can setup our algorithm for encryption. There are a couple of things to note here:

 Currently, there are variable IV and non-variable IV versions of each SecKeyAlgorithm.
 Non-variable IV will use 0000000000000000 as the IV, and variable will use 16 bytes derived from the KDF.
 It is obviously reccomended to use the variable IV algorithms where possible.

 For our example, we will use the following `SecKeyAlgorithm`:

 `.eciesEncryptionCofactorVariableIVX963SHA384AESGCM`

 Selecting this algorithm will perform the following when encrypting data (assuming a P-256 key):

 - It will generate a new P-256 keypair that is ephemeral and is only used for this one operation, then discarded.
 - It will perform a Elliptic-Curve Diffie-Hellman (ECDH) key agreement using the ephemeral private key and the encryption public key to generate a shared secret.
 - It will use the X9.63 Key Derivation Function with underlying SHA-384 hashing to generate a derived key 32 bits in length.
 - It will use the first 16 bits of the derived key as the AES key (16 bits for AES-128) and the last 16 bits as an IV/nonce for AES-GCM
*/
let algorithm: SecKeyAlgorithm = .eciesEncryptionCofactorVariableIVX963SHA384AESGCM
//:We check that this algorithm is supported for encryption using the key that we have provided.
guard SecKeyIsAlgorithmSupported(publicSecKey, .encrypt, algorithm) else {
    throw PlaygroundError.message("\(algorithm) is not supported for encryption with this key.")
}
/*:
 OK, now we are ready to encrypt our data. Let's create a message that we can encrypt.

 For the purposes of this example, we will encrypt a plain string, but you could uncomment the line below to encrypt the contents of a file or anything you wish.
 */
let plaintext = "This is a test message."
let plaintextData = plaintext.data(using: .utf8)
//let plaintextData = try Data(contentsOf: URL(fileURLWithPath: "/Users/user/Desktop/file-to-encrypt.zip"))
/*:
 ### Encrypting our Data
 Now we pass our key, algorithm and data through to SecKeyCreateEncryptedData() in order to perform our encryption. If successful, we will get data returned in the following format:
 
`[ephemeral public key raw bytes] + [encrypted ciphertext] + [AES-GCM authentication tag]`
 
 For our example message and key, this ciphertext data will be 104 bytes in size: 65 for the public key, 23 for the message, and 16 for the tag.

 */
var encryptionError: Unmanaged<CFError>?
guard let encryptedData = SecKeyCreateEncryptedData(publicSecKey, algorithm, plaintextData! as CFData, &encryptionError) as Data? else {
    throw PlaygroundError.message("Error in SecKeyCreateEncryptedData(): \(String(describing: encryptionError))")
}
//: Finally, lets print a Base64 string representation of the encrypted data so that it is portable to the other examples:
print("Ciphertext: \(encryptedData.base64EncodedString())")

} catch PlaygroundError.message(let message){
    print(message)
}
/*:
 [Introduction](Introduction)
 
 [Decrypt Example](Decrypt)
 */
