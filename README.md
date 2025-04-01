# Android Key Attestation Verifier

A Kotlin library for verifying Android key attestation certificate chains.

## Usage

```kotlin
// Create a verifier with trust anchors, revocation info, and time source
val verifier = Verifier(
  { setOf(TrustAnchor(rootCertificate, null)) },  // Trust anchors source
  { setOf<String>() },                            // Revoked serials source
  { Instant.now() }                               // Time source
)

// Verify an attestation certificate chain with challenge
val result = verifier.verify(certificateChain, challenge)

// Handle the verification result
when (result) {
  is VerificationResult.Success -> {
    // Access verified information
    val publicKey = result.publicKey
    val securityLevel = result.securityLevel
    val verifiedBootState = result.verifiedBootState
    val deviceInformation = result.deviceInformation
  }
  is VerificationResult.ChallengeMismatch -> // Handle challenge mismatch
  is VerificationResult.PathValidationFailure -> // Handle validation failure
  is VerificationResult.ChainParsingFailure -> // Handle parsing failure
  is VerificationResult.ExtensionParsingFailure -> // Handle extension parsing issues
  is VerificationResult.ExtensionConstraintViolation -> // Handle constraint violations
}
```

## Building

```bash
./gradlew build
```

## Testing

```bash
./gradlew test
```

## License

This project is licensed under the Apache License 2.0 - see the
[LICENSE](LICENSE) file for details.
