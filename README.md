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

// Verify an attestation certificate chain
val result = verifier.verify(certificateChain)

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

If there is additional verification you'd like to perform on the challenge
associated with the attestation certificate chain, pass in a `ChallengeChecker`
when verifying. For example, if you expect the challenge to be equal to
"challenge123", then usage would look like

```kotlin
// Create a ChallengeChecker
val challengeChecker = ChallengeMatcher("challenge123")

// Verify an attestation certificate chain with the checker
val result = verifier.verify(certificateChain, challengeChecker)
```

If the implementations in challengecheckers/ don't fit your needs, simply extend
the `ChallengeChecker` interface.

## Building

```bash
./gradlew build
```

## Testing

```bash
./gradlew test
```

## Roots

Android Key Attestation root certificates are documented
[here](https://developer.android.com/privacy-and-security/security-key-attestation#root_certificate).

## Getting Revoked Serials

The revoked serials may be retrieved from https://android.googleapis.com/attestation/status.

See [here](https://developer.android.com/privacy-and-security/security-key-attestation#certificate_status)
for more information about the format of the data.

## License

This project is licensed under the Apache License 2.0 - see the
[LICENSE](LICENSE) file for details.
