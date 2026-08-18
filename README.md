# Android Key Attestation Verifier

A Kotlin library for verifying Android key attestation certificate chains.

## Usage

```kotlin
// Create a verifier with default, Google-rooted trust anchors, revocation
// info, and time source.
val verifier = Verifier(
  GoogleTrustAnchors,                  // Trust anchors source
  ::getGoogleRevocationStatusFromWeb,  // Revoked serials source
  { Instant.now() }                    // Time source
)

// Verify an attestation certificate chain
val result = verifier.verify(
  certificateChain,
  challengeChecker,
  AttestationApplicationIdChecker.LENIENT(expectedAppId),
)

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
  is VerificationResult.AttestationApplicationIdMismatch -> // Handle mismatch
  is VerificationResult.PathValidationFailure -> // Handle validation failure
  is VerificationResult.ChainParsingFailure -> // Handle parsing failure
  is VerificationResult.ExtensionParsingFailure -> // Handle extension parsing issues
  is VerificationResult.ExtensionConstraintViolation -> // Handle constraint violations
}
```

### Choose a strong attestation challenge {#use-the-challenge}

Correctly generating your attestation challenges can:

  * Prevent replay attacks (where attackers use an attestation more than once).
  * Set a time-bound on a replay/relay (where attackers use an attestation from
    one device on another device) attacks.

**Important:** A challenge alone, unless it is bound to the protocol in some
other way, cannot entirely prevent relay attacks.

#### Include information unique to the request in the challenge

See the
[PIA](https://developer.android.com/google/play/integrity/standard#protect-requests)
documentation for guidance on how to choose a strong challenge by including
information from the request inthe challenge. Note that the equivalent of the
attestation challenge is `requestHash` in the PIA context.

#### Set time bounds for attestation validity

It’s important that the attestation not be valid for eternity. The longer an
attestation lives, the more likely it is to be used for a replay or relay
attack.

The easiest way to do this is to include a timestamp signed by your server-side
code in the challenge. When you verify the attestation's challenge, you'll check
the challenge signature and then make sure the timestamp is sufficiently fresh.

#### Example implementations

For example, if you expect the challenge to be equal to "challenge123", then
usage would look like

```kotlin
// Create a ChallengeChecker
val challengeChecker = ChallengeMatcher(ByteString.copyFromUtf8("challenge123"))
```

If there are multiple checks to perform on the challenge, use a
`ChainedChallengeChecker` to encompass all the individual `ChallengeCheckers`.
Checks in the `ChainedChallengeChecker` halt after the first failure, so take
advantage of this behavior by putting "less expensive" checks first.
For example, if your use case requires the challenge to be equal to an expected
challenge _and_ not seen already (stale), then combine the `ChallengeMatcher`
with an `InMemoryLruCache` like in this sample:

```kotlin
val cacheSize = 100

// Create a ChainedChallengeChecker with desired ChallengeCheckers. The
// coroutineScope is used to run each individual checker.
val challengeChecker =
  ChainedChallengeChecker.of(
    coroutineScope,
    ChallengeMatcher(ByteString.copyFromUtf8("expectedChallenge")),
    InMemoryLruCache(cacheSize),
  )

// Verify an attestation certificate chain with the checker
val result = verifier.verify(certificateChain, challengeChecker)
```

Here, the `ChallengeMatcher` is used first, so we can avoid the cost of checking
against the `InMemoryLruCache` if the challenge doesn't match.

If the implementations in `challengecheckers/` don't fit your needs, simply
extend the `ChallengeChecker` interface.

### Getting the expected Attestation Application Id

It is important to check the attestation application ID when verifying a key
attestation. This assures that you don't accept attestations for keys controlled
by other applications, and can provide some assurance against relay attacks.

The package list should be the names of all applications you expect to verify
against and their minimum accepted version numbers. You can get the signature
digests to put in in `signatures` from the Play Console as the app certificate
digests.

## Building

```bash
./gradlew build
```

## Testing

```bash
./gradlew test
```

## Roots

The root certificates may be retrieved from https://android.googleapis.com/attestation/root.
The `roots.json` source file in this repo is a mirror of the hosted roots file.
The generated `GoogleTrustAnchors` class is created from `roots.json` during
build time (as a Gradle task).

Android Key Attestation root certificates are documented
[here](https://developer.android.com/privacy-and-security/security-key-attestation#root_certificate).

## Getting Revoked Serials

It's important to check the revoked serials list to prevent allowing accepting
fraudulent attestations from known leaked keys. The revoked serials may be
retrieved from https://android.googleapis.com/attestation/status. This list is
updated relatively frequently so it's important to use a fresh copy of the
revocation list.

The above example will make a network call and parse the revoked serials list
every time `verify` is called. For regularly updated binaries, it may make sense
to build the revoked serial list into the binary.

See [here](https://developer.android.com/privacy-and-security/security-key-attestation#certificate_status)
for more information about the format of the data.

## License

This project is licensed under the Apache License 2.0 - see the
[LICENSE](LICENSE) file for details.
