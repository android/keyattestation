/*
 * Copyright 2024 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.android.keyattestation.verifier

import com.android.keyattestation.verifier.VerificationResult.ExtensionConstraintViolation
import com.android.keyattestation.verifier.VerificationResult.ExtensionParsingFailure
import com.android.keyattestation.verifier.VerificationResult.PathValidationFailure
import com.android.keyattestation.verifier.challengecheckers.ChallengeMatcher
import com.android.keyattestation.verifier.testing.CertLists
import com.android.keyattestation.verifier.testing.Certs
import com.android.keyattestation.verifier.testing.FakeCalendar
import com.android.keyattestation.verifier.testing.FakeLogHook
import com.android.keyattestation.verifier.testing.TestUtils.falseChecker
import com.android.keyattestation.verifier.testing.TestUtils.prodAnchors
import com.android.keyattestation.verifier.testing.TestUtils.readCertList
import com.android.keyattestation.verifier.testing.TestUtils.readJson
import com.android.keyattestation.verifier.testing.TestUtils.trueChecker
import com.google.common.truth.Truth.assertThat
import com.google.common.util.concurrent.Futures
import com.google.common.util.concurrent.ListenableFuture
import com.google.protobuf.ByteString
import com.google.protobuf.kotlin.toByteString
import com.google.testing.junit.testparameterinjector.TestParameter
import com.google.testing.junit.testparameterinjector.TestParameterInjector
import java.security.cert.PKIXReason
import java.security.cert.TrustAnchor
import java.time.Instant
import java.time.LocalDate
import java.time.ZoneOffset
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import kotlin.test.assertFailsWith
import kotlin.test.assertIs
import kotlinx.coroutines.guava.await
import kotlinx.coroutines.runBlocking
import org.junit.Test
import org.junit.runner.RunWith

/** Unit tests for [Verifier]. */
@RunWith(TestParameterInjector::class)
class VerifierTest {
  private val verifier =
    Verifier(
      { prodAnchors + TrustAnchor(Certs.root, null) },
      { setOf<String>() },
      { FakeCalendar.DEFAULT.now() },
    )
  private val delayedAlwaysTrueChecker =
    object : ChallengeChecker {
      override fun checkChallenge(challenge: ByteString): ListenableFuture<Boolean> {
        return Futures.scheduleAsync(
          { Futures.immediateFuture(true) },
          5,
          TimeUnit.SECONDS,
          Executors.newSingleThreadScheduledExecutor(),
        )
      }
    }

  @Test
  fun verify_validChain_returnsSuccess(@TestParameter testCase: TestCase) {
    val verifier = Verifier({ prodAnchors }, { setOf<String>() }, { testCase.timestamp })
    val chain = readCertList("${testCase.path}.pem")
    val json = readJson("${testCase.path}.json")
    val result = assertIs<VerificationResult.Success>(verifier.verify(chain))
    assertThat(result.publicKey).isEqualTo(chain[0].publicKey)
    assertThat(result.challenge).isEqualTo(json.attestationChallenge)
    assertThat(result.securityLevel).isEqualTo(json.attestationSecurityLevel)
    assertThat(result.verifiedBootState)
      .isEqualTo(json.hardwareEnforced.rootOfTrust?.verifiedBootState)
  }

  enum class TestCase(val path: String, val timestamp: Instant) {
    PIXEL_3_SDK28(
      "blueline/sdk28/TEE_EC_NONE",
      LocalDate.of(2024, 10, 1).atStartOfDay(ZoneOffset.UTC).toInstant(),
    ),
    PIXEL_8A_SDK34(
      "akita/sdk34/TEE_EC_NONE",
      LocalDate.of(2024, 10, 1).atStartOfDay(ZoneOffset.UTC).toInstant(),
    ),
    PIXEL_9PRO_SDK36(
      "caiman/sdk36/TEE_EC_RKP",
      LocalDate.of(2025, 9, 30).atStartOfDay(ZoneOffset.UTC).toInstant(),
    ),
  }

  @Test
  fun verifyAsync_validChainUsingGeneratedTrustAnchors_returnsSuccess(): Unit = runBlocking {
    val verifier = Verifier(GoogleTrustAnchors, { setOf<String>() }, { Instant.now() })
    val chain = readCertList("blueline/sdk28/TEE_EC_NONE.pem")
    assertIs<VerificationResult.Success>(verifier.verifyAsync(this, chain).await())
  }

  @Test
  fun verifyAsync_validChain_returnsDeviceIdentity() = runBlocking {
    val chain = readCertList("blueline/sdk28/TEE_RSA_BASE+IMEI.pem")
    val result = assertIs<VerificationResult.Success>(verifier.verifyAsync(this, chain).await())
    assertThat(result.attestedDeviceIds)
      .isEqualTo(
        DeviceIdentity(
          "google",
          "blueline",
          "blueline",
          null,
          setOf("990012001354866"),
          null,
          "Google",
          "Pixel 3",
        )
      )
  }

  @Test
  fun verifyAsync_challengeCheckerReturnsTrue_returnsSuccess(): Unit = runBlocking {
    val chain = readCertList("blueline/sdk28/TEE_EC_NONE.pem")

    assertIs<VerificationResult.Success>(verifier.verifyAsync(this, chain, trueChecker).await())
  }

  @Test
  fun verifyAsync_challengeCheckerReturnsFalse_returnsChallengeMismatch(): Unit = runBlocking {
    val chain = readCertList("blueline/sdk28/TEE_EC_NONE.pem")

    assertIs<VerificationResult.ChallengeMismatch>(
      verifier.verifyAsync(this, chain, falseChecker).await()
    )
  }

  @Test
  fun verifyAsync_unexpectedRootKey_returnsPathValidationFailure() = runBlocking {
    val result =
      assertIs<VerificationResult.PathValidationFailure>(
        verifier
          .verifyAsync(
            this,
            CertLists.wrongTrustAnchor,
            ChallengeMatcher(ByteString.copyFromUtf8("challenge")),
          )
          .await()
      )
    assertThat(result.cause.reason).isEqualTo(PKIXReason.NO_TRUST_ANCHOR)
  }

  @Test
  fun unknownTag_unknownTagReason() {
    val result = assertIs<ExtensionParsingFailure>(verifier.verify(CertLists.unknownTag))
    assertThat(result.cause.reason).isEqualTo(KeyAttestationReason.UNKNOWN_TAG_NUMBER)
  }

  @Test
  fun targetMissingAttestationExtension_givesTargetMissingAttestationExtensionReason() {
    val result = assertIs<PathValidationFailure>(verifier.verify(CertLists.missingExtension))
    assertThat(result.cause.reason)
      .isEqualTo(KeyAttestationReason.TARGET_MISSING_ATTESTATION_EXTENSION)
  }

  @Test
  fun rootOfTrustMissing_givesRootOfTrustMissingReason() {
    val result =
      assertIs<ExtensionConstraintViolation>(verifier.verify(CertLists.missingRootOfTrust))
    assertThat(result.reason).isEqualTo(KeyAttestationReason.ROOT_OF_TRUST_CONSTRAINT_VIOLATION)
  }

  @Test
  fun keyOriginNotGenerated_throwsCertPathValidatorException() {
    val result = assertIs<ExtensionConstraintViolation>(verifier.verify(CertLists.importedOrigin))
    assertThat(result.reason).isEqualTo(KeyAttestationReason.KEY_ORIGIN_CONSTRAINT_VIOLATION)
  }

  @Test
  fun mismatchedSecurityLevels_throwsCertPathValidatorException() {
    val result =
      assertIs<ExtensionConstraintViolation>(verifier.verify(CertLists.mismatchedSecurityLevels))
    assertThat(result.reason).isEqualTo(KeyAttestationReason.SECURITY_LEVEL_CONSTRAINT_VIOLATION)
  }

  @Test
  fun mismatchedSecurityLevels_customConfig_succeeds() {
    val verifier =
      Verifier(
        { prodAnchors + TrustAnchor(Certs.root, null) },
        { setOf<String>() },
        { FakeCalendar.DEFAULT.now() },
        ExtensionConstraintConfig(securityLevel = ValidationLevel.NOT_NULL),
      )
    val result =
      assertIs<VerificationResult.Success>(verifier.verify(CertLists.mismatchedSecurityLevels))
    assertThat(result.securityLevel).isEqualTo(SecurityLevel.SOFTWARE)
  }

  @Test
  fun unorderedTags_customConfig_throwsCertPathValidatorException() {
    val verifier =
      Verifier(
        { prodAnchors + TrustAnchor(Certs.root, null) },
        { setOf<String>() },
        { FakeCalendar.DEFAULT.now() },
        ExtensionConstraintConfig(authorizationListTagOrder = TagOrderValidationLevel.STRICT),
      )
    val result = assertIs<ExtensionConstraintViolation>(verifier.verify(CertLists.unorderedTags))
    assertThat(result.reason)
      .isEqualTo(KeyAttestationReason.AUTHORIZATION_LIST_ORDERING_CONSTRAINT_VIOLATION)
  }

  @Test
  fun verifyAsync_failure_inputChainLogged() = runBlocking {
    val logHook = FakeLogHook()
    assertIs<VerificationResult.PathValidationFailure>(
      verifier
        .verifyAsync(
          this,
          CertLists.wrongTrustAnchor,
          ChallengeMatcher(ByteString.copyFromUtf8("challenge")),
          logHook,
        )
        .await()
    )
    assertThat(logHook.fakeVerifyRequestLog.inputChain)
      .isEqualTo(CertLists.wrongTrustAnchor.map { it.encoded.toByteString() })
  }

  @Test
  fun verifyAsync_success_keyDescriptionLogged() = runBlocking {
    val logHook = FakeLogHook()
    val chain = readCertList("blueline/sdk28/TEE_EC_NONE.pem")
    assertIs<VerificationResult.Success>(verifier.verifyAsync(this, chain, log = logHook).await())
    assertThat(logHook.fakeVerifyRequestLog.keyDescription)
      .isEqualTo(chain.first().keyDescription())
  }

  @Test
  fun verifyAsync_malformedPatchLevel_logsInfo() = runBlocking {
    val verifierWithTestRoot =
      Verifier(
        { setOf(TrustAnchor(Certs.root, null)) },
        { setOf<String>() },
        { FakeCalendar.DEFAULT.now() },
      )
    val logHook = FakeLogHook()
    assertIs<VerificationResult.Success>(
      verifierWithTestRoot.verifyAsync(this, CertLists.invalidBootPatchLevel, log = logHook).await()
    )
    assertThat(logHook.fakeVerifyRequestLog.infoMessages).isNotEmpty()
  }

  @Test
  fun verifyAsync_longDelay_successfullyAwaitsChallengeCheck(): Unit = runBlocking {
    val chain = readCertList("blueline/sdk28/TEE_EC_NONE.pem")

    assertIs<VerificationResult.Success>(
      verifier.verifyAsync(this, chain, delayedAlwaysTrueChecker).await()
    )
  }

  @Test
  fun init_softwareRootAsTrustAnchor_fails() {
    assertFailsWith<IllegalArgumentException> {
      Verifier({ setOf(TrustAnchor(SOFTWARE_ROOT, null)) }, { setOf<String>() }, { Instant.now() })
    }
  }
}
