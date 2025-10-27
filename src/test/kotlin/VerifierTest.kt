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
import com.google.protobuf.ByteString
import com.google.protobuf.kotlin.toByteString
import com.google.testing.junit.testparameterinjector.TestParameter
import com.google.testing.junit.testparameterinjector.TestParameterInjector
import java.security.cert.PKIXReason
import java.security.cert.TrustAnchor
import java.time.Instant
import java.time.LocalDate
import java.time.ZoneOffset
import kotlin.test.assertIs
import org.junit.Test
import org.junit.runner.RunWith

/** Unit tests for [Verifier]. */
@RunWith(TestParameterInjector::class)
class VerifierTest {
  private val verifier = Verifier({ prodAnchors }, { setOf<String>() }, { Instant.now() })

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
  fun verify_validChainUsingGeneratedTrustAnchors_returnsSuccess() {
    val verifier = Verifier(GoogleTrustAnchors, { setOf<String>() }, { Instant.now() })
    val chain = readCertList("blueline/sdk28/TEE_EC_NONE.pem")
    assertIs<VerificationResult.Success>(verifier.verify(chain))
  }

  @Test
  fun verify_validChain_returnsDeviceIdentity() {
    val chain = readCertList("blueline/sdk28/TEE_RSA_BASE+IMEI.pem")
    val result = assertIs<VerificationResult.Success>(verifier.verify(chain))
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
  fun verify_challengeCheckerReturnsTrue_returnsSuccess() {
    val chain = readCertList("blueline/sdk28/TEE_EC_NONE.pem")

    assertIs<VerificationResult.Success>(verifier.verify(chain, trueChecker))
  }

  @Test
  fun verify_challengeCheckerReturnsFalse_returnsChallengeMismatch() {
    val chain = readCertList("blueline/sdk28/TEE_EC_NONE.pem")

    assertIs<VerificationResult.ChallengeMismatch>(verifier.verify(chain, falseChecker))
  }

  @Test
  fun verify_unexpectedRootKey_returnsPathValidationFailure() {
    val result =
      assertIs<VerificationResult.PathValidationFailure>(
        verifier.verify(
          CertLists.wrongTrustAnchor,
          ChallengeMatcher(ByteString.copyFromUtf8("challenge")),
        )
      )
    assertThat(result.cause.reason).isEqualTo(PKIXReason.NO_TRUST_ANCHOR)
  }

  @Test
  fun verify_failure_inputChainLogged() {
    val logHook = FakeLogHook()
    assertIs<VerificationResult.PathValidationFailure>(
      verifier.verify(
        CertLists.wrongTrustAnchor,
        ChallengeMatcher(ByteString.copyFromUtf8("challenge")),
        logHook,
      )
    )
    assertThat(logHook.inputChain)
      .isEqualTo(CertLists.wrongTrustAnchor.map { it.encoded.toByteString() })
  }

  @Test
  fun verify_success_keyDescriptionLogged() {
    val logHook = FakeLogHook()
    val chain = readCertList("blueline/sdk28/TEE_EC_NONE.pem")
    assertIs<VerificationResult.Success>(verifier.verify(chain, log = logHook))
    assertThat(logHook.keyDescription).isEqualTo(chain[0].keyDescription())
  }

  @Test
  fun verify_malformedPatchLevel_logsInfo() {
    val verifierWithTestRoot =
      Verifier(
        { setOf(TrustAnchor(Certs.root, null)) },
        { setOf<String>() },
        { FakeCalendar.DEFAULT.now() },
      )
    val logHook = FakeLogHook()
    assertIs<VerificationResult.Success>(
      verifierWithTestRoot.verify(CertLists.invalidBootPatchLevel, log = logHook)
    )
    assertThat(logHook.infoMessages).isNotEmpty()
  }
}
