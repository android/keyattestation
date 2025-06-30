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
import com.android.keyattestation.verifier.testing.TestUtils.prodAnchors
import com.android.keyattestation.verifier.testing.TestUtils.readCertPath
import com.google.common.truth.Truth.assertThat
import com.google.protobuf.ByteString
import java.time.Instant
import kotlin.test.assertIs
import org.junit.Test
import org.junit.runner.RunWith
import org.junit.runners.JUnit4

/** Unit tests for [Verifier]. */
@RunWith(JUnit4::class)
class VerifierTest {
  private val verifier = Verifier({ prodAnchors }, { setOf<String>() }, { Instant.now() })

  @Test
  fun verify_validChain_returnsSuccess() {
    val chain = readCertPath("blueline/sdk28/TEE_EC_NONE.pem")
    val result = assertIs<VerificationResult.Success>(verifier.verify(chain))
    assertThat(result.publicKey).isEqualTo(chain.leafCert().publicKey)
    assertThat(result.challenge).isEqualTo(ByteString.copyFromUtf8("challenge"))
    assertThat(result.securityLevel).isEqualTo(SecurityLevel.TRUSTED_ENVIRONMENT)
    assertThat(result.verifiedBootState).isEqualTo(VerifiedBootState.UNVERIFIED)
  }

  @Test
  fun verify_validChain_returnsDeviceIdentity() {
    val chain = readCertPath("blueline/sdk28/TEE_RSA_BASE+IMEI.pem")
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
    val challengeChecker: ChallengeChecker =
      object : ChallengeChecker {
        override fun checkChallenge(challenge: ByteString) = true
      }

    val chain = readCertPath("blueline/sdk28/TEE_EC_NONE.pem")
    assertIs<VerificationResult.Success>(verifier.verify(chain, challengeChecker))
  }

  @Test
  fun verify_challengeCheckerReturnsFalse_returnsChallengeMismatch() {
    val challengeChecker: ChallengeChecker =
      object : ChallengeChecker {
        override fun checkChallenge(challenge: ByteString) = false
      }

    val chain = readCertPath("blueline/sdk28/TEE_EC_NONE.pem")
    assertIs<VerificationResult.ChallengeMismatch>(verifier.verify(chain, challengeChecker))
  }

  @Test
  fun verify_unexpectedRootKey_returnsPathValidationFailure() {
    assertIs<VerificationResult.PathValidationFailure>(
      verifier.verify(
        CertLists.wrongTrustAnchor,
        ChallengeMatcher(ByteString.copyFromUtf8("challenge")),
      )
    )
  }
}
