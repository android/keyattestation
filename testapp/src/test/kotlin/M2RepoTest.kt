/*
 * Copyright 2026 Google LLC
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

package com.android.keyattestation.verifier.testapp

import com.android.keyattestation.verifier.GoogleTrustAnchors
import com.android.keyattestation.verifier.SecurityLevel
import com.android.keyattestation.verifier.VerificationResult
import com.android.keyattestation.verifier.VerifiedBootState
import com.android.keyattestation.verifier.Verifier
import com.android.keyattestation.verifier.testing.TestUtils
import com.google.common.truth.Truth.assertThat
import kotlin.test.assertIs
import org.junit.Test
import org.junit.runner.RunWith
import org.junit.runners.JUnit4

@RunWith(JUnit4::class)
class M2RepoTest {
  @Test
  fun verify_validChainFromM2Repo_returnsSuccess() {
    val certs = TestUtils.readCertList("tegu/sdk36/TEE_EC_2026_ROOT.pem")
    val notBefore = certs[1].notBefore.toInstant()
    val notAfter = certs[1].notAfter.toInstant()
    val validTime = notBefore.plusMillis((notAfter.toEpochMilli() - notBefore.toEpochMilli()) / 2)

    val verifier =
      Verifier(
        trustAnchorsSource = GoogleTrustAnchors,
        revokedSerialsSource = { emptySet() },
        instantSource = { validTime },
      )
    val result = assertIs<VerificationResult.Success>(verifier.verify(certs))

    assertThat(result.securityLevel).isEqualTo(SecurityLevel.TRUSTED_ENVIRONMENT)
    assertThat(result.verifiedBootState).isEqualTo(VerifiedBootState.VERIFIED)
  }
}
