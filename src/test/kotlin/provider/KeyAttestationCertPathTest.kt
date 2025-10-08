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

package com.android.keyattestation.verifier.provider

import com.android.keyattestation.verifier.testing.CertLists
import com.android.keyattestation.verifier.testing.TestUtils.readCertPath
import com.google.common.truth.Truth.assertThat
import com.google.protobuf.ByteString
import com.google.testing.junit.testparameterinjector.TestParameter
import com.google.testing.junit.testparameterinjector.TestParameterInjector
import java.security.cert.CertificateException
import java.security.cert.X509Certificate
import kotlin.test.assertFailsWith
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(TestParameterInjector::class)
class KeyAttestationCertPathTest {
  @Test
  fun constructor_noleaf_throwsCertificateException() {
    assertFailsWith<CertificateException> {
      KeyAttestationCertPath(CertLists.validFactoryProvisioned.drop(1))
    }
  }

  @Test
  fun constructor_noRoot_throwsException() {
    assertFailsWith<CertificateException> {
      KeyAttestationCertPath(CertLists.validFactoryProvisioned.dropLast(1))
    }
  }

  @Test
  fun constructor_tooShort_throwsException() {
    assertFailsWith<CertificateException> {
      KeyAttestationCertPath(
        CertLists.validFactoryProvisioned.first(),
        CertLists.validFactoryProvisioned.last(),
      )
    }
  }

  @Test
  fun constructor_extraLeaf_throwsCertificateException() {
    assertFailsWith<CertificateException> { KeyAttestationCertPath(CertLists.extended) }
  }

  @Test
  fun generateFrom() {
    val unused =
      KeyAttestationCertPath.generateFrom(
        CertLists.validFactoryProvisioned.map(X509Certificate::getEncoded).map(ByteString::copyFrom)
      )
  }

  @Test
  fun generateFrom_throwsCertificateException() {
    assertFailsWith<CertificateException> {
      KeyAttestationCertPath.generateFrom(listOf(ByteString.copyFromUtf8("#NotACert")))
    }
  }

  @Test
  fun getEncodings_throwsUnsupportedOperationException() {
    assertFailsWith<UnsupportedOperationException> {
      KeyAttestationCertPath(CertLists.validFactoryProvisioned).getEncodings()
    }
  }

  @Test
  fun getEncoded_throwsUnsupportedOperationException() {
    assertFailsWith<UnsupportedOperationException> {
      KeyAttestationCertPath(CertLists.validFactoryProvisioned).getEncoded()
    }
    assertFailsWith<UnsupportedOperationException> {
      KeyAttestationCertPath(CertLists.validFactoryProvisioned).getEncoded("null")
    }
  }

  @Test
  fun getCertificates_inCorrectOrderWithoutRoot() {
    assertThat(KeyAttestationCertPath(CertLists.validFactoryProvisioned).getCertificates())
      .containsExactlyElementsIn(CertLists.validFactoryProvisioned.dropLast(1))
      .inOrder()
  }

  @Test
  fun leafCert_returnsExpectedCert() {
    assertThat(KeyAttestationCertPath(CertLists.validFactoryProvisioned).leafCert())
      .isEqualTo(CertLists.validFactoryProvisioned.first())
  }

  @Test
  fun provisioningMethod_returnsExpectedType(@TestParameter testCase: ProvisioningMethodTestCase) {
    val certPath = readCertPath("${testCase.path}.pem")
    assertThat(certPath.provisioningMethod()).isEqualTo(testCase.expected)
  }

  enum class ProvisioningMethodTestCase(val path: String, val expected: ProvisioningMethod) {
    FACTORY_PROVISIONED("blueline/sdk28/TEE_EC_NONE", ProvisioningMethod.FACTORY_PROVISIONED),
    REMOTELY_PROVISIONED("caiman/sdk36/TEE_EC_RKP", ProvisioningMethod.REMOTELY_PROVISIONED),
    UNKNOWN("marlin/sdk29/TEE_EC_NONE", ProvisioningMethod.UNKNOWN),
  }
}
