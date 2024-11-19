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
import com.google.common.truth.Truth.assertThat
import com.google.protobuf.ByteString
import java.security.cert.CertificateException
import java.security.cert.X509Certificate
import kotlin.test.assertFailsWith
import org.junit.Test
import org.junit.runner.RunWith
import org.junit.runners.JUnit4

@RunWith(JUnit4::class)
class KeyAttestationCertPathTest {
  @Test
  fun constructor_noleaf_throwsCertificateException() {
    assertFailsWith<CertificateException> { KeyAttestationCertPath(CertLists.valid.drop(1)) }
  }

  @Test
  fun constructor_noRoot_throwsException() {
    assertFailsWith<CertificateException> { KeyAttestationCertPath(CertLists.valid.dropLast(1)) }
  }

  @Test
  fun constructor_tooShort_throwsException() {
    assertFailsWith<CertificateException> {
      KeyAttestationCertPath(CertLists.valid.first(), CertLists.valid.last())
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
        CertLists.valid.map(X509Certificate::getEncoded).map(ByteString::copyFrom)
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
      KeyAttestationCertPath(CertLists.valid).getEncodings()
    }
  }

  @Test
  fun getEncoded_throwsUnsupportedOperationException() {
    assertFailsWith<UnsupportedOperationException> {
      KeyAttestationCertPath(CertLists.valid).getEncoded()
    }
    assertFailsWith<UnsupportedOperationException> {
      KeyAttestationCertPath(CertLists.valid).getEncoded("null")
    }
  }

  @Test
  fun getCertificates_inCorrectOrderWithoutRoot() {
    assertThat(KeyAttestationCertPath(CertLists.valid).getCertificates())
      .containsExactlyElementsIn(CertLists.valid.dropLast(1))
      .inOrder()
  }

  @Test
  fun leafCert_returnsExpectedCert() {
    assertThat(KeyAttestationCertPath(CertLists.valid).leafCert())
      .isEqualTo(CertLists.valid.first())
  }

  @Test
  fun isRemotelyProvisioned_returnsTrue() {
    assertThat(KeyAttestationCertPath(CertLists.remotelyProvisioned).isRemotelyProvisioned())
      .isTrue()
  }

  @Test
  fun isRemotelyProvisioned_returnsFalse() {
    assertThat(KeyAttestationCertPath(CertLists.valid).isRemotelyProvisioned()).isFalse()
  }
}
