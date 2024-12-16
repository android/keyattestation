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

import com.android.keyattestation.verifier.asX509Certificate
import com.google.protobuf.ByteString
import java.security.cert.CertPath
import java.security.cert.CertificateException
import java.security.cert.X509Certificate

/**
 * [CertPath] representing an Android key attestation certificate chain.
 *
 * The expected input is a full key attestation certificate chain (i.e. the output of
 * `KeyStore.getCertificateChain()`) in the following order:
 * 1. Leaf certificate (containing the extension)
 * 2. Attestation certificate (contains the ProvisioningInfo extension if remotely provisioned)
 * 3. Intermediate certificate
 * 5. [Intermediate certificate] (if remotely provisioned)
 * 4. Root certificate
 *
 * The last certificate in the chain is the trust anchor and is not included in the resulting
 * [CertPath]: "By convention, the certificates in a CertPath object of type X.509 are ordered
 * starting with the target certificate and ending with a certificate issued by the trust anchor.
 * That is, the issuer of one certificate is the subject of the following one. The certificate
 * representing the TrustAnchor should not be included in the certification path."
 *
 * https://docs.oracle.com/en/java/javase/21/security/java-pki-programmers-guide.html#GUID-E47B8A0E-6B3A-4B49-994D-CF185BF441EC
 */
class KeyAttestationCertPath(certs: List<X509Certificate>) : CertPath("X.509") {
  val certificatesWithAnchor: List<X509Certificate>

  init {
    if (certs.size < 3) throw CertificateException("At least 3 certificates are required")
    when (certs.indexOfLast { it.hasAttestationExtension() }) {
      0 -> {} // expected value
      -1 -> throw CertificateException("Attestation extension not found")
      else -> throw CertificateException("Attestation extension on unexpected certificate")
    }
    if (!certs.last().isSelfIssued()) throw CertificateException("Root certificate not found")
    this.certificatesWithAnchor = certs
  }

  constructor(vararg certificates: X509Certificate) : this(certificates.toList())

  override fun getEncodings(): Iterator<String> = throw UnsupportedOperationException()

  override fun getEncoded(): ByteArray = throw UnsupportedOperationException()

  override fun getEncoded(encoding: String): ByteArray = throw UnsupportedOperationException()

  override fun getCertificates(): List<X509Certificate> = certificatesWithAnchor.dropLast(1)

  /**
   * Returns true if the attestation certificate was remotely provisioned.
   *
   * Key Attestation certificates can either be provisioned at the factory or remotely. A factory
   * provisioned certificate is static for the lifetime of the device and shares a key pair with a
   * large number of devices. Remotely provisioned certificates are short-lived and are
   * authenticated by a device unique key.
   *
   * Remotely provisioned certificates can be identified by the presence of the "provisioning
   * information" extension.
   *
   * https://source.android.com/docs/security/features/keystore/attestation#provisioninginfo_extension
   *
   * @return true if an attestation certificate is present in the chain and was remotely
   *   provisioned, or false otherwise.
   */
  fun isRemotelyProvisioned(): Boolean =
    attestationCert().getExtensionValue(PROVISIONING_INFO_OID) != null

  /**
   * Returns the leaf certificate from the certificate chain.
   *
   * It is expected that the leaf certificate will always be the first certificate in the chain. See
   * "Chain extension attack prevention" from go/how-to-validate-key-attestations for details.
   *
   * @return the leaf certificate from the chain if present, or null otherwise.
   */
  fun leafCert(): X509Certificate = certificates[0]

  private fun attestationCert(): X509Certificate = certificates[1]

  companion object {
    private const val KEY_DESCRIPTION_OID = "1.3.6.1.4.1.11129.2.1.17"
    private const val PROVISIONING_INFO_OID = "1.3.6.1.4.1.11129.2.1.30"

    @JvmStatic
    @Throws(CertificateException::class)
    fun generateFrom(certs: List<ByteString>): KeyAttestationCertPath =
      KeyAttestationCertPath(certs.map { it.newInput().asX509Certificate() })

    private fun X509Certificate.isSelfIssued() = issuerX500Principal == subjectX500Principal

    private fun X509Certificate.hasAttestationExtension() =
      nonCriticalExtensionOIDs?.contains(KEY_DESCRIPTION_OID) ?: false
  }
}
