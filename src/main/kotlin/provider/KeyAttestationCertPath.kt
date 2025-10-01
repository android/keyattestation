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
import javax.security.auth.x500.X500Principal

/**
 * [CertPath] representing an Android key attestation certificate chain.
 *
 * The expected input is a full key attestation certificate chain (i.e. the output of
 * `KeyStore.getCertificateChain()`) in the following order:
 * 1. Leaf certificate (containing the extension)
 * 2. Attestation certificate (contains the ProvisioningInfo extension if remotely provisioned)
 * 3. Intermediate certificate (not present if software-backed attestation)
 * 4. [Intermediate certificate] (only present if remotely provisioned)
 * 5. Root certificate
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
    // < 3 check needed to support parsing software-backed certs.
    if (certs.size < 3) throw CertificateException("At least 3 certificates are required")
    when (certs.indexOfLast { it.hasAttestationExtension() }) {
      0 -> {} // expected value
      -1 -> throw CertificateException("Attestation extension not found")
      else ->
        if (certs[0].hasAttestationExtension())
          throw CertificateException("Additional attestation extension found")
        else throw CertificateException("Certificate after target certificate")
    }
    if (!certs.last().isSelfIssued()) throw CertificateException("Root certificate not found")
    this.certificatesWithAnchor = certs
  }

  constructor(vararg certificates: X509Certificate) : this(certificates.toList())

  override fun getEncodings(): Iterator<String> = throw UnsupportedOperationException()

  override fun getEncoded(): ByteArray = throw UnsupportedOperationException()

  override fun getEncoded(encoding: String): ByteArray = throw UnsupportedOperationException()

  override fun getCertificates(): List<X509Certificate> = certificatesWithAnchor.dropLast(1)

  fun provisioningMethod() =
    when {
      isFactoryProvisioned() -> ProvisioningMethod.FACTORY_PROVISIONED
      isRemoteProvisioned() -> ProvisioningMethod.REMOTELY_PROVISIONED
      else -> ProvisioningMethod.UNKNOWN
    }

  /**
   * Returns the leaf certificate from the certificate chain.
   *
   * It is expected that the leaf certificate will always be the first certificate in the chain. See
   * "Chain extension attack prevention" from go/how-to-validate-key-attestations for details.
   *
   * @return the leaf certificate from the chain if present, or null otherwise.
   */
  fun leafCert(): X509Certificate = certificates[0]

  fun attestationCert(): X509Certificate = certificates[1]

  fun intermediateCert(): X509Certificate = certificates.last()

  private fun isFactoryProvisioned(): Boolean {
    val rdn = parseDN(this.intermediateCert().subjectX500Principal.getName(X500Principal.RFC1779))
    return rdn.containsKey("OID.2.5.4.5") && rdn["OID.2.5.4.12"] in setOf("TEE", "StrongBox")
  }

  // TODO(google-internal bug): Update this to use fields in the RKP root.
  private fun isRemoteProvisioned(): Boolean {
    val rdn = parseDN(this.intermediateCert().subjectX500Principal.getName(X500Principal.RFC1779))
    return rdn["CN"] == "Droid CA2" && rdn["O"] == "Google LLC"
  }

  companion object {
    @JvmStatic
    @Throws(CertificateException::class)
    fun generateFrom(certs: List<ByteString>): KeyAttestationCertPath =
      KeyAttestationCertPath(certs.map { it.newInput().asX509Certificate() })

    private fun X509Certificate.isSelfIssued() = issuerX500Principal == subjectX500Principal
  }
}

enum class ProvisioningMethod {
  UNKNOWN,
  FACTORY_PROVISIONED,
  REMOTELY_PROVISIONED,
}

private fun parseDN(dn: String): Map<String, String> {
  val attributes = mutableMapOf<String, String>()
  val parts = dn.split(",")

  for (part in parts) {
    val keyValue = part.trim().split("=", limit = 2)
    if (keyValue.size == 2) {
      attributes[keyValue[0].trim()] = keyValue[1].trim()
    }
  }
  return attributes
}
