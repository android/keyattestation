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

package com.android.keyattestation.verifier.testing

import com.android.keyattestation.verifier.AuthorizationList
import com.android.keyattestation.verifier.KeyDescription
import com.android.keyattestation.verifier.SecurityLevel
import com.google.protobuf.ByteString
import java.math.BigInteger
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.PrivateKey
import java.security.PublicKey
import java.security.cert.X509Certificate
import java.security.interfaces.ECPrivateKey
import java.security.interfaces.RSAPrivateKey
import java.security.spec.ECGenParameterSpec
import java.security.spec.RSAKeyGenParameterSpec
import java.util.Date
import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.asn1.x509.BasicConstraints
import org.bouncycastle.asn1.x509.Extension
import org.bouncycastle.cert.X509CertificateHolder
import org.bouncycastle.cert.X509v3CertificateBuilder
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder
import org.bouncycastle.operator.ContentSigner
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder

internal class KeyAttestationCertFactory(val fakeCalendar: FakeCalendar = FakeCalendar.DEFAULT) {
  private val ecKeyPairGenerator =
    KeyPairGenerator.getInstance("EC").apply {
      initialize(ECGenParameterSpec("secp256r1"), FakeSecureRandom())
    }

  internal fun generateEcKeyPair() = ecKeyPairGenerator.generateKeyPair()

  private val rsaKeyPairGenerator =
    KeyPairGenerator.getInstance("RSA").apply {
      initialize(RSAKeyGenParameterSpec(512, RSAKeyGenParameterSpec.F4), FakeSecureRandom())
    }

  internal fun generateRsaKeyPair() = rsaKeyPairGenerator.generateKeyPair()

  val rootKey = ecKeyPairGenerator.generateKeyPair()
  val intermediateKey = ecKeyPairGenerator.generateKeyPair()
  val attestationKey = ecKeyPairGenerator.generateKeyPair()
  val leafKey: KeyPair = ecKeyPairGenerator.generateKeyPair()

  val root: X509Certificate = generateRootCertificate()
  val factoryIntermediate = generateIntermediateCertificate()
  val remoteIntermediate =
    generateIntermediateCertificate(subject = X500Name("O=Google LLC, CN=Droid CA9000"))
  val attestation = generateAttestationCert()

  internal fun generateRootCertificate(
    keyPair: KeyPair = rootKey,
    subject: X500Name = X500Name("SERIALNUMBER=badc0de"),
  ) =
    generateCertificate(
      keyPair.public,
      keyPair.private,
      subject,
      subject,
      serialNumber = BigInteger.ZERO,
      notBefore = fakeCalendar.yesterday(),
      notAfter = fakeCalendar.tomorrow(),
      extensions = listOf(BASIC_CONSTRAINTS_EXT),
    )

  internal fun generateIntermediateCertificate(
    publicKey: PublicKey = intermediateKey.public,
    signingKey: PrivateKey = rootKey.private,
    subject: X500Name = X500Name("SERIALNUMBER=e18c4f2ca699739a, T=TEE"),
    issuer: X500Name = this.root.subject,
  ) =
    generateCertificate(
      publicKey,
      signingKey,
      subject,
      issuer,
      serialNumber = BigInteger.ZERO,
      notBefore = fakeCalendar.yesterday(),
      notAfter = fakeCalendar.tomorrow(),
      extensions = listOf(BASIC_CONSTRAINTS_EXT),
    )

  internal fun generateAttestationCert(
    signingKey: PrivateKey = intermediateKey.private,
    issuer: X500Name = factoryIntermediate.subject,
    serialNumber: BigInteger = BigInteger.ZERO,
    notBefore: Date = fakeCalendar.yesterday(),
    notAfter: Date = fakeCalendar.tomorrow(),
    extraExtension: Extension? = null,
  ) =
    generateCertificate(
      attestationKey.public,
      signingKey,
      X500Name("serialNumber=decafbad"),
      issuer,
      serialNumber,
      notBefore,
      notAfter,
      extensions = listOfNotNull(BASIC_CONSTRAINTS_EXT, extraExtension),
    )

  private val KEY_DESCRIPTION_EXT =
    KeyDescription(
        attestationVersion = 1.toBigInteger(),
        attestationSecurityLevel = SecurityLevel.TRUSTED_ENVIRONMENT,
        keymasterVersion = 1.toBigInteger(),
        keymasterSecurityLevel = SecurityLevel.TRUSTED_ENVIRONMENT,
        attestationChallenge = ByteString.copyFromUtf8("challenge"),
        uniqueId = ByteString.empty(),
        softwareEnforced = AuthorizationList(),
        teeEnforced = AuthorizationList(),
      )
      .asExtension()

  internal fun generateLeafCert(
    publicKey: PublicKey = leafKey.public,
    signingKey: PrivateKey = attestationKey.private,
    subject: X500Name = X500Name("CN=Android Keystore Key"),
    issuer: X500Name = Certs.attestation.subject,
    notBefore: Date = this.fakeCalendar.yesterday(),
    notAfter: Date = this.fakeCalendar.tomorrow(),
    extension: Extension? = KEY_DESCRIPTION_EXT,
  ): X509Certificate =
    generateCertificate(
      publicKey,
      signingKey,
      subject,
      issuer,
      serialNumber = BigInteger.ZERO,
      notBefore = notBefore,
      notAfter = notAfter,
      extensions = extension?.let { listOf(it) } ?: emptyList(),
    )

  private fun generateCertificate(
    publicKey: PublicKey,
    signingKey: PrivateKey,
    subject: X500Name,
    issuer: X500Name,
    serialNumber: BigInteger,
    notBefore: Date,
    notAfter: Date,
    extensions: List<Extension> = emptyList<Extension>(),
  ): X509Certificate {
    val builder =
      JcaX509v3CertificateBuilder(issuer, serialNumber, notBefore, notAfter, subject, publicKey)
    extensions.forEach(builder::addExtension)
    return builder.sign(signingKey.asSigner())
  }

  companion object {
    val BASIC_CONSTRAINTS_EXT =
      Extension(
        Extension.basicConstraints,
        /* critical= */ true,
        BasicConstraints(/* cA= */ true).encoded,
      )
  }
}

private fun PrivateKey.asSigner(): ContentSigner {
  val signatureAlgorithm =
    when (this) {
      is ECPrivateKey -> "SHA256WithECDSA"
      is RSAPrivateKey -> "SHA256WithRSA"
      else -> throw IllegalArgumentException("Unsupported private key type: ${this::class}")
    }
  return JcaContentSignerBuilder(signatureAlgorithm).build(this)
}

private fun X509CertificateHolder.asX509Certificate() =
  JcaX509CertificateConverter().getCertificate(this)

private fun X509v3CertificateBuilder.sign(signer: ContentSigner) =
  this.build(signer).asX509Certificate()
