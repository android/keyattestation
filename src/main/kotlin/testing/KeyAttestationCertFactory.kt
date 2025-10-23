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
import com.android.keyattestation.verifier.Origin
import com.android.keyattestation.verifier.ProvisioningInfoMap
import com.android.keyattestation.verifier.RootOfTrust
import com.android.keyattestation.verifier.SecurityLevel
import com.android.keyattestation.verifier.VerifiedBootState
import com.google.protobuf.ByteString
import org.bouncycastle.asn1.ASN1ObjectIdentifier
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
  val rkpKey = ecKeyPairGenerator.generateKeyPair()
  val attestationKey = ecKeyPairGenerator.generateKeyPair()
  val leafKey: KeyPair = ecKeyPairGenerator.generateKeyPair()

  val root: X509Certificate = generateRootCertificate()
  val factoryIntermediate = generateIntermediateCertificate()
  val remoteIntermediate = generateIntermediateCertificate(subject = REMOTE_INTERMEDIATE_SUBJECT, rkp = true)
  val rkpIntermediate =
    generateIntermediateCertificate(
      publicKey = rkpKey.public,
      signingKey = intermediateKey.private,
      subject = RKP_INTERMEDIATE_SUBJECT,
      issuer = REMOTE_INTERMEDIATE_SUBJECT,
    )
  val strongBoxIntermediate =
    generateIntermediateCertificate(
      subject = X500Name("SERIALNUMBER=e18c4f2ca699739a, T=StrongBox")
    )
  val factoryAttestation = generateAttestationCert()

  internal fun generateRootCertificate(
    keyPair: KeyPair = rootKey,
    subject: X500Name = X500Name("SERIALNUMBER=badc0de"),
  ) =
    generateCertificate(
      keyPair.public,
      keyPair.private,
      subject = subject,
      issuer = subject,
      serialNumber = BigInteger.valueOf(0xca11cafe),
      notBefore = fakeCalendar.lastWeek(),
      notAfter = fakeCalendar.nextWeek(),
      extensions = listOf(BASIC_CONSTRAINTS_EXT),
    )

  internal fun generateIntermediateCertificate(
    publicKey: PublicKey = intermediateKey.public,
    signingKey: PrivateKey = rootKey.private,
    subject: X500Name = X500Name("SERIALNUMBER=e18c4f2ca699739a, T=TEE"),
    issuer: X500Name = this.root.subject,
    rkp: Boolean = false
  ) =
    generateCertificate(
      publicKey,
      signingKey,
      subject,
      issuer,
      serialNumber = BigInteger.valueOf(0x1234567890),
      notBefore = fakeCalendar.lastWeek(),
      notAfter = fakeCalendar.nextWeek(),
      extensions = if(rkp) listOf(BASIC_CONSTRAINTS_EXT, RKP_EXT) else listOf(BASIC_CONSTRAINTS_EXT),
    )

  internal fun generateRkpAttestationCert(
    securityLevel: SecurityLevel = SecurityLevel.TRUSTED_ENVIRONMENT,
    serialNumber: BigInteger,
  ) =
    generateAttestationCert(
      signingKey = rkpKey.private,
      subject = rkpAttestationName(securityLevel, serialNumber),
      issuer = rkpIntermediate.subject,
      serialNumber,
      extraExtension =
        Extension(
          ProvisioningInfoMap.OID,
          /* critical= */ false,
          ProvisioningInfoMap(
              certificatesIssued = 1,
            )
            .cborEncode(),
        ),
    )

  internal fun generateAttestationCert(
    signingKey: PrivateKey = intermediateKey.private,
    subject: X500Name = X500Name("serialNumber=decafbad"),
    issuer: X500Name = factoryIntermediate.subject,
    serialNumber: BigInteger = BigInteger.valueOf(0xcafbad),
    notBefore: Date = fakeCalendar.lastWeek(),
    notAfter: Date = fakeCalendar.nextWeek(),
    extraExtension: Extension? = null,
  ) =
    generateCertificate(
      attestationKey.public,
      signingKey,
      subject,
      issuer,
      serialNumber,
      notBefore,
      notAfter,
      extensions = listOfNotNull(BASIC_CONSTRAINTS_EXT, extraExtension),
    )

  internal fun rkpAttestationName(securityLevel: SecurityLevel, serialNumber: BigInteger) =
    when (securityLevel) {
      SecurityLevel.TRUSTED_ENVIRONMENT ->
        X500Name("O=TEE,CN=${serialNumber.toString(/*radix= */ 16)}")
      SecurityLevel.STRONG_BOX ->
        X500Name("O=StrongBox,CN=${serialNumber.toString(/*radix= */ 16)}")
      else -> X500Name("O=Unknown,CN=fff0000ddd")
    }

  private val KEY_DESCRIPTION_EXT =
    KeyDescription(
        attestationVersion = 1.toBigInteger(),
        attestationSecurityLevel = SecurityLevel.TRUSTED_ENVIRONMENT,
        keyMintVersion = 1.toBigInteger(),
        keyMintSecurityLevel = SecurityLevel.TRUSTED_ENVIRONMENT,
        attestationChallenge = ByteString.copyFromUtf8("A random 40-byte challenge for no reason"),
        uniqueId = ByteString.empty(),
        softwareEnforced = AuthorizationList(),
        hardwareEnforced =
          AuthorizationList(
            rootOfTrust =
              RootOfTrust(
                ByteString.copyFromUtf8("bootKey"),
                false,
                VerifiedBootState.VERIFIED,
                ByteString.copyFromUtf8("bootHash"),
              ),
            origin = Origin.GENERATED,
          ),
      )
      .asExtension()

  internal val STRONG_BOX_KEY_DESCRIPTION_EXT =
    KeyDescription(
        attestationVersion = 400.toBigInteger(),
        attestationSecurityLevel = SecurityLevel.STRONG_BOX,
        keyMintVersion = 400.toBigInteger(),
        keyMintSecurityLevel = SecurityLevel.STRONG_BOX,
        attestationChallenge = ByteString.copyFromUtf8("yak city"),
        uniqueId = ByteString.empty(),
        softwareEnforced = AuthorizationList(),
        hardwareEnforced =
          AuthorizationList(
            rootOfTrust =
              RootOfTrust(
                ByteString.copyFromUtf8("bootKey"),
                false,
                VerifiedBootState.VERIFIED,
                ByteString.copyFromUtf8("bootHash"),
              ),
            origin = Origin.GENERATED,
          ),
      )
      .asExtension()

  internal fun generateLeafCert(
    publicKey: PublicKey = leafKey.public,
    signingKey: PrivateKey = attestationKey.private,
    subject: X500Name = X500Name("CN=Android Keystore Key"),
    issuer: X500Name = Certs.factoryAttestation.subject,
    notBefore: Date = this.fakeCalendar.lastWeek(),
    notAfter: Date = this.fakeCalendar.nextWeek(),
    extension: Extension? = KEY_DESCRIPTION_EXT,
  ): X509Certificate =
    generateCertificate(
      publicKey,
      signingKey,
      subject,
      issuer,
      serialNumber = BigInteger.ONE,
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
      val RKP_EXT =
          Extension(
              ProvisioningInfoMap.OID,
              /* critical= */ false,
              "040da2011880036773616d73756e67".hexToByteArray() /*taken from a real samsung device*/,
          )
    val RKP_INTERMEDIATE_SUBJECT = X500Name("O=Google LLC, CN=Droid CA3")
    val REMOTE_INTERMEDIATE_SUBJECT = X500Name("CN=Droid CA2, O=Google LLC")
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
