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

import com.android.keyattestation.verifier.provider.KeyAttestationCertPath
import java.security.cert.TrustAnchor
import org.bouncycastle.asn1.ASN1ObjectIdentifier
import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.asn1.x509.Extension

object ObjectIds {
  internal val KEY_DESCRIPTION = ASN1ObjectIdentifier("1.3.6.1.4.1.11129.2.1.17")
  internal val PROVISIONING_INFO = ASN1ObjectIdentifier("1.3.6.1.4.1.11129.2.1.30")
}

private val certFactory = KeyAttestationCertFactory()
private val fakeCalendar = certFactory.fakeCalendar

object Certs {
  val root = certFactory.root
  val rootAnchor = TrustAnchor(certFactory.root, null)
  val factoryIntermediate = certFactory.factoryIntermediate
  val remoteIntermediate = certFactory.remoteIntermediate
  val attestation = certFactory.attestation
}

/**
 * "Certificate lists" for testing [CertPath] construction
 *
 * A list of [X509Certificate]s in the order they are generated by Android Keystore.
 */
object CertLists {
  val noLeaf by lazy { listOf(Certs.attestation, Certs.factoryIntermediate, certFactory.root) }

  val extended by lazy {
    val leafCert = certFactory.generateLeafCert()
    listOf(
      certFactory.generateLeafCert(
        certFactory.leafKey.public,
        certFactory.leafKey.private,
        leafCert.subject,
      ),
      leafCert,
      Certs.attestation,
      Certs.factoryIntermediate,
      certFactory.root,
    )
  }

  @JvmStatic
  val validFactoryProvisioned by lazy {
    listOf(
      certFactory.generateLeafCert(),
      Certs.attestation,
      Certs.factoryIntermediate,
      certFactory.root,
    )
  }

  val validRemotelyProvisioned by lazy {
    val rkpKey = certFactory.generateEcKeyPair()
    val rkpName = X500Name("CN=RKP")
    val rkpIntermediate =
      certFactory.generateIntermediateCertificate(
        publicKey = rkpKey.public,
        signingKey = certFactory.intermediateKey.private,
        subject = rkpName,
        issuer = Certs.remoteIntermediate.subject,
      )
    val attestationCertWithProvisioningInfoExt =
      certFactory.generateAttestationCert(
        signingKey = rkpKey.private,
        issuer = rkpIntermediate.subject,
        extraExtension =
          Extension(ObjectIds.PROVISIONING_INFO, /* critical= */ false, byteArrayOf()),
      )
    listOf(
      certFactory.generateLeafCert(),
      attestationCertWithProvisioningInfoExt,
      rkpIntermediate,
      Certs.remoteIntermediate,
      certFactory.root,
    )
  }

  val wrongTrustAnchor by lazy {
    val anchorKeyPair = certFactory.generateEcKeyPair()
    val anchorSubject = X500Name("SERIALNUMBER=g00dc0de")
    listOf(
      certFactory.generateLeafCert(),
      Certs.attestation,
      certFactory.generateIntermediateCertificate(
        signingKey = anchorKeyPair.private,
        issuer = anchorSubject,
      ),
      certFactory.generateRootCertificate(keyPair = anchorKeyPair, subject = anchorSubject),
    )
  }
}

object Chains {
  @JvmStatic val validFactoryProvisioned = KeyAttestationCertPath(CertLists.validFactoryProvisioned)

  @JvmStatic
  val validRemotelyProvisioned by lazy {
    KeyAttestationCertPath(CertLists.validRemotelyProvisioned)
  }

  @JvmStatic val wrongTrustAnchor by lazy { KeyAttestationCertPath(CertLists.wrongTrustAnchor) }

  val wrongIntermediateSubject by lazy {
    KeyAttestationCertPath(
      certFactory.generateLeafCert(),
      Certs.attestation,
      certFactory.generateIntermediateCertificate(subject = X500Name("O=Unexpected Inc.")),
      certFactory.root,
    )
  }

  @JvmStatic
  val wrongIssuer by lazy {
    KeyAttestationCertPath(
      certFactory.generateLeafCert(issuer = X500Name("O=Unexpected Inc.")),
      Certs.attestation,
      Certs.factoryIntermediate,
      certFactory.root,
    )
  }

  @JvmStatic
  val wrongSignature by lazy {
    KeyAttestationCertPath(
      certFactory.generateLeafCert(signingKey = certFactory.generateEcKeyPair().private),
      Certs.attestation,
      Certs.factoryIntermediate,
      certFactory.root,
    )
  }

  val wrongAlgorithm by lazy {
    KeyAttestationCertPath(
      certFactory.generateLeafCert(signingKey = certFactory.generateRsaKeyPair().private),
      Certs.attestation,
      Certs.factoryIntermediate,
      certFactory.root,
    )
  }

  val notYetValid by lazy {
    KeyAttestationCertPath(
      certFactory.generateLeafCert(),
      certFactory.generateAttestationCert(
        notBefore = fakeCalendar.tomorrow(),
        notAfter = fakeCalendar.tomorrow(),
      ),
      Certs.factoryIntermediate,
      certFactory.root,
    )
  }

  @JvmStatic
  val expired by lazy {
    KeyAttestationCertPath(
      certFactory.generateLeafCert(),
      certFactory.generateAttestationCert(
        notBefore = fakeCalendar.yesterday(),
        notAfter = fakeCalendar.yesterday(),
      ),
      Certs.factoryIntermediate,
      certFactory.root,
    )
  }

  val expiredLeaf by lazy {
    KeyAttestationCertPath(
      certFactory.generateLeafCert(
        notBefore = fakeCalendar.yesterday(),
        notAfter = fakeCalendar.yesterday(),
      ),
      Certs.attestation,
      Certs.factoryIntermediate,
      certFactory.root,
    )
  }

  @JvmStatic
  val unparseableExtension by lazy {
    KeyAttestationCertPath(
      certFactory.generateLeafCert(
        extension =
          Extension(ObjectIds.KEY_DESCRIPTION, /* critical= */ false, byteArrayOf(0x42, 0x42))
      ),
      Certs.attestation,
      Certs.factoryIntermediate,
      certFactory.root,
    )
  }

  @JvmField val REVOKED_SERIAL_NUMBER = 42.toBigInteger()
  @JvmField val REVOKED_SERIAL_NUMBER_BIG = 8000000000000.toBigInteger()
  @JvmField
  val REVOKED_SERIAL_NUMBER_LONG_STRING = "c35747a084470c3135aeefe2b8d40cd6".toBigInteger(16)
  @JvmField val REVOKED_SERIAL_NUMBER_ODD_LENGTH = 1228286566665971148.toBigInteger()

  @JvmStatic
  val revoked by lazy {
    KeyAttestationCertPath(
      certFactory.generateLeafCert(),
      certFactory.generateAttestationCert(serialNumber = REVOKED_SERIAL_NUMBER),
      Certs.factoryIntermediate,
      certFactory.root,
    )
  }

  val forgedKeybox by lazy {
    val compromisedAttestationKey = certFactory.generateEcKeyPair()
    val name = X500Name("O=Honest Achmed's Used Cars and Certificates")
    KeyAttestationCertPath(
      certFactory.generateLeafCert(),
      // Attestation certificate signed by the attacker created keybox
      certFactory.generateAttestationCert(
        signingKey = compromisedAttestationKey.private,
        issuer = name,
      ),
      // Attacker created keybox signed by the compromised keybox
      certFactory.generateIntermediateCertificate(
        compromisedAttestationKey.public,
        certFactory.intermediateKey.private,
        subject = name,
        issuer = Certs.factoryIntermediate.subject,
      ),
      // Google signed keybox that was compromised
      Certs.factoryIntermediate,
      // Google signed root certificate
      Certs.root,
    )
  }
}
