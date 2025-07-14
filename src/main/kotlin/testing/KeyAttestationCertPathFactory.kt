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

import com.android.keyattestation.verifier.KeyDescription
import com.android.keyattestation.verifier.ProvisioningInfoMap
import com.android.keyattestation.verifier.provider.KeyAttestationCertPath
import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.asn1.x509.Extension

class KeyAttestationCertPathFactory(val fakeCalendar: FakeCalendar = FakeCalendar()) {
  private val certFactory: KeyAttestationCertFactory =
    KeyAttestationCertFactory(fakeCalendar = fakeCalendar)

  @JvmOverloads
  fun generateCertPath(
    keyDescription: KeyDescription,
    remotelyProvisioned: Boolean = false,
  ): KeyAttestationCertPath {
    if (remotelyProvisioned) {
      val rkpKey = certFactory.generateEcKeyPair()
      val rkpIntermediate =
        certFactory.generateIntermediateCertificate(
          publicKey = rkpKey.public,
          signingKey = certFactory.intermediateKey.private,
          subject = X500Name("CN=RKP"),
          issuer = certFactory.remoteIntermediate.subject,
        )
      val attestationCertWithProvisioningInfoExt =
        certFactory.generateAttestationCert(
          signingKey = rkpKey.private,
          issuer = rkpIntermediate.subject,
          extraExtension =
            Extension(
              ObjectIds.PROVISIONING_INFO,
              /* critical= */ false,
              ProvisioningInfoMap(
                  certificatesIssued = 1,
                )
                .encodeToAsn1(),
            ),
        )
      return KeyAttestationCertPath(
        certFactory.generateLeafCert(extension = keyDescription.asExtension()),
        attestationCertWithProvisioningInfoExt,
        rkpIntermediate,
        certFactory.remoteIntermediate,
        certFactory.root,
      )
    } else {
      return KeyAttestationCertPath(
        certFactory.generateLeafCert(extension = keyDescription.asExtension()),
        certFactory.generateAttestationCert(),
        certFactory.factoryIntermediate,
        certFactory.root,
      )
    }
  }
}
