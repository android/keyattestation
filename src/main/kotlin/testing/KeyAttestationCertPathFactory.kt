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
import com.android.keyattestation.verifier.SecurityLevel
import com.android.keyattestation.verifier.provider.KeyAttestationCertPath
import java.math.BigInteger
import java.security.PublicKey

/**
 * Factory for creating valid [KeyAttestationCertPath] chains for testing.
 *
 * @param fakeCalendar the fake calendar for the certificate chains validity period.
 */
class KeyAttestationCertPathFactory(val fakeCalendar: FakeCalendar = FakeCalendar()) {
  private val certFactory: KeyAttestationCertFactory =
    KeyAttestationCertFactory(fakeCalendar = fakeCalendar)

  /* The root certificate of all generated certificate chains. */
  val root = certFactory.root
  /* The root key of all generated certificate chains. */
  val rootKey = certFactory.rootKey

  @JvmOverloads
  /* Generates a valid certificate chain for the given parameters. */
  fun generateCertPath(
    keyDescription: KeyDescription,
    remotelyProvisioned: Boolean = false,
    leafKey: PublicKey = certFactory.leafKey.public,
  ): KeyAttestationCertPath {
    if (remotelyProvisioned) {
      val attestationSerialNumber = BigInteger.valueOf(0xf00d)
      return KeyAttestationCertPath(
        certFactory.generateLeafCert(
          extension = keyDescription.asExtension(),
          publicKey = leafKey,
          issuer =
            certFactory.rkpAttestationName(
              keyDescription.attestationSecurityLevel,
              attestationSerialNumber,
            ),
        ),
        certFactory.generateRkpAttestationCert(
          keyDescription.attestationSecurityLevel,
          attestationSerialNumber,
        ),
        certFactory.rkpIntermediate,
        certFactory.remoteIntermediate,
        certFactory.root,
      )
    } else if (keyDescription.attestationSecurityLevel == SecurityLevel.STRONG_BOX) {
      return KeyAttestationCertPath(
        certFactory.generateLeafCert(extension = keyDescription.asExtension(), publicKey = leafKey),
        certFactory.generateAttestationCert(issuer = certFactory.strongBoxIntermediate.subject),
        certFactory.strongBoxIntermediate,
        certFactory.root,
      )
    } else {
      return KeyAttestationCertPath(
        certFactory.generateLeafCert(extension = keyDescription.asExtension(), publicKey = leafKey),
        certFactory.generateAttestationCert(),
        certFactory.factoryIntermediate,
        certFactory.root,
      )
    }
  }
}
