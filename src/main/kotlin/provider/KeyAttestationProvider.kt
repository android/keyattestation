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

package com.google.wireless.android.security.attestationverifier.provider

import java.security.Provider
import java.security.ProviderException

/**
 * A JCA provider for verifying Android Key Attestation certificates chains.
 *
 * https://docs.oracle.com/en/java/javase/21/security/howtoimplaprovider.html
 */
class KeyAttestationProvider :
    Provider("KeyAttestation", "0.1", "Android Key Attestation Provider") {
    init {
        putService(
            ProviderService(
                this,
                "CertPathValidator",
                "KeyAttestation",
                "com.google.wireless.android.security.attestationverifier.provider.KeyAttestationCertPathValidator",
            )
        )
    }
}

private class ProviderService(
    provider: Provider,
    type: String,
    algorithm: String,
    className: String,
) : Provider.Service(provider, type, algorithm, className, null, null) {
    override fun newInstance(constructorParameter: Any?): Any {
        if (type == "CertPathValidator" && algorithm == "KeyAttestation") {
            return KeyAttestationCertPathValidator()
        }
        throw ProviderException("No implementation for $type.$algorithm")
    }
}