package com.android.keyattestation.verifier.provider

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
