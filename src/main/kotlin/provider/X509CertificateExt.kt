package com.android.keyattestation.verifier.provider

import java.security.cert.X509Certificate
import javax.security.auth.x500.X500Principal

private const val KEY_DESCRIPTION_OID = "1.3.6.1.4.1.11129.2.1.17"

internal fun X509Certificate.hasAttestationExtension() =
  nonCriticalExtensionOIDs?.contains(KEY_DESCRIPTION_OID) ?: false

enum class ProvisioningMethod {
  UNKNOWN,
  FACTORY_PROVISIONED,
  REMOTELY_PROVISIONED,
}

fun X509Certificate.provisioningMethod(): ProvisioningMethod {
  val rdn = parseDN(this.subjectX500Principal.getName(X500Principal.RFC1779))
  return when {
    isFactoryProvisioned(rdn) -> ProvisioningMethod.FACTORY_PROVISIONED
    isRemoteProvisioned(rdn) -> ProvisioningMethod.REMOTELY_PROVISIONED
    else -> ProvisioningMethod.UNKNOWN
  }
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

private fun isFactoryProvisioned(rdn: Map<String, String>) =
  rdn.containsKey("OID.2.5.4.5") && rdn["OID.2.5.4.12"] in setOf("TEE", "StrongBox")

private fun isRemoteProvisioned(rdn: Map<String, String>) =
  rdn.containsKey("CN") && rdn.containsKey("O")
