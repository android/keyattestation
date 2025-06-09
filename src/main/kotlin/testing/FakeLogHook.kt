package com.android.keyattestation.verifier.testing

import com.android.keyattestation.verifier.KeyDescription
import com.android.keyattestation.verifier.LogHook
import com.android.keyattestation.verifier.ProvisioningInfoMap
import com.android.keyattestation.verifier.VerificationResult
import com.google.protobuf.ByteString

/**  */
class FakeLogHook : LogHook {
  var inputChain = mutableListOf<ByteString>()
  var result: VerificationResult? = null
  var keyDescription: KeyDescription? = null
  var provisioningInfoMap: ProvisioningInfoMap? = null
  var certSerialNumbers = mutableListOf<String>()
  var infoMessages = mutableListOf<String>()

  override fun logInputChain(inputChain: List<ByteString>) {
    this.inputChain.addAll(inputChain)
  }

  override fun logResult(result: VerificationResult) {
    this.result = result
  }

  override fun logKeyDescription(keyDescription: KeyDescription) {
    this.keyDescription = keyDescription
  }

  override fun logProvisioningInfoMap(provisioningInfoMap: ProvisioningInfoMap) {
    this.provisioningInfoMap = provisioningInfoMap
  }

  override fun logCertSerialNumbers(certSerialNumbers: List<String>) {
    this.certSerialNumbers.addAll(certSerialNumbers)
  }

  override fun logInfoMessage(infoMessage: String) {
    this.infoMessages.add(infoMessage)
  }
}
