/*
 * Copyright 2025 Google LLC
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
import com.android.keyattestation.verifier.LogHook
import com.android.keyattestation.verifier.ProvisioningInfoMap
import com.android.keyattestation.verifier.VerificationResult
import com.google.protobuf.ByteString

/**
 * Fake implementation of [LogHook] for testing.
 *
 * Stores the last values passed to each logging method. A new instance should be created for each
 * test.
 */
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
