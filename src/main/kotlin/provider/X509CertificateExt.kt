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

package com.android.keyattestation.verifier.provider

import java.security.cert.X509Certificate

private const val KEY_DESCRIPTION_OID = "1.3.6.1.4.1.11129.2.1.17"
private const val PROVISIONING_INFO_OID = "1.3.6.1.4.1.11129.2.1.30"

internal fun X509Certificate.hasAttestationExtension() =
  nonCriticalExtensionOIDs?.contains(KEY_DESCRIPTION_OID) ?: false

internal fun X509Certificate.hasProvisioningInfoExtension() =
  nonCriticalExtensionOIDs?.contains(PROVISIONING_INFO_OID) ?: false
