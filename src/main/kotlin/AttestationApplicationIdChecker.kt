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

package com.android.keyattestation.verifier

import com.google.errorprone.annotations.ThreadSafe
import java.math.BigInteger

/** Checks the attestation application ID in an Android Key Attestation certificate. */
@ThreadSafe
sealed class AttestationApplicationIdChecker(
  val isSatisfied: (AttestationApplicationId?, BigInteger?) -> Boolean
) {
  /**
   * Checks the given [attestationApplicationId] for validity.
   *
   * @return True if the attestation application ID is valid, else false.
   */
  fun checkAttestationApplicationId(
    attestationApplicationId: AttestationApplicationId?,
    osVersion: BigInteger?,
  ): Boolean = isSatisfied(attestationApplicationId, osVersion)

  /**
   * Checks that the attestation application ID matches the expected value.
   *
   * This is the strictest form of attestation application ID check. There is no leniency for the OS
   * version so it may fail on older devices.
   *
   * @param expectedId The expected value of the attestation application ID.
   */
  data class STRICT(val expectedId: AttestationApplicationId) :
    AttestationApplicationIdChecker({ id, _ -> expectedId.isSatisfiedBy(id) })

  /**
   * Checks that the attestation application ID matches the expected value or that the OS version is
   * at or below the maximum OS version.
   *
   * This is a lenient form of attestation application ID check. It allows for older devices to pass
   * the check if they have an unknown package name.
   *
   * @param expectedId The expected value of the attestation application ID.
   * @param maxOsVersion The maximum OS version that the device can be on to pass the check.
   */
  data class LENIENT(val expectedId: AttestationApplicationId, val maxOsVersion: BigInteger) :
    AttestationApplicationIdChecker({ id, osVersion ->
      expectedId.isSatisfiedBy(id) ||
        (osVersion != null && osVersion <= maxOsVersion && hasUnknownPackage(id))
    })

  /**
   * Does not check the attestation application ID. This should only be used for testing purposes.
   */
  data object NONE : AttestationApplicationIdChecker({ _, _ -> true })

  companion object {
    fun hasUnknownPackage(id: AttestationApplicationId?) =
      id != null && id.packages.any { it.name == "UnknownPackage" && it.version == BigInteger.ONE }
  }
}
