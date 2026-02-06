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

import androidx.annotation.RequiresApi
import com.google.errorprone.annotations.Immutable
import com.google.errorprone.annotations.ThreadSafe

/**
 * Configuration for validating the extensions in an Android attestation certificate, as described
 * at https://source.android.com/docs/security/features/keystore/attestation.
 */
@ThreadSafe
data class ExtensionConstraintConfig(
  val keyOrigin: ValidationLevel<Origin> = ValidationLevel.STRICT(Origin.GENERATED),
  val securityLevel: ValidationLevel<KeyDescription> =
    SecurityLevelValidationLevel.STRICT(SecurityLevel.TRUSTED_ENVIRONMENT),
  val rootOfTrust: ValidationLevel<RootOfTrust> = ValidationLevel.NOT_NULL,
)

/** Configuration for validating a single extension in an Android attestation certificate. */
@Immutable(containerOf = ["T"])
sealed interface ValidationLevel<out T> {
  /** Evaluates whether the [extension] is satisfied by this [ValidationLevel]. */
  fun isSatisfiedBy(extension: Any?): Boolean

  /**
   * Checks that the extension exists and matches the expected value.
   *
   * @param expectedVal The expected value of the extension.
   */
  @Immutable(containerOf = ["T"])
  data class STRICT<T>(val expectedVal: T) : ValidationLevel<T> {
    override fun isSatisfiedBy(extension: Any?): Boolean = extension == expectedVal
  }

  /* Check that the extension exists. */
  @Immutable
  data object NOT_NULL : ValidationLevel<Nothing> {
    override fun isSatisfiedBy(extension: Any?): Boolean = extension != null
  }

  @Immutable
  data object IGNORE : ValidationLevel<Nothing> {
    override fun isSatisfiedBy(extension: Any?): Boolean = true
  }
}

/**
 * Configuration for validating the attestationSecurityLevel and keyMintSecurityLevel fields in an
 * Android attestation certificate.
 */
@Immutable
sealed class SecurityLevelValidationLevel : ValidationLevel<KeyDescription> {
  @RequiresApi(24)
  fun areSecurityLevelsMatching(keyDescription: KeyDescription): Boolean {
    return keyDescription.attestationSecurityLevel == keyDescription.keyMintSecurityLevel
  }

  /**
   * Checks that both the attestationSecurityLevel and keyMintSecurityLevel match the expected
   * value.
   *
   * @param expectedVal The expected value of the security level.
   */
  @Immutable
  data class STRICT(val expectedVal: SecurityLevel) : SecurityLevelValidationLevel() {
    @RequiresApi(24)
    override fun isSatisfiedBy(extension: Any?): Boolean {
      val keyDescription = extension as? KeyDescription ?: return false
      val securityLevelIsExpected = keyDescription.attestationSecurityLevel == this.expectedVal
      return areSecurityLevelsMatching(keyDescription) && securityLevelIsExpected
    }
  }

  /**
   * Checks that the attestationSecurityLevel is equal to the keyMintSecurityLevel, and that this
   * security level is not [SecurityLevel.SOFTWARE].
   */
  @Immutable
  data object NOT_SOFTWARE : SecurityLevelValidationLevel() {
    @RequiresApi(24)
    override fun isSatisfiedBy(extension: Any?): Boolean {
      val keyDescription = extension as? KeyDescription ?: return false
      val securityLevelIsSoftware =
        keyDescription.attestationSecurityLevel == SecurityLevel.SOFTWARE
      return areSecurityLevelsMatching(keyDescription) && !securityLevelIsSoftware
    }
  }

  /**
   * Checks that the attestationSecurityLevel is equal to the keyMintSecurityLevel, regardless of
   * security level.
   */
  @Immutable
  data object CONSISTENT : SecurityLevelValidationLevel() {
    @RequiresApi(24)
    override fun isSatisfiedBy(extension: Any?): Boolean {
      val keyDescription = extension as? KeyDescription ?: return false
      return areSecurityLevelsMatching(keyDescription)
    }
  }
}
