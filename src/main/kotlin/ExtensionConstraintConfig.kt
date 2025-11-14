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
 * Configuration for validating the extensions in an Android attenstation certificate, as described
 * at https://source.android.com/docs/security/features/keystore/attestation.
 */
@ThreadSafe
data class ExtensionConstraintConfig(
  val keyOrigin: ValidationLevel<Origin> = ValidationLevel.STRICT(Origin.GENERATED),
  val securityLevel: SecurityLevelValidationLevel = SecurityLevelValidationLevel.STRICT(),
  val rootOfTrust: ValidationLevel<RootOfTrust> = ValidationLevel.STRICT(null),
)

/**
 * Configuration for validating a single extension in an Android attenstation certificate.
 *
 * @param expectedVal The expected value of the extension. If null, the extension is checked for
 *   existence but not equality.
 */
@Immutable(containerOf = ["T"])
sealed interface ValidationLevel<out T> {
  @Immutable(containerOf = ["T"]) data class STRICT<T>(val expectedVal: T?) : ValidationLevel<T>

  @Immutable data object IGNORE : ValidationLevel<Nothing>
}

/**
 * Configuration for validating the attestationSecurityLevel and keyMintSecurityLevel fields in an
 * Android attenstation certificate.
 */
@Immutable
sealed interface SecurityLevelValidationLevel {
  /**
   * Checks that the attestationSecurityLevel is both (1) one of {TRUSTED_ENVIRONMENT, STRONG_BOX}
   * and (2) equal to the keyMintSecurityLevel.
   *
   * If expectedVal is provided, checks that both the attestationSecurityLevel and
   * keyMintSecurityLevel are equal to the expected value.
   */
  @Immutable
  data class STRICT(val expectedVal: SecurityLevel? = null) : SecurityLevelValidationLevel

  /**
   * Checks that the attestationSecurityLevel is equal to the keyMintSecurityLevel, regardless of
   * security level
   */
  @Immutable data object MATCH : SecurityLevelValidationLevel

  /**
   * Checks that attestationSecurityLevel and keyMintSecurityLevel both exist and are correctly
   * formed. If they are unequal, [Verifier.verify] will return the lower securityLevel.
   */
  @Immutable data object EXISTS : SecurityLevelValidationLevel
}

/** Evaluates whether the [extension] is satisfied by the [ValidationLevel]. */
fun <T> ValidationLevel<T>.isSatisfiedBy(extension: T?): Boolean =
  when (this) {
    is ValidationLevel.STRICT ->
      if (expectedVal == null) extension != null else extension == expectedVal
    is ValidationLevel.IGNORE -> true
  }

/** Evaluates whether the [keyDescription] is satisfied by the [SecurityLevelValidationLevel]. */
@RequiresApi(24)
fun SecurityLevelValidationLevel.isSatisfiedBy(keyDescription: KeyDescription): Boolean {
  val securityLevelsMatch =
    keyDescription.attestationSecurityLevel == keyDescription.keyMintSecurityLevel

  return when (this) {
    is SecurityLevelValidationLevel.STRICT -> {
      val securityLevelIsExpected =
        if (this.expectedVal != null) keyDescription.attestationSecurityLevel == this.expectedVal
        else keyDescription.attestationSecurityLevel != SecurityLevel.SOFTWARE
      securityLevelsMatch && securityLevelIsExpected
    }
    is SecurityLevelValidationLevel.MATCH -> securityLevelsMatch
    is SecurityLevelValidationLevel.EXISTS -> true
  }
}
