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
import com.android.keyattestation.verifier.provider.KeyAttestationCertPath
import com.google.common.collect.ImmutableList
import com.google.errorprone.annotations.Immutable
import com.google.errorprone.annotations.ThreadSafe

private typealias AttributeMapper = (KeyDescription) -> Any?

/** An individual limit to place on the KeyDescription from an attestation certificate. */
@ThreadSafe
sealed interface Constraint {
  sealed interface Result {}

  data object Satisfied : Result

  data class Violated(val failureMessage: String) : Result

  /** Fixed label, suitable for logging or metrics. */
  val label: String

  /** Verifies that [description] satisfies this [Constraint]. */
  fun check(description: KeyDescription, certPath: KeyAttestationCertPath): Result
}

/**
 * Configuration for validating the attributes in an Android attestation certificate, as described
 * at https://source.android.com/docs/security/features/keystore/attestation.
 */
@ThreadSafe
class ConstraintConfig(
  val allowSoftwareRoot: Boolean = false,
  val keyOrigin: Constraint? = null,
  val securityLevel: Constraint? = null,
  val rootOfTrust: Constraint? = null,
  val additionalConstraints: ImmutableList<Constraint> = ImmutableList.of(),
) {
  @RequiresApi(24)
  fun getConstraints() =
    ImmutableList.builder<Constraint>()
      .add(
        keyOrigin
          ?: AttributeConstraint.STRICT("Origin", Origin.GENERATED) { it.hardwareEnforced.origin }
      )
      .add(securityLevel ?: SecurityLevelConstraint.NOT_SOFTWARE)
      .add(
        rootOfTrust
          ?: AttributeConstraint.NOT_NULL("Root of trust") { it.hardwareEnforced.rootOfTrust }
      )
      .addAll(additionalConstraints)
      .build()

  companion object {
    fun testDefault(): ConstraintConfig = ConstraintConfig(allowSoftwareRoot = true)
  }
}

/**
 * We need a builder to support creating a [ConstraintConfig], as it's a thread-safe object. A
 * Kotlin-idiomatic builder function is provided below.
 */
class ConstraintConfigBuilder() {
  var allowSoftwareRoot: Boolean = false
  var keyOrigin: Constraint? = null
  var securityLevel: Constraint? = null
  var rootOfTrust: Constraint? = null
  var additionalConstraints: MutableList<Constraint> = mutableListOf()

  fun securityLevel(constraint: () -> Constraint) {
    this.securityLevel = constraint()
  }

  fun keyOrigin(constraint: () -> Constraint) {
    this.keyOrigin = constraint()
  }

  fun rootOfTrust(constraint: () -> Constraint) {
    this.rootOfTrust = constraint()
  }

  fun additionalConstraint(constraint: () -> Constraint) {
    additionalConstraints.add(constraint())
  }

  fun build(): ConstraintConfig =
    ConstraintConfig(
      allowSoftwareRoot,
      keyOrigin,
      securityLevel,
      rootOfTrust,
      ImmutableList.copyOf(additionalConstraints),
    )
}

/** Implements a Kotlin-style type safe builder for creating a [ConstraintConfig]. */
fun constraintConfig(init: ConstraintConfigBuilder.() -> Unit): ConstraintConfig {
  val builder = ConstraintConfigBuilder()
  builder.init()
  return builder.build()
}

/** Constraint that is always satisfied. */
@Immutable
data object IgnoredConstraint : Constraint {
  override val label = "Ignored"

  override fun check(description: KeyDescription, certPath: KeyAttestationCertPath) =
    Constraint.Satisfied
}

/** Constraint that checks a single attribute of the [KeyDescription]. */
@Immutable(containerOf = ["T"])
sealed class AttributeConstraint<out T>(override val label: String, val mapper: AttributeMapper?) :
  Constraint {
  /** Evaluates whether the [description] is satisfied by this [AttributeConstraint]. */
  override fun check(description: KeyDescription, certPath: KeyAttestationCertPath) =
    if (isSatisfied(mapper?.invoke(description))) {
      Constraint.Satisfied
    } else {
      Constraint.Violated(getFailureMessage(mapper?.invoke(description)))
    }

  internal abstract fun isSatisfied(attribute: Any?): Boolean

  internal open fun getFailureMessage(attribute: Any?): String =
    "$label violates constraint: value=$attribute, config=$this"

  /**
   * Checks that the attribute exists and matches the expected value.
   *
   * @param expectedVal The expected value of the attribute.
   */
  @Immutable(containerOf = ["T"])
  data class STRICT<T>(val l: String, val expectedVal: T, private val m: AttributeMapper) :
    AttributeConstraint<T>(l, m) {
    override fun isSatisfied(attribute: Any?): Boolean = attribute == expectedVal
  }

  /* Check that the attribute exists. */
  data class NOT_NULL(val l: String, private val m: AttributeMapper) :
    AttributeConstraint<Nothing>(l, m) {
    override fun isSatisfied(attribute: Any?): Boolean = attribute != null
  }
}

/**
 * Configuration for validating the attestationSecurityLevel and keyMintSecurityLevel fields in an
 * Android attestation certificate.
 */
@Immutable
@RequiresApi(24)
sealed class SecurityLevelConstraint(
  val isSatisfied: (KeyDescription, KeyAttestationCertPath) -> Boolean
) : Constraint {
  companion object {
    const val LABEL = "Security level"
  }

  override val label = LABEL

  override fun check(description: KeyDescription, certPath: KeyAttestationCertPath) =
    if (isSatisfied(description, certPath)) {
      Constraint.Satisfied
    } else {
      Constraint.Violated(getFailureMessage(description, certPath))
    }

  open fun getFailureMessage(
    description: KeyDescription,
    certPath: KeyAttestationCertPath,
  ): String =
    "Security level violates constraint: " +
      "keyMintSecurityLevel=${description.keyMintSecurityLevel}, " +
      "attestationSecurityLevel=${description.attestationSecurityLevel}, " +
      "config=$this"

  /**
   * Checks that both the attestationSecurityLevel and keyMintSecurityLevel match the expected
   * value.
   *
   * @param expectedVal The expected value of the security level.
   */
  @Immutable
  data class STRICT(val expectedVal: SecurityLevel) :
    SecurityLevelConstraint({ desc, _ ->
      desc.keyMintSecurityLevel == expectedVal && desc.attestationSecurityLevel == expectedVal
    })

  /**
   * Checks that the attestationSecurityLevel is equal to the keyMintSecurityLevel, and that this
   * security level is not [SecurityLevel.SOFTWARE].
   */
  @Immutable
  data object NOT_SOFTWARE :
    SecurityLevelConstraint({ desc, _ ->
      desc.keyMintSecurityLevel == desc.attestationSecurityLevel &&
        desc.attestationSecurityLevel != SecurityLevel.SOFTWARE
    })

  /**
   * Checks that the attestationSecurityLevel is equal to the keyMintSecurityLevel, regardless of
   * security level.
   */
  @Immutable
  data object CONSISTENT :
    SecurityLevelConstraint({ desc, _ ->
      desc.attestationSecurityLevel == desc.keyMintSecurityLevel
    })

  /**
   * Checks that the keyMintSecurityLevel matches the security level claimed by the certificate.
   * this constraint may be used in conjunction with other security level constraints. e.g. it may
   * be combined with [STRICT] to verify that the keyMintSecurityLevel is precisely
   * [SecurityLevel.STRONG_BOX] and that the security level matches the value claimed by the
   * Google-signed certificate.
   */
  @Immutable
  data object MATCHES_CERTIFICATE :
    SecurityLevelConstraint({ desc, certPath ->
      when (desc.keyMintSecurityLevel) {
        SecurityLevel.SOFTWARE ->
          certPath.securityLevel() == null || certPath.securityLevel() == SecurityLevel.SOFTWARE
        // Older cert chains do not make a TEE security level claim, so allow null. StrongBox certs
        // always explicitly claim the StrongBox security level, so there's no risk of a TEE cert
        // chain claiming to be StrongBox.
        SecurityLevel.TRUSTED_ENVIRONMENT ->
          certPath.securityLevel() == null ||
            certPath.securityLevel() == SecurityLevel.TRUSTED_ENVIRONMENT
        SecurityLevel.STRONG_BOX -> certPath.securityLevel() == SecurityLevel.STRONG_BOX
      }
    }) {
    override fun getFailureMessage(
      description: KeyDescription,
      certPath: KeyAttestationCertPath,
    ): String =
      "Security level of KeyMint (${description.keyMintSecurityLevel}) does not match " +
        "attestation certificate (${certPath.securityLevel()})"
  }
}

/**
 * Configuration for validating the ordering of the attributes in the AuthorizationList sequence in
 * an Android attestation certificate.
 */
@Immutable
@RequiresApi(24)
sealed class TagOrderConstraint : Constraint {
  override val label = "Tag order"

  /**
   * Checks that the attributes in the AuthorizationList sequence appear in the order specified by
   * https://source.android.com/docs/security/features/keystore/attestation#schema.
   */
  @Immutable
  data object STRICT : TagOrderConstraint() {
    override fun check(description: KeyDescription, certPath: KeyAttestationCertPath) =
      if (
        description.softwareEnforced.areTagsOrdered && description.hardwareEnforced.areTagsOrdered
      ) {
        Constraint.Satisfied
      } else {
        Constraint.Violated("Authorization list tags must be in ascending order")
      }
  }
}
