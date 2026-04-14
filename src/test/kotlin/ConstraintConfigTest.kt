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

import com.android.keyattestation.verifier.testing.TestUtils.readCertPath
import com.google.common.truth.Truth.assertThat
import com.google.protobuf.ByteString
import kotlin.test.assertIs
import org.junit.Test
import org.junit.runner.RunWith
import org.junit.runners.JUnit4

@RunWith(JUnit4::class)
class ConstraintConfigTest {

  private companion object {
    val authorizationList =
      AuthorizationList(purposes = setOf(1.toBigInteger()), algorithms = 1.toBigInteger())

    fun createTestKeyDescription(
      attestationSecurityLevel: SecurityLevel,
      keyMintSecurityLevel: SecurityLevel,
    ) =
      KeyDescription(
        attestationVersion = 1.toBigInteger(),
        attestationSecurityLevel = attestationSecurityLevel,
        keyMintVersion = 1.toBigInteger(),
        keyMintSecurityLevel = keyMintSecurityLevel,
        attestationChallenge = ByteString.empty(),
        uniqueId = ByteString.empty(),
        softwareEnforced = authorizationList,
        hardwareEnforced = authorizationList,
      )
  }

  val keyDescriptionWithStrongBoxSecurityLevels =
    createTestKeyDescription(SecurityLevel.STRONG_BOX, SecurityLevel.STRONG_BOX)
  val keyDescriptionWithTeeSecurityLevels =
    createTestKeyDescription(SecurityLevel.TRUSTED_ENVIRONMENT, SecurityLevel.TRUSTED_ENVIRONMENT)
  val keyDescriptionWithSoftwareSecurityLevels =
    createTestKeyDescription(SecurityLevel.SOFTWARE, SecurityLevel.SOFTWARE)
  val keyDescriptionWithMismatchedSecurityLevels =
    createTestKeyDescription(SecurityLevel.STRONG_BOX, SecurityLevel.TRUSTED_ENVIRONMENT)

  private val testCertPath = readCertPath("akita/sdk34/TEE_EC_NONE.pem")

  @Test
  fun AttributeConstraintIsSatisfied_strictWithExpectedValue() {
    val level = AttributeConstraint.STRICT("Unique ID", "foo") { it.uniqueId.toStringUtf8() }
    val kd =
      keyDescriptionWithSoftwareSecurityLevels.copy(uniqueId = ByteString.copyFromUtf8("foo"))

    assertIs<Constraint.Satisfied>(level.check(kd))
    assertIs<Constraint.Violated>(level.check(kd.copy(uniqueId = ByteString.copyFromUtf8("bar"))))
  }

  @Test
  fun AttributeConstraintIsSatisfied_notNull_allowsAnyValue() {
    val level = AttributeConstraint.NOT_NULL("Root of trust") { it.hardwareEnforced.rootOfTrust }

    assertIs<Constraint.Violated>(level.check(keyDescriptionWithSoftwareSecurityLevels))

    val kdWithRot =
      keyDescriptionWithSoftwareSecurityLevels.copy(
        hardwareEnforced =
          keyDescriptionWithSoftwareSecurityLevels.hardwareEnforced.copy(
            rootOfTrust = RootOfTrust(ByteString.empty(), false, VerifiedBootState.VERIFIED)
          )
      )
    assertIs<Constraint.Satisfied>(level.check(kdWithRot))
  }

  @Test
  fun SecurityLevelConstraintIsSatisfied_strictWithExpectedValue() {
    val level = SecurityLevelConstraint.STRICT(SecurityLevel.STRONG_BOX)

    assertIs<Constraint.Satisfied>(level.check(keyDescriptionWithStrongBoxSecurityLevels))
    assertIs<Constraint.Violated>(level.check(keyDescriptionWithTeeSecurityLevels))
    assertIs<Constraint.Violated>(level.check(keyDescriptionWithMismatchedSecurityLevels))
  }

  @Test
  fun SecurityLevelConstraintIsSatisfied_notSoftware_allowsAnyNonSoftwareMatchingLevels() {
    val level = SecurityLevelConstraint.NOT_SOFTWARE

    assertIs<Constraint.Satisfied>(level.check(keyDescriptionWithStrongBoxSecurityLevels))
    assertIs<Constraint.Satisfied>(level.check(keyDescriptionWithTeeSecurityLevels))
    assertIs<Constraint.Violated>(level.check(keyDescriptionWithSoftwareSecurityLevels))
    assertIs<Constraint.Violated>(level.check(keyDescriptionWithMismatchedSecurityLevels))
  }

  @Test
  fun SecurityLevelConstraintIsSatisfied_consistent_allowsAnyMatchingLevels() {
    val level = SecurityLevelConstraint.CONSISTENT

    assertIs<Constraint.Satisfied>(level.check(keyDescriptionWithStrongBoxSecurityLevels))
    assertIs<Constraint.Satisfied>(level.check(keyDescriptionWithTeeSecurityLevels))
    assertIs<Constraint.Satisfied>(level.check(keyDescriptionWithSoftwareSecurityLevels))
    assertIs<Constraint.Violated>(level.check(keyDescriptionWithMismatchedSecurityLevels))
  }

  @Test
  fun AuthorizationListOrderingIsSatisfied_strictWithUnorderedTags_fails() {
    val ordering = TagOrderConstraint.STRICT

    assertIs<Constraint.Satisfied>(ordering.check(keyDescriptionWithStrongBoxSecurityLevels))

    val kdUnordered =
      KeyDescription.parseFrom(readCertPath("invalid/tags_not_in_ascending_order.pem").leafCert())!!

    assertIs<Constraint.Violated>(ordering.check(kdUnordered))
  }

  @Test
  fun attributeConstraint_withViolation_returnsCorrectMessage() {
    val level = AttributeConstraint.STRICT("Unique ID", "foo") { it.uniqueId.toStringUtf8() }
    val kd =
      keyDescriptionWithSoftwareSecurityLevels.copy(uniqueId = ByteString.copyFromUtf8("bar"))

    val violation = assertIs<Constraint.Violated>(level.check(kd))
    assertThat(violation.failureMessage)
      .isEqualTo("Unique ID violates constraint: value=bar, config=$level")
  }

  @Test
  fun securityLevelConstraint_withViolation_returnsCorrectMessage() {
    val level = SecurityLevelConstraint.STRICT(SecurityLevel.STRONG_BOX)

    val violation = assertIs<Constraint.Violated>(level.check(keyDescriptionWithTeeSecurityLevels))
    assertThat(violation.failureMessage)
      .isEqualTo(
        "Security level violates constraint: keyMintSecurityLevel=TRUSTED_ENVIRONMENT, " +
          "attestationSecurityLevel=TRUSTED_ENVIRONMENT, config=$level"
      )
  }

  @Test
  fun tagOrderConstraint_withViolation_returnsCorrectMessage() {
    val level = TagOrderConstraint.STRICT
    val kdUnordered =
      KeyDescription.parseFrom(readCertPath("invalid/tags_not_in_ascending_order.pem").leafCert())!!

    val violation = assertIs<Constraint.Violated>(level.check(kdUnordered))
    assertThat(violation.failureMessage)
      .isEqualTo("Authorization list tags must be in ascending order")
  }
}
