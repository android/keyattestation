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
import com.google.protobuf.kotlin.toByteStringUtf8
import java.math.BigInteger
import kotlin.test.assertIs
import org.junit.Assert.assertThrows
import org.junit.Test
import org.junit.runner.RunWith
import org.junit.runners.JUnit4

@RunWith(JUnit4::class)
class ConstraintConfigTest {

  private companion object {
    const val TEST_PACKAGE_NAME = "com.example.app"
    val TEST_PACKAGE_VERSION = BigInteger.valueOf(10)
    val TEST_PACKAGE_INFO = AttestationPackageInfo(TEST_PACKAGE_NAME, TEST_PACKAGE_VERSION)
    val TEST_SIGNATURE = ByteString.copyFromUtf8("test-signature")
    val TEST_APP_ID =
      AttestationApplicationId(
        packages = setOf(TEST_PACKAGE_INFO),
        signatures = setOf(TEST_SIGNATURE),
      )
    val UNKNOWN_PACKAGE = AttestationPackageInfo("UnknownPackage", BigInteger.ONE)
    val MAX_OS_VERSION = BigInteger.valueOf(140000)

    val authorizationList =
      AuthorizationList(
        purposes = setOf(1.toBigInteger()),
        algorithms = 1.toBigInteger(),
        osVersion = MAX_OS_VERSION,
      )

    fun createTestKeyDescription(
      attestationSecurityLevel: SecurityLevel,
      keyMintSecurityLevel: SecurityLevel,
    ) =
      KeyDescription(
        attestationVersion = 400.toBigInteger(),
        attestationSecurityLevel = attestationSecurityLevel,
        keyMintVersion = 400.toBigInteger(),
        keyMintSecurityLevel = keyMintSecurityLevel,
        attestationChallenge = ByteString.empty(),
        uniqueId = ByteString.empty(),
        softwareEnforced = AuthorizationList(attestationApplicationId = TEST_APP_ID),
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
  private val factoryCertPath = readCertPath("blueline/sdk28/TEE_EC_NONE.pem")
  private val rkpCertPath = readCertPath("caiman/sdk36/TEE_EC_RKP.pem")
  private val unknownCertPath = readCertPath("marlin/sdk29/TEE_EC_NONE.pem")

  @Test
  fun AttributeConstraintIsSatisfied_strictWithExpectedValue() {
    val level = AttributeConstraint.STRICT("Unique ID", "foo") { it.uniqueId.toStringUtf8() }
    val kd =
      keyDescriptionWithSoftwareSecurityLevels.copy(uniqueId = ByteString.copyFromUtf8("foo"))

    assertIs<Constraint.Satisfied>(level.check(kd, testCertPath))
    assertIs<Constraint.Violated>(
      level.check(kd.copy(uniqueId = ByteString.copyFromUtf8("bar")), testCertPath)
    )
  }

  @Test
  fun AttributeConstraintIsSatisfied_notNull_allowsAnyValue() {
    val level = AttributeConstraint.NOT_NULL("Root of trust") { it.hardwareEnforced.rootOfTrust }

    assertIs<Constraint.Violated>(
      level.check(keyDescriptionWithSoftwareSecurityLevels, testCertPath)
    )

    val kdWithRot =
      keyDescriptionWithSoftwareSecurityLevels.copy(
        hardwareEnforced =
          keyDescriptionWithSoftwareSecurityLevels.hardwareEnforced.copy(
            rootOfTrust = RootOfTrust(ByteString.empty(), false, VerifiedBootState.VERIFIED)
          )
      )
    assertIs<Constraint.Satisfied>(level.check(kdWithRot, testCertPath))
  }

  @Test
  fun SecurityLevelConstraintIsSatisfied_strictWithExpectedValue() {
    val strongBoxCertPath = readCertPath("blueline/sdk28/SB_RSA_NONE.pem")
    val strongBoxLevel = SecurityLevelConstraint.STRICT(SecurityLevel.STRONG_BOX)

    assertIs<Constraint.Satisfied>(
      strongBoxLevel.check(keyDescriptionWithStrongBoxSecurityLevels, strongBoxCertPath)
    )
    assertIs<Constraint.Violated>(
      strongBoxLevel.check(keyDescriptionWithStrongBoxSecurityLevels, testCertPath)
    )
    assertIs<Constraint.Violated>(
      strongBoxLevel.check(keyDescriptionWithTeeSecurityLevels, testCertPath)
    )
    assertIs<Constraint.Violated>(
      strongBoxLevel.check(keyDescriptionWithMismatchedSecurityLevels, testCertPath)
    )

    val teeLevel = SecurityLevelConstraint.STRICT(SecurityLevel.TRUSTED_ENVIRONMENT)
    assertIs<Constraint.Satisfied>(
      teeLevel.check(keyDescriptionWithTeeSecurityLevels, testCertPath)
    )
    assertIs<Constraint.Violated>(
      teeLevel.check(keyDescriptionWithTeeSecurityLevels, strongBoxCertPath)
    )
  }

  @Test
  fun SecurityLevelConstraintIsSatisfied_notSoftware_allowsAnyNonSoftwareMatchingLevels() {
    val level = SecurityLevelConstraint.NOT_SOFTWARE

    assertIs<Constraint.Satisfied>(
      level.check(keyDescriptionWithStrongBoxSecurityLevels, testCertPath)
    )
    assertIs<Constraint.Satisfied>(level.check(keyDescriptionWithTeeSecurityLevels, testCertPath))
    assertIs<Constraint.Violated>(
      level.check(keyDescriptionWithSoftwareSecurityLevels, testCertPath)
    )
    assertIs<Constraint.Violated>(
      level.check(keyDescriptionWithMismatchedSecurityLevels, testCertPath)
    )
  }

  @Test
  fun SecurityLevelConstraintIsSatisfied_consistent_allowsAnyMatchingLevels() {
    val level = SecurityLevelConstraint.CONSISTENT

    assertIs<Constraint.Satisfied>(
      level.check(keyDescriptionWithStrongBoxSecurityLevels, testCertPath)
    )
    assertIs<Constraint.Satisfied>(level.check(keyDescriptionWithTeeSecurityLevels, testCertPath))
    assertIs<Constraint.Satisfied>(
      level.check(keyDescriptionWithSoftwareSecurityLevels, testCertPath)
    )
    assertIs<Constraint.Violated>(
      level.check(keyDescriptionWithMismatchedSecurityLevels, testCertPath)
    )
  }

  @Test
  fun AuthorizationListOrderingIsSatisfied_strictWithUnorderedTags_fails() {
    val ordering = TagOrderConstraint.STRICT

    assertIs<Constraint.Satisfied>(
      ordering.check(keyDescriptionWithStrongBoxSecurityLevels, testCertPath)
    )

    val kdUnordered =
      KeyDescription.parseFrom(readCertPath("invalid/tags_not_in_ascending_order.pem").leafCert())!!

    assertIs<Constraint.Violated>(ordering.check(kdUnordered, testCertPath))
  }

  @Test
  fun attributeConstraint_withViolation_returnsCorrectMessage() {
    val level = AttributeConstraint.STRICT("Unique ID", "foo") { it.uniqueId.toStringUtf8() }
    val kd =
      keyDescriptionWithSoftwareSecurityLevels.copy(uniqueId = ByteString.copyFromUtf8("bar"))

    val violation = assertIs<Constraint.Violated>(level.check(kd, testCertPath))
    assertThat(violation.failureMessage)
      .isEqualTo("Unique ID violates constraint: value=bar, config=$level")
  }

  @Test
  fun securityLevelConstraint_withViolation_returnsCorrectMessage() {
    val level = SecurityLevelConstraint.NOT_SOFTWARE

    val violation =
      assertIs<Constraint.Violated>(
        level.check(keyDescriptionWithSoftwareSecurityLevels, testCertPath)
      )
    assertThat(violation.failureMessage)
      .isEqualTo(
        "Security level violates constraint: keyMintSecurityLevel=SOFTWARE, " +
          "attestationSecurityLevel=SOFTWARE, config=$level"
      )
  }

  @Test
  fun securityLevelConstraintStrict_withCertificateMismatch_returnsCorrectMessage() {
    val level = SecurityLevelConstraint.STRICT(SecurityLevel.STRONG_BOX)

    val violation =
      assertIs<Constraint.Violated>(
        level.check(keyDescriptionWithStrongBoxSecurityLevels, testCertPath)
      )
    assertThat(violation.failureMessage)
      .isEqualTo(
        "Security level of KeyMint (STRONG_BOX) does not match attestation certificate (TRUSTED_ENVIRONMENT)"
      )
  }

  @Test
  fun tagOrderConstraint_withViolation_returnsCorrectMessage() {
    val level = TagOrderConstraint.STRICT
    val kdUnordered =
      KeyDescription.parseFrom(readCertPath("invalid/tags_not_in_ascending_order.pem").leafCert())!!

    val violation = assertIs<Constraint.Violated>(level.check(kdUnordered, testCertPath))
    assertThat(violation.failureMessage)
      .isEqualTo("Authorization list tags must be in ascending order")
  }

  @Test
  fun constraintConfig_inputLimits_customValue() {
    val config = constraintConfig {
      inputLimits { InputLimits(maxPackages = 50, maxSignatures = 25) }
    }
    assertThat(config.inputLimits.maxPackages).isEqualTo(50)
    assertThat(config.inputLimits.maxSignatures).isEqualTo(25)
  }

  @Test
  fun inputLimits_zeroOrNegative_throws() {
    assertThrows(IllegalArgumentException::class.java) {
      InputLimits(maxPackages = 0, maxSignatures = 10)
    }
    assertThrows(IllegalArgumentException::class.java) {
      InputLimits(maxPackages = -1, maxSignatures = 10)
    }
    assertThrows(IllegalArgumentException::class.java) {
      InputLimits(maxPackages = 10, maxSignatures = 0)
    }
    assertThrows(IllegalArgumentException::class.java) {
      InputLimits(maxPackages = 10, maxSignatures = -5)
    }
  }

  @Test
  fun SecurityLevelConstraintIsSatisfied_matchesCertificate_nullClaim() {
    val factoryCertPathWithNoClaim = readCertPath("blueline/sdk28/TEE_EC_NONE.pem")

    assertIs<Constraint.Satisfied>(
      SecurityLevelConstraint.MATCHES_CERTIFICATE.check(
        keyDescriptionWithTeeSecurityLevels,
        factoryCertPathWithNoClaim,
      )
    )
    assertIs<Constraint.Satisfied>(
      SecurityLevelConstraint.MATCHES_CERTIFICATE.check(
        keyDescriptionWithSoftwareSecurityLevels,
        factoryCertPathWithNoClaim,
      )
    )
    assertIs<Constraint.Violated>(
      SecurityLevelConstraint.MATCHES_CERTIFICATE.check(
        keyDescriptionWithStrongBoxSecurityLevels,
        factoryCertPathWithNoClaim,
      )
    )
  }

  @Test
  fun SecurityLevelConstraintIsSatisfied_matchesCertificate_trustedEnvironmentClaim() {
    assertIs<Constraint.Satisfied>(
      SecurityLevelConstraint.MATCHES_CERTIFICATE.check(
        keyDescriptionWithTeeSecurityLevels,
        testCertPath,
      )
    )
    assertIs<Constraint.Violated>(
      SecurityLevelConstraint.MATCHES_CERTIFICATE.check(
        keyDescriptionWithSoftwareSecurityLevels,
        testCertPath,
      )
    )
    assertIs<Constraint.Violated>(
      SecurityLevelConstraint.MATCHES_CERTIFICATE.check(
        keyDescriptionWithStrongBoxSecurityLevels,
        testCertPath,
      )
    )
  }

  @Test
  fun SecurityLevelConstraintIsSatisfied_matchesCertificate_strongBoxClaim() {
    val strongBoxCertPath = readCertPath("blueline/sdk28/SB_RSA_NONE.pem")

    assertIs<Constraint.Satisfied>(
      SecurityLevelConstraint.MATCHES_CERTIFICATE.check(
        keyDescriptionWithStrongBoxSecurityLevels,
        strongBoxCertPath,
      )
    )
    assertIs<Constraint.Violated>(
      SecurityLevelConstraint.MATCHES_CERTIFICATE.check(
        keyDescriptionWithTeeSecurityLevels,
        strongBoxCertPath,
      )
    )
    assertIs<Constraint.Violated>(
      SecurityLevelConstraint.MATCHES_CERTIFICATE.check(
        keyDescriptionWithSoftwareSecurityLevels,
        strongBoxCertPath,
      )
    )
  }

  @Test
  fun matchesCertificate_withViolation_returnsCorrectMessage() {
    val violation =
      assertIs<Constraint.Violated>(
        SecurityLevelConstraint.MATCHES_CERTIFICATE.check(
          keyDescriptionWithStrongBoxSecurityLevels,
          testCertPath,
        )
      )
    assertThat(violation.failureMessage)
      .isEqualTo(
        "Security level of KeyMint (STRONG_BOX) does not match attestation certificate (TRUSTED_ENVIRONMENT)"
      )
  }

  @Test
  fun compositeConstraint_allSatisfied_returnsSatisfied() {
    val composite =
      CompositeConstraint(
        "test constraint",
        SecurityLevelConstraint.CONSISTENT,
        SecurityLevelConstraint.NOT_SOFTWARE,
      )

    assertIs<Constraint.Satisfied>(
      composite.check(keyDescriptionWithTeeSecurityLevels, testCertPath)
    )
    assertThat(composite.label).isEqualTo("test constraint")
  }

  @Test
  fun compositeConstraint_stopsOnFirstViolation() {
    val composite =
      CompositeConstraint("test", SecurityLevelConstraint.NOT_SOFTWARE, TagOrderConstraint.STRICT)

    val violation =
      assertIs<Constraint.Violated>(
        composite.check(keyDescriptionWithSoftwareSecurityLevels, testCertPath)
      )
    assertThat(violation.failureMessage).contains("Security level violates constraint")
  }

  @Test
  fun compositeConstraint_emptyDefaultLabel() {
    val composite = CompositeConstraint("test composite")
    assertThat(composite.label).isEqualTo("test composite")
    assertIs<Constraint.Satisfied>(
      composite.check(keyDescriptionWithTeeSecurityLevels, testCertPath)
    )
  }

  @Test
  fun ProvisioningMethodConstraintIsSatisfied_factory_allowsFactoryCertPath() {
    assertIs<Constraint.Satisfied>(
      ProvisioningMethodConstraint.FACTORY.check(
        keyDescriptionWithTeeSecurityLevels,
        factoryCertPath,
      )
    )
    assertIs<Constraint.Violated>(
      ProvisioningMethodConstraint.FACTORY.check(keyDescriptionWithTeeSecurityLevels, rkpCertPath)
    )
    assertIs<Constraint.Violated>(
      ProvisioningMethodConstraint.FACTORY.check(
        keyDescriptionWithTeeSecurityLevels,
        unknownCertPath,
      )
    )
  }

  @Test
  fun ProvisioningMethodConstraintIsSatisfied_rkp_allowsRkpCertPath() {
    assertIs<Constraint.Satisfied>(
      ProvisioningMethodConstraint.REMOTE.check(keyDescriptionWithTeeSecurityLevels, rkpCertPath)
    )
    assertIs<Constraint.Violated>(
      ProvisioningMethodConstraint.REMOTE.check(
        keyDescriptionWithTeeSecurityLevels,
        factoryCertPath,
      )
    )
    assertIs<Constraint.Violated>(
      ProvisioningMethodConstraint.REMOTE.check(
        keyDescriptionWithTeeSecurityLevels,
        unknownCertPath,
      )
    )
  }

  @Test
  fun provisioningMethodConstraint_factory_withViolation_returnsCorrectMessage() {
    val factoryConstraint = ProvisioningMethodConstraint.FACTORY
    val rkpViolation =
      assertIs<Constraint.Violated>(
        factoryConstraint.check(keyDescriptionWithTeeSecurityLevels, rkpCertPath)
      )
    assertThat(rkpViolation.failureMessage)
      .isEqualTo(
        "Provisioning method violates constraint: provisioningMethod=REMOTELY_PROVISIONED, config=$factoryConstraint"
      )
    assertThat(factoryConstraint.label).isEqualTo("Provisioning method")
  }

  @Test
  fun provisioningMethodConstraint_remote_withViolation_returnsCorrectMessage() {
    val remoteConstraint = ProvisioningMethodConstraint.REMOTE
    val factoryViolation =
      assertIs<Constraint.Violated>(
        remoteConstraint.check(keyDescriptionWithTeeSecurityLevels, factoryCertPath)
      )
    assertThat(factoryViolation.failureMessage)
      .isEqualTo(
        "Provisioning method violates constraint: provisioningMethod=FACTORY_PROVISIONED, config=$remoteConstraint"
      )
    assertThat(remoteConstraint.label).isEqualTo("Provisioning method")
  }

  @Test
  fun constraintConfig_provisioningMethod_configuredViaAdditionalConstraint() {
    val config = constraintConfig { additionalConstraint { ProvisioningMethodConstraint.FACTORY } }
    assertThat(config.additionalConstraints).contains(ProvisioningMethodConstraint.FACTORY)
    assertThat(config.getGenericConstraints()).contains(ProvisioningMethodConstraint.FACTORY)
  }

  @Test
  fun attestationApplicationId_strict_matchingAppId_returnsSatisfied() {
    assertIs<Constraint.Satisfied>(
      AttestationApplicationIdConstraint.STRICT.check(
        TEST_APP_ID,
        keyDescriptionWithTeeSecurityLevels,
      )
    )
  }

  @Test
  fun attestationApplicationId_strict_higherVersion_returnsSatisfied() {
    assertIs<Constraint.Satisfied>(
      AttestationApplicationIdConstraint.STRICT.check(
        AttestationApplicationId(
          setOf(AttestationPackageInfo(TEST_PACKAGE_NAME, TEST_PACKAGE_VERSION - BigInteger.ONE)),
          setOf(TEST_SIGNATURE),
        ),
        keyDescriptionWithTeeSecurityLevels,
      )
    )
  }

  @Test
  fun attestationApplicationId_strict_noSignatureRequirements_returnsSatisfied() {
    assertIs<Constraint.Satisfied>(
      AttestationApplicationIdConstraint.STRICT.check(
        AttestationApplicationId(packages = setOf(TEST_PACKAGE_INFO), signatures = emptySet()),
        keyDescriptionWithTeeSecurityLevels,
      )
    )
  }

  @Test
  fun attestationApplicationId_strict_lowerVersion_returnsViolated() {
    assertIs<Constraint.Violated>(
      AttestationApplicationIdConstraint.STRICT.check(
        AttestationApplicationId(
          setOf(AttestationPackageInfo(TEST_PACKAGE_NAME, TEST_PACKAGE_VERSION + BigInteger.ONE)),
          setOf(TEST_SIGNATURE),
        ),
        keyDescriptionWithTeeSecurityLevels,
      )
    )
  }

  @Test
  fun attestationApplicationId_strict_mismatchedPackageName_returnsViolated() {
    assertIs<Constraint.Violated>(
      AttestationApplicationIdConstraint.STRICT.check(
        AttestationApplicationId(
          setOf(
            AttestationPackageInfo(name = "different.package.name", version = TEST_PACKAGE_VERSION)
          ),
          emptySet(),
        ),
        keyDescriptionWithTeeSecurityLevels,
      )
    )
  }

  @Test
  fun attestationApplicationId_strict_mismatchedSignature_returnsViolated() {
    assertIs<Constraint.Violated>(
      AttestationApplicationIdConstraint.STRICT.check(
        AttestationApplicationId(
          setOf(AttestationPackageInfo(TEST_PACKAGE_NAME, TEST_PACKAGE_VERSION)),
          setOf("other-signature".toByteStringUtf8()),
        ),
        keyDescriptionWithTeeSecurityLevels,
      )
    )
  }

  @Test
  fun attestationApplicationId_lenient_matchingAppId_returnsSatisfiedRegardlessOfOsVersion() {
    assertIs<Constraint.Satisfied>(
      AttestationApplicationIdConstraint.ALLOW_UNKNOWN_PACKAGE(MAX_OS_VERSION)
        .check(TEST_APP_ID, keyDescriptionWithTeeSecurityLevels)
    )
  }

  @Test
  fun attestationApplicationId_lenient_mismatchedAppId_withUnknownPackage_andLowerOrEqualOsVersion_returnsSatisfied() {
    val actualAppId =
      AttestationApplicationId(packages = setOf(UNKNOWN_PACKAGE), signatures = setOf())

    val kdEqualOs =
      keyDescriptionWithTeeSecurityLevels.copy(
        softwareEnforced = authorizationList.copy(attestationApplicationId = actualAppId),
        hardwareEnforced = authorizationList.copy(osVersion = MAX_OS_VERSION),
      )
    assertIs<Constraint.Satisfied>(
      AttestationApplicationIdConstraint.ALLOW_UNKNOWN_PACKAGE(MAX_OS_VERSION)
        .check(TEST_APP_ID, kdEqualOs)
    )

    val kdLowerOs =
      keyDescriptionWithTeeSecurityLevels.copy(
        softwareEnforced = authorizationList.copy(attestationApplicationId = actualAppId),
        hardwareEnforced = authorizationList.copy(osVersion = BigInteger.valueOf(130000)),
      )
    assertIs<Constraint.Satisfied>(
      AttestationApplicationIdConstraint.ALLOW_UNKNOWN_PACKAGE(MAX_OS_VERSION)
        .check(TEST_APP_ID, kdLowerOs)
    )
  }

  @Test
  fun attestationApplicationId_lenient_mismatchedAppId_withUnknownPackage_andHigherOsVersion_returnsViolated() {
    val actualAppId =
      AttestationApplicationId(packages = setOf(UNKNOWN_PACKAGE), signatures = setOf())
    val kd =
      keyDescriptionWithTeeSecurityLevels.copy(
        softwareEnforced = authorizationList.copy(attestationApplicationId = actualAppId),
        hardwareEnforced = authorizationList.copy(osVersion = BigInteger.valueOf(150000)),
      )

    assertIs<Constraint.Violated>(
      AttestationApplicationIdConstraint.ALLOW_UNKNOWN_PACKAGE(MAX_OS_VERSION)
        .check(TEST_APP_ID, kd)
    )
  }

  @Test
  fun attestationApplicationId_lenient_mismatchedAppId_withoutUnknownPackage_andLowerOsVersion_returnsViolated() {
    assertIs<Constraint.Violated>(
      AttestationApplicationIdConstraint.ALLOW_UNKNOWN_PACKAGE(MAX_OS_VERSION)
        .check(
          AttestationApplicationId(
            packages = setOf(AttestationPackageInfo("com.other.app", BigInteger.valueOf(10))),
            signatures = setOf(TEST_SIGNATURE),
          ),
          keyDescriptionWithTeeSecurityLevels,
        )
    )
  }

  @Test
  fun attestationApplicationId_lenient_mismatchedAppId_withUnknownPackageWrongVersion_returnsViolated() {
    val actualAppId =
      AttestationApplicationId(
        packages = setOf(AttestationPackageInfo("UnknownPackage", BigInteger.valueOf(2))),
        signatures = setOf(),
      )
    val kd =
      keyDescriptionWithTeeSecurityLevels.copy(
        softwareEnforced = authorizationList.copy(attestationApplicationId = actualAppId),
        hardwareEnforced = authorizationList.copy(osVersion = BigInteger.valueOf(130000)),
      )

    assertIs<Constraint.Violated>(
      AttestationApplicationIdConstraint.ALLOW_UNKNOWN_PACKAGE(MAX_OS_VERSION)
        .check(TEST_APP_ID, kd)
    )
  }

  @Test
  fun attestationApplicationId_none_alwaysReturnsSatisfied() {
    assertIs<Constraint.Satisfied>(
      AttestationApplicationIdConstraint.NONE.check(
        TEST_APP_ID,
        keyDescriptionWithTeeSecurityLevels,
      )
    )
  }

  @Test
  fun attestationApplicationIdConstraint_withViolation_returnsCorrectMessage() {
    val expectedAppId =
      AttestationApplicationId(
        packages = setOf(AttestationPackageInfo("com.other.app", BigInteger.valueOf(10))),
        signatures = setOf(TEST_SIGNATURE),
      )
    val constraint = AttestationApplicationIdConstraint.STRICT

    val violation =
      assertIs<Constraint.Violated>(
        constraint.check(expectedAppId, keyDescriptionWithTeeSecurityLevels)
      )
    assertThat(violation.failureMessage)
      .isEqualTo(
        "Attestation application ID violates constraint: attestationApplicationId=$TEST_APP_ID, config=$constraint"
      )
    assertThat(constraint.label).isEqualTo("Attestation application ID")
  }
}
