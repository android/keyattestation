package com.android.keyattestation.verifier

import com.google.common.truth.Truth.assertThat
import com.google.protobuf.ByteString
import org.junit.Test
import org.junit.runner.RunWith
import org.junit.runners.JUnit4

@RunWith(JUnit4::class)
class ExtensionBuildersTest {
  @Test
  fun attestationPackageInfo_isUnmodifiable() {
    val packages = mutableSetOf<AttestationPackageInfo>()
    val appId =
      AttestationApplicationIdBuilder.attestationApplicationIdBuilder()
        .setPackages(packages)
        .setSignatures(setOf(ByteString.copyFromUtf8("signature")))
        .build()
    packages.add(AttestationPackageInfo(name = "foo", version = 1.toBigInteger()))
    assertThat(appId.packages).isEqualTo(setOf<AttestationPackageInfo>())
  }
}
