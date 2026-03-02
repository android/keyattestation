/*
 * Copyright 2026 Google LLC
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

import com.google.common.truth.Truth.assertThat
import com.google.protobuf.ByteString
import java.io.ByteArrayInputStream
import java.math.BigInteger
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import org.junit.Test
import org.junit.runner.RunWith
import org.junit.runners.JUnit4

@RunWith(JUnit4::class)
class CertPrinterTest {

  @Test
  fun prettyPrint_certWithKeyDescription_containsExpectedFields() {
    val certPem =
      """
      -----BEGIN CERTIFICATE-----
      MIIDHzCCAsWgAwIBAgIBATAKBggqhkjOPQQDAjA5MQwwCgYDVQQKEwNURUUxKTAnBgNVBAMTIGE0Njk5
      OTU2ZjVmYTJlNTk0NDZkYWViMDM0NWVlNjBiMB4XDTcwMDEwMTAwMDAwMFoXDTQ4MDEwMTAwMDAwMFow
      HzEdMBsGA1UEAxMUQW5kcm9pZCBLZXlzdG9yZSBLZXkwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAASs
      PMgrwPgQUvwR9Sv/sH6eGYJKLzJCPZQJ/Pz3m55hjZT9NbGoRN3RtbyOyg7eeYIVahdlt9TEgNSWyX00
      3nMoo4IB1jCCAdIwggG+BgorBgEEAdZ5AgERBIIBrjCCAaoCAgGQCgEBAgIBkAoBAQQkYmZmYzVkNmEt
      NmQxNi00ZjYxLTg0NDctMzFhZTVkYzQ1MmJjBAAwgYW/hT0IAgYBm5W5jq6/hUVPBE0wSzElMCMEHmNv
      bS5nb29nbGUuYW5kcm9pZC5hdHRlc3RhdGlvbgIBADEiBCAQOTjuRTflno7nkvZUUE+4NG/Gs0bQu8RB
      X8M5/PyOwb+FVCIEIP3h2NJD1LAsHh6KEX9ZdFn1LPNBiSxGCOo4UCMd2R2YMIHpoQgxBgIBAgIBA6ID
      AgEDowQCAgEApQUxAwIBBKoDAgEBv4N3AgUAv4U+AwIBAL+FQEwwSgQgAAAAAAAAAAAAAAAAAAAAAAAA
      AAAAAAAAAAAAAAAAAAABAf8KAQAEIDOaZqcibz+y1aPvaSJvY0gx7hzI+4+Lz37WaJhTKKR/v4VBBQID
      AnEAv4VCBQIDAxdqv4VGCAQGZ29vZ2xlv4VHBwQFcmFuZ2+/hUgHBAVyYW5nb7+FTAgEBkdvb2dsZb+F
      TRMEEVBpeGVsIDEwIFBybyBGb2xkv4VOBgIEATUlbb+FTwYCBAE1JW0wDgYDVR0PAQH/BAQDAgeAMAoG
      CCqGSM49BAMCA0gAMEUCIA3zQL6efoCyw7aYU2x6NqY0yt4JHhs1yXlEvqwg7ZiCAiEA7brdQWRd3J6O
      Xh4ozGU8VwOIqq3rB7MkIwyCej3omiQ=
      -----END CERTIFICATE-----
      """
        .trimIndent()

    val cf = CertificateFactory.getInstance("X.509")
    val cert =
      cf.generateCertificate(ByteArrayInputStream(certPem.toByteArray())) as X509Certificate
    val certString = CertPrinter.prettyString(cert)

    assertThat(certString)
      .isEqualTo(
        """
        |X.509 Certificate:
        |    Version: 3
        |    Serial Number: 1
        |    Signature Algorithm: SHA256withECDSA
        |    Issuer: CN=a4699956f5fa2e59446daeb0345ee60b, O=TEE
        |    Validity:
        |        Not Before: 1970-01-01T00:00:00.000Z
        |        Not After: 2048-01-01T00:00:00.000Z
        |    Subject: CN=Android Keystore Key
        |    Public Key Algorithm: EC
        |Custom Extensions:
        |    Key Description:
        |        attestationVersion: 400
        |        attestationSecurityLevel: TRUSTED_ENVIRONMENT
        |        keyMintVersion: 400
        |        keyMintSecurityLevel: TRUSTED_ENVIRONMENT
        |        attestationChallenge: 62666663356436612d366431362d346636312d383434372d333161653564633435326263
        |        uniqueId: ""
        |        softwareEnforced:
        |            creationDateTime: 2026-01-06T23:52:04.526Z
        |            attestationApplicationId:
        |                packages:
        |                    name: com.google.android.attestation, version: 0
        |                signatures:
        |                    103938ee4537e59e8ee792f654504fb8346fc6b346d0bbc4415fc339fcfc8ec1
        |            moduleHash: fde1d8d243d4b02c1e1e8a117f597459f52cf341892c4608ea3850231dd91d98
        |        hardwareEnforced:
        |            purposes: [SIGN, VERIFY]
        |            algorithms: EC
        |            keySize: 256
        |            digests: [SHA_2_256]
        |            ecCurve: P_256
        |            noAuthRequired: true
        |            origin: GENERATED
        |            rootOfTrust:
        |                verifiedBootKey: 0000000000000000000000000000000000000000000000000000000000000000
        |                deviceLocked: true
        |                verifiedBootState: VERIFIED
        |                verifiedBootHash: 339a66a7226f3fb2d5a3ef69226f634831ee1cc8fb8f8bcf7ed668985328a47f
        |            osVersion: 160000
        |            osPatchLevel: 202602
        |            attestationIdBrand: google
        |            attestationIdDevice: rango
        |            attestationIdProduct: rango
        |            attestationIdManufacturer: Google
        |            attestationIdModel: Pixel 10 Pro Fold
        |            vendorPatchLevel: 20260205
        |            bootPatchLevel: 20260205
        |"""
          .trimMargin()
      )
  }

  @Test
  fun prettyPrint_certWithProvisioningInfo_containsExpectedFields() {
    val certPem =
      """
      -----BEGIN CERTIFICATE-----
      MIIB4zCCAYmgAwIBAgIRAKRpmVb1+i5ZRG2usDRe5gswCgYIKoZIzj0EAwIwKTETMBEGA1UEChMKR29v
      Z2xlIExMQzESMBAGA1UEAxMJRHJvaWQgQ0EzMB4XDTI2MDEwNDIzNTIwNVoXDTI2MDExMzIzNTIwNVow
      OTEMMAoGA1UEChMDVEVFMSkwJwYDVQQDEyBhNDY5OTk1NmY1ZmEyZTU5NDQ2ZGFlYjAzNDVlZTYwYjBZ
      MBMGByqGSM49AgEGCCqGSM49AwEHA0IABHhAy148nSdWGSL2nANKuFuKaeiG/0eDf7hV3PiVy65mXroe
      c8z5yREemH4wb93jQJuCXomaoWzTi3vJYUuvZLSjgYEwfzAdBgNVHQ4EFgQUXcFm1z+N5fMjutiLG6vk
      g+QOJNowHwYDVR0jBBgwFoAUr9Ze5/g+WQ7f/6MZ4PbO1lD7/i4wDwYDVR0TAQH/BAUwAwEB/zAOBgNV
      HQ8BAf8EBAMCAgQwHAYKKwYBBAHWeQIBHgQOowEYQAL1A2ZHb29nbGUwCgYIKoZIzj0EAwIDSAAwRQIh
      AIKMDL79gwLPhWXd0gxdfBXJpxb9c/GiWrkDwPyTFS8oAiBvD5m/7+/uCETxpKnUzX/kh4GnbSpo6q+5
      +aMMwqkWGA==
      -----END CERTIFICATE-----
      """
        .trimIndent()

    val cf = CertificateFactory.getInstance("X.509")
    val cert =
      cf.generateCertificate(ByteArrayInputStream(certPem.toByteArray())) as X509Certificate
    val certString = CertPrinter.prettyString(cert)

    var expectedString =
      """
      |X.509 Certificate:
      |    Version: 3
      |    Serial Number: a4699956f5fa2e59446daeb0345ee60b
      |    Signature Algorithm: SHA256withECDSA
      |    Issuer: CN=Droid CA3, O=Google LLC
      |    Validity:
      |        Not Before: 2026-01-04T23:52:05.000Z
      |        Not After: 2026-01-13T23:52:05.000Z
      |    Subject: CN=a4699956f5fa2e59446daeb0345ee60b, O=TEE
      |    Public Key Algorithm: EC
      |Custom Extensions:
      |    Provisioning Info:
      |        certificatesIssued: 64
      |"""
        .trimMargin()
    assertThat(certString).isEqualTo(expectedString)
  }

  @Test
  fun prettyPrint_provisioningInfoMap_matchesExpectedString() {
    val info =
      ProvisioningInfoMap(
        certificatesIssued = 42,
      )
    val infoString = CertPrinter.prettyString(info)

    var expectedString =
      """
      |Provisioning Info:
      |    certificatesIssued: 42
      |"""
        .trimMargin()
    assertThat(infoString).isEqualTo(expectedString)
  }
}
