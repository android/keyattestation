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

import java.io.ByteArrayOutputStream
import java.io.PrintStream
import java.nio.charset.StandardCharsets
import java.nio.file.Files
import org.junit.Test
import org.junit.runner.RunWith
import org.junit.runners.JUnit4

@RunWith(JUnit4::class)
class VerifierCliTest {
  companion object {
    private fun resolveTestData(path: String) =
    kotlin.io.path.Path("testdata/$path")
  }

  @Test
  fun run_validChain_outputsSuccess() {
    val path = resolveTestData("tegu/sdk36/TEE_EC_2026_ROOT.pem")
    val outputStream = ByteArrayOutputStream()
    val printStream = PrintStream(outputStream, true, StandardCharsets.UTF_8.name())

    VerifierCli(printStream).run(arrayOf(path.toString()))

    val output = outputStream.toString(StandardCharsets.UTF_8.name())
    assertThat(output).contains("Verification Successful!")
    assertThat(output).contains("attestationSecurityLevel: TRUSTED_ENVIRONMENT")
    assertThat(output).contains("verifiedBootState: VERIFIED")
  }

  @Test
  fun run_invalidChain_outputsFailure() {
    val path = resolveTestData("invalid/tags_not_in_ascending_order.pem")
    val outputStream = ByteArrayOutputStream()
    val printStream = PrintStream(outputStream, true, StandardCharsets.UTF_8.name())

    VerifierCli(printStream).run(arrayOf(path.toString()))

    val output = outputStream.toString(StandardCharsets.UTF_8.name())
    assertThat(output).contains("Verification Failed")
  }

  @Test
  fun run_garbageFile_outputsNoCertificatesFound() {
    val path = Files.createTempFile("garbage", ".pem")
    Files.write(path, "This is not a certificate".toByteArray(StandardCharsets.UTF_8))
    val outputStream = ByteArrayOutputStream()
    val printStream = PrintStream(outputStream, true, StandardCharsets.UTF_8.name())

    VerifierCli(printStream).run(arrayOf(path.toString()))

    val output = outputStream.toString(StandardCharsets.UTF_8.name())
    assertThat(output).contains("No certificates found in the file.")
  }

  @Test
  fun run_singleCertificate_skipsValidation() {
    val pem =
      """
-----BEGIN CERTIFICATE-----
MIIDGTCCAr+gAwIBAgIBATAKBggqhkjOPQQDAjA/MRIwEAYDVQQMDAlTdHJvbmdC
b3gxKTAnBgNVBAUTIGM3NmMxY2YyYzFlNjAyZTIyNDNjZWFjYzZjNDhmZDY2MB4X
DTI2MDIyNDE5MTMxNFoXDTI2MDIyNDE5MjMxNFowHzEdMBsGA1UEAxMUQW5kcm9p
ZCBLZXlzdG9yZSBLZXkwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAT94SNF9xvU
8j59w59kKiB5HRxi+MoY1cYeW9bOeBwZiKMoy+0G7o3WDFW8qeKDf7+PWIqw8XBh
t/F+T63P6svEo4IByjCCAcYwDgYDVR0PAQH/BAQDAgeAMIIBsgYKKwYBBAHWeQIB
EQSCAaIwggGeAgIBLAoBAgICASwKAQIECAAAAZyREsJjBAAwWr+FPQgCBgGckRLz
qL+FRUoESDBGMSAwHgQWY29tLmdvb2dsZS5hbmRyb2lkLmdtcwIEDzH4MzEiBCAZ
dbLxcXe8iaXf8x+eZKbK4oGlPcHR1ZsdFH/hyCr6ADCCASShBTEDAgECogMCAQOj
BAICAQClBTEDAgEEqgMCAQG/g3cCBQC/hT4DAgEAv4VATDBKBCAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAEBAAoBAgQghTYtfyzOcjrZ9r5loF+0KXCH
Zksoyjtkn3Cs5xMfhUO/hUEFAgMCcQC/hUIFAgMDF2u/hUYIBAZnb29nbGW/hUcH
BAVyYW5nb7+FSAcEBXJhbmdvv4VJEAQONTQzMDFGRENHMDAwNTW/hUoRBA8zNTQ3
OTI2NDAxNjA2MDa/hUwIBAZHb29nbGW/hU0TBBFQaXhlbCAxMCBQcm8gRm9sZL+F
TgYCBAE1JdG/hU8GAgQBNSXRv4VTEQQPMzU0NzkyNjQwMTYwNjE0MAoGCCqGSM49
BAMCA0gAMEUCIQDsQfNc6amKNPa09HAdC2ttlwa7ZYth3QriCT+XubzsigIgRM87
F3amnfzZkTIFYCL1rPPb6Vp9pI1xhRE5Uk21Eso=
-----END CERTIFICATE-----
"""
    val path = Files.createTempFile("single_cert", ".pem")
    Files.write(path, pem.trim().toByteArray(StandardCharsets.UTF_8))
    val outputStream = ByteArrayOutputStream()
    val printStream = PrintStream(outputStream, true, StandardCharsets.UTF_8.name())

    VerifierCli(printStream).run(arrayOf(path.toString()))

    val output = outputStream.toString(StandardCharsets.UTF_8.name())
    assertThat(output)
      .contains("Only one certificate found in the file. Skipping chain validation.")
    assertThat(output).contains("Key Description:")
  }

  @Test
  fun run_weirdNumberOfCerts_outputsWarning() {
    val pem =
      """
-----BEGIN CERTIFICATE-----
MIIB/zCCAYWgAwIBAgIQa3t2bdQ8SUwTPwRFiW7JUzAKBggqhkjOPQQDAjA/MRIw
EAYDVQQMDAlTdHJvbmdCb3gxKTAnBgNVBAUTIGYzZGYxOTdiMTQxYzkzNDdjN2Rh
ZjAzNzVlYzBmOTQ5MB4XDTIwMDkxMTE4MDI0MloXDTMwMDkwOTE4MDI0MlowPzES
MBAGA1UEDAwJU3Ryb25nQm94MSkwJwYDVQQFEyBjNzZjMWNmMmMxZTYwMmUyMjQz
Y2VhY2M2YzQ4ZmQ2NjBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABCaEwkCPBQpw
sZg5+8gxAsXi9vs01+kLt4ubw+TpCNo4Y7dH4vxHdaS1vjlhpkknkvhBNZDZACul
BAoDWBpveoKjYzBhMB0GA1UdDgQWBBT+tIq2wD7bX50KwNIbOTnjgtiJijAfBgNV
HSMEGDAWgBRu5hHfcEbVuzRtjS2OBjcfUnGrTTAPBgNVHRMBAf8EBTADAQH/MA4G
A1UdDwEB/wQEAwICBDAKBggqhkjOPQQDAgNoADBlAjBjG8OmB/fwQr2JNjcOGuYL
xN1xzCvOlufug2nASHuSprsXVJWq3LAH4f3O5KvwKs0CMQDW9RisqFSDyJhc4kCv
CCW4UN0vFX7COXV6mD9QYUabN18emfu9jYjAhDNIXbfQJBY=
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIDmTCCAYGgAwIBAgIQBg2Ja9xgpXallHvgiV9ZiTANBgkqhkiG9w0BAQsFADAb
MRkwFwYDVQQFExBmOTIwMDllODUzYjZiMDQ1MB4XDTIwMDkxMTE4MDIyMVoXDTMw
MDkwOTE4MDIyMVowPzESMBAGA1UEDAwJU3Ryb25nQm94MSkwJwYDVQQFEyBmM2Rm
MTk3YjE0MWM5MzQ3YzdkYWYwMzc1ZWMwZjk0OTB2MBAGByqGSM49AgEGBSuBBAAi
A2IABHJGYGgFBHogBxkYllZN3Ckx4N40qmD72LhOxrVE73IqhDuP7naPKmEdfcF4
U4lzb/FzFPZ/fsHmSE/DSwHoST3AxQwq9g0xx/m1p/aWPVq8Rco2uhSgsnLMbGz2
8V6jY6NjMGEwHQYDVR0OBBYEFG7mEd9wRtW7NG2NLY4GNx9ScatNMB8GA1UdIwQY
MBaAFDZh4QB8iAUJUYtEbEf/GkzJ6k8SMA8GA1UdEwEB/wQFMAMBAf8wDgYDVR0P
AQH/BAQDAgIEMA0GCSqGSIb3DQEBCwUAA4ICAQA4KNgGY+XZsN9BgD53T//kTlya
sN6bBnyajVac3O9pvYgLarushTyz8xfbtio3WEy5484QiWKhXbVTGFjt9XeH0drH
e2dYBKroYxWGsI0NdY3trA1uMx80oWhvEuFxvAQHV//UHd0YQCVuXjDQTP8Fdr8n
8eYPBd5fxQol+pWY0UjbPgpf3Pz5KkJBEp5aijoLurlANL11d1pX8fotCCLhh0/Q
ArmFbAxTOQrCIRI+2yX0D1DwazeWrZLSD/hPkM1/uEmleE45XEUXy2MLdixtEiI6
yy+A/wQMizMoVhVuXVUZZiDLHPtNTjxQs5ZXDyDyxpJa0X5WckbttqRuEgd6iMWV
hhMatfV7e8jXmt72BJzSZWOAf2hU2Xes6oIGjFah6AIFcMoqKfBzClrEbkiES+qL
SXuBjDNkI3jXcU775OI/Q+gK19yDtzR+wl1uP8ivGnRixTc96r/i4AwTyiijvWW6
QQcKAwTJSniD5LS5V/jB5ml6oX26fFhQteRPAsLXQfD11adkh7suquWL3ZV1GNSH
+89rbGtO1wSl98cHnUu30dXSxHBAPK+N3S7sz8YaM1CBpb4eUCj6ASR6Hr/UxW9G
EnajLq2KPYf8MqG0ECgxQf9PDBBkTnZfFMRs4/FNtaUu10dOjj7ltEfrS0rHjgYE
ykrM9WmORlkUk9NsoQ==
-----END CERTIFICATE-----
"""
    val path = Files.createTempFile("weird_cert_count", ".pem")
    Files.write(path, pem.trim().toByteArray(StandardCharsets.UTF_8))
    val outputStream = ByteArrayOutputStream()
    val printStream = PrintStream(outputStream, true, StandardCharsets.UTF_8.name())

    VerifierCli(printStream).run(arrayOf(path.toString()))

    val output = outputStream.toString(StandardCharsets.UTF_8.name())
    assertThat(output).contains("Less than 3 certificates found in the file.")
    assertThat(output)
      .contains("This cannot possibly be a valid Key Attestation certificate chain.")
  }
}
