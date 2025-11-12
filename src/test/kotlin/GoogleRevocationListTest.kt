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

import com.google.common.truth.Truth.assertThat
import java.io.IOException
import java.io.InputStream
import java.net.HttpURLConnection
import java.net.URI
import java.net.URL
import kotlin.test.assertFailsWith
import org.junit.Test
import org.junit.runner.RunWith
import org.junit.runners.JUnit4

@RunWith(JUnit4::class)
class GoogleRevocationListTest {
  @Test
  fun getGoogleRevocationStatusFromWeb_success() {
    val json =
      """
      {
        "entries": {
          "abc": { "status": "REVOKED" },
          "def": { "status": "OK" }
        }
      }
      """
        .trimIndent()
    val uri = URI("http://localhost")
    val result =
      getRevocationStatusFromWeb(uri.toURL()) {
        FakeHttpURLConnection(uri.toURL(), HttpURLConnection.HTTP_OK, json)
      }

    assertThat(result).containsExactly("abc")
  }

  @Test
  fun getRevocationStatusFromWeb_httpError_throwsIOException() {
    val uri = URI("http://localhost")
    assertFailsWith<IOException> {
      getRevocationStatusFromWeb(uri.toURL()) {
        FakeHttpURLConnection(uri.toURL(), HttpURLConnection.HTTP_NOT_FOUND)
      }
    }
  }

  @Test
  fun parseAttestationStatus_emptyList() {
    val json = """{"entries": {}}"""
    val result = parseAttestationStatus(json.byteInputStream())
    assertThat(result).isEmpty()
  }

  @Test
  fun parseAttestationStatus_revokedAndOkEntries() {
    val json =
      """
      {
        "entries": {
          "abc": {
            "status": "REVOKED",
            "reason": "KEY_COMPROMISE"
          },
          "def": {
            "status": "OK"
          },
          "123": {
            "status": "REVOKED",
            "reason": "SUPERSEDED"
          }
        }
      }
      """
        .trimIndent()
    val result = parseAttestationStatus(json.byteInputStream())
    assertThat(result).containsExactly("abc", "123")
  }

  @Test
  fun parseAttestationStatus_onlyOkEntries() {
    val json =
      """
      {
        "entries": {
          "def": {
            "status": "OK"
          },
          "456": {
            "status": "OK"
          }
        }
      }
      """
        .trimIndent()
    val result = parseAttestationStatus(json.byteInputStream())
    assertThat(result).isEmpty()
  }

  @Test
  fun parseAttestationStatus_onlyRevokedEntries() {
    val json =
      """
      {
        "entries": {
          "abc": {
            "status": "REVOKED",
            "reason": "KEY_COMPROMISE"
          },
          "123": {
            "status": "REVOKED",
            "reason": "SUPERSEDED"
          }
        }
      }
      """
        .trimIndent()
    val result = parseAttestationStatus(json.byteInputStream())
    assertThat(result).containsExactly("abc", "123")
  }
}

private class FakeHttpURLConnection(
  url: URL,
  private val fakeResponseCode: Int,
  val responseBody: String = "",
) : HttpURLConnection(url) {
  override fun connect() {}

  override fun disconnect() {}

  override fun getInputStream(): InputStream = responseBody.byteInputStream()

  override fun getResponseCode() = fakeResponseCode

  override fun usingProxy() = false
}
