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

import com.google.gson.Gson
import java.io.IOException
import java.io.InputStream
import java.io.InputStreamReader
import java.net.HttpURLConnection
import java.net.URI
import java.net.URL

/**
 * Fetches Google's revocation status list from the web.
 *
 * This function will fail-closed if it cannot download or parse the revocation list, by throwing an
 * exception.
 *
 * @return A set of revoked serial numbers.
 */
fun getGoogleRevocationStatusFromWeb(): Set<String> =
  getRevocationStatusFromWeb(
    URI.create("https://android.googleapis.com/attestation/status").toURL()
  )

/**
 * Fetches a revocation status list from the web.
 *
 * This function will fail-closed if it cannot download or parse the revocation list, by throwing an
 * exception.
 *
 * @return A set of revoked serial numbers.
 */
fun getRevocationStatusFromWeb(
  url: URL,
  connectionProvider: (URL) -> HttpURLConnection = {
    (it.openConnection() as? HttpURLConnection)
      ?: throw IllegalArgumentException("Could not open HttpURLConnection to $it")
  },
): Set<String> {
  val connection = connectionProvider(url)
  try {
    connection.requestMethod = "GET"
    connection.connect()

    if (connection.responseCode != HttpURLConnection.HTTP_OK) {
      throw IOException(
        "Failed to fetch revocation list from $url: HTTP ${connection.responseCode}"
      )
    }
    return parseAttestationStatus(connection.inputStream)
  } finally {
    connection.disconnect()
  }
}

/**
 * Parses a revocation status list from an input stream.
 *
 * This function will fail-closed if it cannot parse the revocation list, by throwing an exception.
 *
 * @return A set of revoked serial numbers.
 */
fun parseAttestationStatus(input: InputStream): Set<String> {
  data class StatusEntry(val status: String)
  data class StatusFile(val entries: Map<String, StatusEntry>)

  return Gson()
    .fromJson(InputStreamReader(input), StatusFile::class.java)
    .entries
    .filterValues { it.status == "REVOKED" }
    .keys
}
