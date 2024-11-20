/*
 * Copyright 2024 Google LLC
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

package com.android.keyattestation.verifier.testing

import com.android.keyattestation.verifier.keyDescription
import com.android.keyattestation.verifier.testing.TestUtils.TESTDATA_PATH
import com.android.keyattestation.verifier.testing.TestUtils.readCertPath
import com.google.devtools.api.source.vcslib.Vcslib
import com.google.devtools.javatools.formatting.Fmtserver.FileType
import com.google.devtools.javatools.formatting.Formatter
import com.google.devtools.javatools.formatting.file
import com.google.devtools.javatools.formatting.formatRequest
import com.google.net.rpc3.client.RpcClientContext
import com.google.net.rpc3.client.builder.RpcStubParametersBuilder
import com.google.protobuf.kotlin.toByteStringUtf8
import java.nio.file.Files
import java.nio.file.Path
import kotlin.io.path.Path
import kotlin.io.path.extension
import kotlin.io.path.isDirectory
import kotlin.io.path.name
import kotlin.io.path.nameWithoutExtension
import kotlin.io.path.readText
import kotlin.io.path.reader
import kotlin.io.path.writeText

/**
 * Regenerates the test golden data.
 *
 * Usage:
 * ```shell
 * $ blaze run //java/com/google/wireless/android/security/attestationverifier/testing:RegenerateTestData
 * ```
 */
object RegenerateTestData {
  private val testDataPath by lazy {
    val workspaceDir =
      System.getenv()["BUILD_WORKSPACE_DIRECTORY"]
        ?: error("Must be invoked from within a google3 workspace")
    val vcs = Vcslib.vcsInfoFor(workspaceDir)
    Path(vcs.sourceRoot(), "google3", TESTDATA_PATH)
  }

  private val fmtServer: Formatter.ClientInterface =
    Formatter.newStub(RpcStubParametersBuilder().setCombinedServerSpec("blade:fmtserver").create())

  @JvmStatic
  fun main(args: Array<String>) {
    Files.walk(testDataPath)
      .skip(1)
      .filter { path -> path.isDirectory() }
      .filter { path -> !path.endsWith("invalid") }
      .forEach { path -> processDirectory(path) }
  }

  private fun processDirectory(dirPath: Path) {
    for (path in Files.walk(dirPath, 1).filter { it.extension == "pem" }) {
      val chain = readCertPath(path.reader())
      val leafCert =
        requireNotNull(chain.leafCert()) { "$path: Chain does not contain a leaf certificate" }
      val keyDescription =
        requireNotNull(leafCert.keyDescription()) { "$path: Failed to parse attestation extension" }

      val outPath = dirPath.resolve("${path.nameWithoutExtension}.json")
      dirPath.resolve(outPath).writeText(keyDescription.toJson())
      formatFile(dirPath.resolve(outPath))
    }
  }

  /** Formats a JSON file in-place using go/fmtserver. */
  private fun formatFile(path: Path) {
    val request = formatRequest {
      type = FileType.JSON
      file += file {
        name = path.name
        contents = path.readText().toByteStringUtf8()
      }
    }
    val response = fmtServer.format(RpcClientContext.create(), request)
    if (!response.getFile(0).correct) {
      path.writeText(response.getFile(0).contents.toStringUtf8())
    }
  }
}
