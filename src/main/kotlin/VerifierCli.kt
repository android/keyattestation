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

import java.io.File
import java.io.PrintStream
import java.security.cert.X509Certificate
import java.time.Instant

// Any chain shorter than this is not possibly valid Key Attestation chain.
private const val MIN_CERTS_IN_VALID_CHAIN = 3

class VerifierCli(private val output: PrintStream, private val instantSource: InstantSource) {
  companion object {
    @JvmStatic
    fun main(args: Array<String>) {
      VerifierCli(System.out, { Instant.now() }).run(args)
    }
  }

  fun run(args: Array<String>) {
    if (args.size != 1) {
      output.println("Usage: verifier_cli <path_to_pem_file>")
      output.println("Input may be a single certificate or a certificate chain.")
      return
    }

    val certs: List<X509Certificate>? = parsePemChain(File(args[0]).readText())
    when {
      certs == null || certs.isEmpty() -> {
        output.println("No certificates found in the file.")
      }
      certs.size == 1 -> {
        output.println("Only one certificate found in the file. Skipping chain validation.")
        certs.firstOrNull()?.let { output.println(CertPrinter.prettyString(it)) }
      }
      certs.size < MIN_CERTS_IN_VALID_CHAIN -> {
        output.println("Less than ${MIN_CERTS_IN_VALID_CHAIN} certificates found in the file.")
        output.println("This cannot possibly be a valid Key Attestation certificate chain.")
      }
      else -> {
        verify(certs)
      }
    }
  }

  private fun verify(certs: List<X509Certificate>) {
    val verifier =
      Verifier(
        trustAnchorsSource = GoogleTrustAnchors,
        revokedSerialsSource = { emptySet() },
        instantSource,
      )

    val result = verifier.verify(certs)

    when (result) {
      is VerificationResult.Success -> {
        output.println("Verification Successful!")
        for (cert in certs) {
          output.println(CertPrinter.prettyString(cert))
        }
      }
      else -> {
        output.println("Verification Failed: $result")
        val leaf = certs.firstOrNull()
        if (leaf != null) {
          output.println("Leaf certificate:")
          output.println(CertPrinter.prettyString(leaf))
        }
      }
    }
  }

  private fun parsePemChain(pem: String) =
    """-----BEGIN CERTIFICATE-----([\s\S]*?)-----END CERTIFICATE-----"""
      .toRegex()
      .findAll(pem)
      .map { it.value.asX509Certificate() }
      .toList()
}
