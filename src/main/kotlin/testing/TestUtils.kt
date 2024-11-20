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

import com.android.keyattestation.verifier.KeyDescription
import com.android.keyattestation.verifier.asX509Certificate
import com.android.keyattestation.verifier.provider.KeyAttestationCertPath
import com.google.devtools.build.runtime.RunfilesPaths
import com.google.gson.Gson
import com.google.protobuf.ByteString
import com.squareup.moshi.FromJson
import com.squareup.moshi.Moshi
import com.squareup.moshi.ToJson
import java.io.Reader
import java.math.BigInteger
import java.nio.file.Path
import java.security.cert.TrustAnchor
import java.util.Base64
import kotlin.io.path.Path
import kotlin.io.path.reader
import org.bouncycastle.cert.X509CertificateHolder
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter
import org.bouncycastle.openssl.PEMParser

object TestUtils {
  private const val PROD_ROOT_PATH =
    "googledata/html/external_content/android_googleapis_com/attestation/root"
  const val TESTDATA_PATH =
    "javatests/com/google/wireless/android/security/attestationverifier/testdata"

  fun readCertPath(subpath: String): KeyAttestationCertPath =
    readCertPath(readFile(Path(base = TESTDATA_PATH, /* subpaths...= */ subpath)))

  fun readCertPath(reader: Reader): KeyAttestationCertPath {
    return PEMParser(reader)
      .use {
        buildList {
          var obj = it.readObject()
          while (obj != null) {
            add(obj as X509CertificateHolder)
            obj = it.readObject()
          }
        }
      }
      .map { JcaX509CertificateConverter().getCertificate(it) }
      .let { KeyAttestationCertPath(it) }
  }

  val prodRoot by lazy {
    val certs = Gson().fromJson(readFile(PROD_ROOT_PATH), Array<String>::class.java).toSet()
    check(certs.size == 1) { "Multiple certificates in the root file are not yet supported" }
    certs.first().asX509Certificate()
  }

  val prodAnchor = TrustAnchor(prodRoot, null)

  private fun readFile(path: Path) = RunfilesPaths.resolve(path).reader()

  private fun readFile(path: String) = RunfilesPaths.resolve(path).reader()
}

object Base64ByteStringAdapter {
  @ToJson
  fun toJson(value: ByteString): String {
    return Base64.getEncoder().encodeToString(value.toByteArray())
  }

  @FromJson
  fun fromJson(value: String): ByteString {
    return ByteString.copyFrom(Base64.getDecoder().decode(value))
  }
}

object BigIntegerAdapter {
  @FromJson fun fromJson(value: String) = BigInteger(value)

  @ToJson fun toJson(value: BigInteger) = value.toString()
}

private val moshi = Moshi.Builder().add(Base64ByteStringAdapter).add(BigIntegerAdapter).build()
private val keyDescriptionAdapter = moshi.adapter(KeyDescription::class.java)

internal fun KeyDescription.toJson() = keyDescriptionAdapter.toJson(this)

fun String.toKeyDescription() = keyDescriptionAdapter.fromJson(this)
