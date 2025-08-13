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
import com.android.keyattestation.verifier.PatchLevel
import com.android.keyattestation.verifier.asX509Certificate
import com.android.keyattestation.verifier.provider.KeyAttestationCertPath

import com.google.gson.Gson
import com.google.gson.GsonBuilder
import com.google.gson.JsonDeserializationContext
import com.google.gson.JsonDeserializer
import com.google.gson.JsonElement
import com.google.gson.JsonPrimitive
import com.google.gson.JsonSerializationContext
import com.google.gson.JsonSerializer
import com.google.protobuf.ByteString
import java.io.Reader
import java.lang.reflect.Type
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
  private const val PROD_ROOT_PATH = "roots.json"
  const val TESTDATA_PATH = "testdata"

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

  val prodAnchors by lazy {
    Gson()
      .fromJson(readFile(PROD_ROOT_PATH), Array<String>::class.java)
      .map { TrustAnchor(it.asX509Certificate(), null) }
      .toSet()
  }

  private fun readFile(path: Path) = path.reader()
  private fun readFile(path: String) = readFile(Path(path))
}

object Base64ByteStringAdapter : JsonDeserializer<ByteString>, JsonSerializer<ByteString> {
  override fun serialize(value: ByteString, typeOfSrc: Type, context: JsonSerializationContext) =
    JsonPrimitive(Base64.getEncoder().encodeToString(value.toByteArray()))

  override fun deserialize(json: JsonElement, typeOfT: Type, context: JsonDeserializationContext) =
    ByteString.copyFrom(Base64.getDecoder().decode(json.asJsonPrimitive.asString))
}

object BigIntegerAdapter : JsonDeserializer<BigInteger>, JsonSerializer<BigInteger> {
  override fun serialize(value: BigInteger, typeOfSrc: Type, context: JsonSerializationContext) =
    JsonPrimitive(value.toString())

  override fun deserialize(json: JsonElement, typeOfT: Type, context: JsonDeserializationContext) =
    BigInteger(json.asJsonPrimitive.asString)
}

// Assumes everything is well formatted.
object PatchLevelAdapter : JsonDeserializer<PatchLevel>, JsonSerializer<PatchLevel> {
  override fun serialize(value: PatchLevel, typeOfSrc: Type, context: JsonSerializationContext) =
    JsonPrimitive(value.toString())

  override fun deserialize(json: JsonElement, typeOfT: Type, context: JsonDeserializationContext) =
    PatchLevel.from(json.asJsonPrimitive.asString)
}

private val gson =
  GsonBuilder()
    .registerTypeAdapter(ByteString::class.java, Base64ByteStringAdapter)
    .registerTypeAdapter(BigInteger::class.java, BigIntegerAdapter)
    .registerTypeAdapter(PatchLevel::class.java, PatchLevelAdapter)
    .create()

internal fun KeyDescription.toJson() = gson.toJson(this)

fun String.toKeyDescription() = gson.fromJson(this, KeyDescription::class.java)
