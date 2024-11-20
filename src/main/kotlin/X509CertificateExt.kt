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

package com.android.keyattestation.verifier

import java.io.InputStream
import java.security.cert.CertificateException
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate

private val certificateFactory = CertificateFactory.getInstance("X.509")

/** Returns an [X509Certificate] from a [String]. */
fun String.asX509Certificate() = this.byteInputStream().asX509Certificate()

@Throws(CertificateException::class)
fun InputStream.asX509Certificate() =
  certificateFactory.generateCertificate(this) as X509Certificate

/**
 * Returns the Android Key Attestation extension.
 *
 * @return the DER-encoded OCTET string containing the KeyDescription sequence or null if the
 *   extension is not present in the certificate.
 */
fun X509Certificate.keyDescription() = KeyDescription.parseFrom(this)
