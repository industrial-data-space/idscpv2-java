/*-
 * ========================LICENSE_START=================================
 * idscp2-api
 * %%
 * Copyright (C) 2023 Fraunhofer AISEC
 * %%
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 * =========================LICENSE_END==================================
 */
package de.fhg.aisec.ids.idscp2.api

import java.security.MessageDigest
import java.security.cert.Certificate

/**
 * Lookup table for encodeHexString()
 */
private val hexLookup = (0..255).map {
    it.toString(radix = 16).padStart(2, '0')
}

/**
 * Encode a byte array to a hex string
 * @return Hexadecimal representation of the given bytes
 */
fun ByteArray.toHexString(delimiter: CharSequence = ""): String =
    this.joinToString(delimiter) { hexLookup[java.lang.Byte.toUnsignedInt(it)] }

val Certificate.sha256Fingerprint
    get() = MessageDigest.getInstance("SHA-256").digest(encoded).toHexString()
