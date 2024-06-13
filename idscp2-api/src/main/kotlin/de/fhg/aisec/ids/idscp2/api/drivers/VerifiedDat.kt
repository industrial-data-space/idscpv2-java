/*-
 * ========================LICENSE_START=================================
 * idscp2-api
 * %%
 * Copyright (C) 2022 Fraunhofer AISEC
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
package de.fhg.aisec.ids.idscp2.api.drivers

data class VerifiedDat(val bytes: ByteArray, val identity: String, val expirationTime: Long) {
    fun remainingValidity(renewalThreshold: Float): Long =
        ((expirationTime - (System.currentTimeMillis() / 1000)) * renewalThreshold).toLong()

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as VerifiedDat

        if (!bytes.contentEquals(other.bytes)) return false
        if (identity != other.identity) return false
        if (expirationTime != other.expirationTime) return false

        return true
    }

    override fun hashCode(): Int {
        var result = bytes.contentHashCode()
        result = 31 * result + identity.hashCode()
        result = 31 * result + expirationTime.hashCode()
        return result
    }
}
