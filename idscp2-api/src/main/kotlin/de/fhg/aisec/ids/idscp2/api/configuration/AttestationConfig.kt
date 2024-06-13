/*-
 * ========================LICENSE_START=================================
 * idscp2-api
 * %%
 * Copyright (C) 2021 Fraunhofer AISEC
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
package de.fhg.aisec.ids.idscp2.api.configuration

import java.util.Objects

/**
 * Attestation configuration class, containing attestation suite for supported / expected
 * attestation types
 *
 * @author Leon Beckmann (leon.beckmann@aisec.fraunhofer.de)
 */
class AttestationConfig {
    lateinit var supportedAttestationSuite: Array<String>
        private set
    lateinit var expectedAttestationSuite: Array<String>
        private set
    var raTimeoutDelay = DEFAULT_RA_TIMEOUT_DELAY.toInt().toLong() // in ms
        private set

    class Builder {
        private val config = AttestationConfig()

        fun setSupportedRaSuite(suite: Array<String>): Builder {
            config.supportedAttestationSuite = suite
            return this
        }

        fun setExpectedRaSuite(suite: Array<String>): Builder {
            config.expectedAttestationSuite = suite
            return this
        }

        fun setRaTimeoutDelay(delay: Long): Builder {
            config.raTimeoutDelay = delay
            return this
        }

        fun build(): AttestationConfig = config
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other == null || javaClass != other.javaClass) return false
        val that = other as AttestationConfig
        return supportedAttestationSuite.contentEquals(that.supportedAttestationSuite) &&
            expectedAttestationSuite.contentEquals(that.expectedAttestationSuite) &&
            raTimeoutDelay == that.raTimeoutDelay
    }

    override fun hashCode(): Int = Objects.hash(
        supportedAttestationSuite.contentHashCode(),
        expectedAttestationSuite.contentHashCode(),
        raTimeoutDelay
    )

    companion object {
        const val DEFAULT_RA_TIMEOUT_DELAY = "3600000" // in ms: 1 hour
    }
}
