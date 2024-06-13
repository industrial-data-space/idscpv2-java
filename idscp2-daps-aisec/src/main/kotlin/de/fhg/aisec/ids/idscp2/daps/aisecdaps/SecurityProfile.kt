/*-
 * ========================LICENSE_START=================================
 * idscp2-daps-aisec
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
package de.fhg.aisec.ids.idscp2.daps.aisecdaps

enum class SecurityProfile {
    // we use enum comparison, so ensure that INVALID option is the worst and TRUSTED_PLUS is the best
    INVALID,
    BASE,
    TRUSTED,
    TRUSTED_PLUS;

    companion object {
        private const val CONNECTOR_SECURITY_PROFILE_BASE = "idsc:BASE_CONNECTOR_SECURITY_PROFILE"
        private const val CONNECTOR_SECURITY_PROFILE_TRUSTED = "idsc:TRUSTED_CONNECTOR_SECURITY_PROFILE"
        private const val CONNECTOR_SECURITY_PROFILE_TRUSTED_PLUS = "idsc:TRUSTED_CONNECTOR_PLUS_SECURITY_PROFILE"

        fun fromString(s: String): SecurityProfile = when (s) {
            CONNECTOR_SECURITY_PROFILE_BASE -> BASE
            CONNECTOR_SECURITY_PROFILE_TRUSTED -> TRUSTED
            CONNECTOR_SECURITY_PROFILE_TRUSTED_PLUS -> TRUSTED_PLUS
            else -> INVALID
        }
    }
}
