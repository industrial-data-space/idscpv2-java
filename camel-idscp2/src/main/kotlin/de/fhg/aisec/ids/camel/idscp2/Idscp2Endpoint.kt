/*-
 * ========================LICENSE_START=================================
 * camel-idscp2
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
package de.fhg.aisec.ids.camel.idscp2

import de.fhg.aisec.ids.idscp2.api.configuration.Idscp2Configuration
import de.fhg.aisec.ids.idscp2.defaultdrivers.securechannel.tls13.NativeTlsConfiguration
import org.apache.camel.support.jsse.SSLContextParameters

interface Idscp2Endpoint {

    val supportedRaSuites: String
    val expectedRaSuites: String
    val dapsRaTimeoutDelay: Long
    val remaining: String
    val transportSslContextParameters: SSLContextParameters?
    val dapsSslContextParameters: SSLContextParameters?
    val sslContextParameters: SSLContextParameters?
    var idscp2Configuration: Idscp2Configuration?
    var secureChannelConfigurationBuilder: NativeTlsConfiguration.Builder?
    var secureChannelConfiguration: NativeTlsConfiguration
}
