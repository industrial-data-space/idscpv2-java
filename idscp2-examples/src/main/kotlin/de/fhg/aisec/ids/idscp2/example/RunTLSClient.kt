/*-
 * ========================LICENSE_START=================================
 * idscp2-examples
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
package de.fhg.aisec.ids.idscp2.example

import de.fhg.aisec.ids.idscp2.api.configuration.AttestationConfig
import de.fhg.aisec.ids.idscp2.api.configuration.Idscp2Configuration
import de.fhg.aisec.ids.idscp2.daps.aisecdaps.AisecDapsDriver
import de.fhg.aisec.ids.idscp2.daps.aisecdaps.AisecDapsDriverConfig
import de.fhg.aisec.ids.idscp2.defaultdrivers.remoteattestation.demo.DemoRaProver
import de.fhg.aisec.ids.idscp2.defaultdrivers.remoteattestation.demo.DemoRaVerifier
import de.fhg.aisec.ids.idscp2.defaultdrivers.securechannel.tls13.NativeTlsConfiguration
import de.fhg.aisec.ids.idscp2.keystores.KeyStoreUtil.loadKeyStore
import java.nio.file.Paths
import java.util.Objects

object RunTLSClient {
    @JvmStatic
    fun main(args: Array<String>) {
        val keyStorePath = Paths.get(
            Objects.requireNonNull(
                RunTLSClient::class.java.classLoader
                    .getResource("ssl/client-keystore.p12")
            ).path
        )

        val trustStorePath = Paths.get(
            Objects.requireNonNull(
                RunTLSClient::class.java.classLoader
                    .getResource("ssl/truststore.p12")
            ).path
        )

        val localAttestationConfig = AttestationConfig.Builder()
            .setSupportedRaSuite(arrayOf(DemoRaProver.DEMO_RA_PROVER_ID))
            .setExpectedRaSuite(arrayOf(DemoRaVerifier.DEMO_RA_VERIFIER_ID))
            .setRaTimeoutDelay(300 * 1000L) // 300 seconds
            .build()

        val password = "password".toCharArray()

        // Load certificates from local KeyStore
        val ks = loadKeyStore(keyStorePath, password)

        val dapsDriver = AisecDapsDriver(
            AisecDapsDriverConfig.Builder()
                .setKeyStorePath(keyStorePath)
                .setKeyStorePassword(password)
                .setKeyPassword(password)
                .setKeyAlias("1")
                .setTrustStorePath(trustStorePath)
                .setTrustStorePassword(password)
                .setDapsUrl("https://daps-dev.aisec.fraunhofer.de/v4")
                .loadTransportCertsFromKeystore(ks)
                .build()
        )

        // create idscp2 config
        val settings = Idscp2Configuration.Builder()
            .setAckTimeoutDelay(500) //  500 ms
            .setHandshakeTimeoutDelay(5 * 1000L) // 5 seconds
            .setAttestationConfig(localAttestationConfig)
            .setDapsDriver(dapsDriver)
            .build()

        // create secureChannel config
        val nativeTlsConfiguration = NativeTlsConfiguration.Builder()
            .setKeyStorePath(keyStorePath)
            .setKeyStorePassword(password)
            .setKeyPassword(password)
            .setTrustStorePath(trustStorePath)
            .setTrustStorePassword(password)
            .setCertificateAlias("1.0.1")
            .setHost("tc-core-server")
            .build()

        val initiator = Idscp2ClientInitiator()
        initiator.init(settings, nativeTlsConfiguration)
    }
}
