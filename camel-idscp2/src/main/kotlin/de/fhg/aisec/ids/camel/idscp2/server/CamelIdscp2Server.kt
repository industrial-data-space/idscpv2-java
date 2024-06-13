/*-
 * ========================LICENSE_START=================================
 * camel-idscp2
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
package de.fhg.aisec.ids.camel.idscp2.server

import de.fhg.aisec.ids.camel.idscp2.ListenerManager
import de.fhg.aisec.ids.idscp2.api.Idscp2EndpointListener
import de.fhg.aisec.ids.idscp2.api.configuration.Idscp2Configuration
import de.fhg.aisec.ids.idscp2.applayer.AppLayerConnection
import de.fhg.aisec.ids.idscp2.core.forEachResilient
import de.fhg.aisec.ids.idscp2.core.server.Idscp2Server
import de.fhg.aisec.ids.idscp2.core.server.Idscp2ServerFactory
import de.fhg.aisec.ids.idscp2.defaultdrivers.securechannel.tls13.NativeTLSDriver
import de.fhg.aisec.ids.idscp2.defaultdrivers.securechannel.tls13.NativeTlsConfiguration
import org.slf4j.LoggerFactory

class CamelIdscp2Server(
    serverConfiguration: Idscp2Configuration,
    nativeTlsConfiguration: NativeTlsConfiguration,
    private val useIdsMessages: Boolean
) : Idscp2EndpointListener<AppLayerConnection> {
    private val server: Idscp2Server<AppLayerConnection>
    private val listeners = LinkedHashSet<Idscp2EndpointListener<AppLayerConnection>>()

    init {
        val serverFactory = Idscp2ServerFactory(
            ::AppLayerConnection,
            this,
            serverConfiguration,
            NativeTLSDriver(),
            nativeTlsConfiguration
        )
        server = serverFactory.listen()
    }

    override fun onConnection(connection: AppLayerConnection) {
        if (useIdsMessages) {
            connection.addIdsMessageListener { c, header, _, _ ->
                header?.let {
                    ListenerManager.publishTransferContractEvent(c, it.transferContract)
                }
            }
        }
        synchronized(listeners) {
            listeners.forEachResilient(log) { it.onConnection(connection) }
        }
    }

    fun addEndpointListener(listener: Idscp2EndpointListener<AppLayerConnection>) {
        synchronized(listeners) {
            listeners += listener
        }
    }

    fun removeEndpointListener(listener: Idscp2EndpointListener<AppLayerConnection>) {
        synchronized(listeners) {
            listeners -= listener
        }
    }

    val allConnections: Collection<AppLayerConnection> = server.allConnections

    fun terminate() {
        server.terminate()
    }

    companion object {
        private val log = LoggerFactory.getLogger(CamelIdscp2Server::class.java)
    }
}
