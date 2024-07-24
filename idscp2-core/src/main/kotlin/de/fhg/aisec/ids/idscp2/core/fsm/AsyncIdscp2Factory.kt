/*-
 * ========================LICENSE_START=================================
 * idscp2-core
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
package de.fhg.aisec.ids.idscp2.core.fsm

import de.fhg.aisec.ids.idscp2.api.configuration.Idscp2Configuration
import de.fhg.aisec.ids.idscp2.api.connection.Idscp2Connection
import de.fhg.aisec.ids.idscp2.api.fsm.FSM
import de.fhg.aisec.ids.idscp2.core.securechannel.SecureChannel
import org.slf4j.LoggerFactory
import java.util.UUID
import java.util.concurrent.CompletableFuture

/**
 * An object for initiating IDSCP2 connections for a given secure channel.
 * First the FSM is created and the IDSCP2 handshake is started, on success, the connection is created and the
 * connection future is completed.
 *
 * It ensures that no connection is created when the Idscp2Handshake has failed.
 *
 * @author Leon Beckmann (leon.beckmann@aisec.fraunhofer.de)
 */

object AsyncIdscp2Factory {
    private val LOG = LoggerFactory.getLogger(AsyncIdscp2Factory::class.java)

    fun <CC : Idscp2Connection> initiateIdscp2Connection(
        secureChannel: SecureChannel,
        configuration: Idscp2Configuration,
        connectionFactory: (FSM, String) -> CC,
        connectionFuture: CompletableFuture<CC>
    ): Boolean {
        if (connectionFuture.isCancelled) {
            secureChannel.close()
            return false
        }

        // create the id for the future connection, it is used in the FSM for better logging readability
        val id: String = UUID.randomUUID().toString()

        // create the FSM for the connection
        val fsm = FSMImpl(
            secureChannel,
            configuration.dapsDriver,
            configuration.attestationConfig,
            configuration.ackTimeoutDelay,
            configuration.handshakeTimeoutDelay,
            id,
            connectionFuture
        )

        // register FSM to secure channel, pass peer certificate to FSM
        secureChannel.setFsm(fsm)

        // ForkJoinPool used to exhibit strange deadlocking behavior when used here, reason unknown.
        Thread.ofVirtual().start {
            try {
                if (LOG.isDebugEnabled) {
                    LOG.debug("Asynchronously starting IDSCP2 handshake for connection {}...", id)
                }
                fsm.startIdscpHandshake()

                /*
                 * Create connection and notify connection future, which is hold by the user (client) or by the
                 * secure server (server)
                 */
                if (LOG.isDebugEnabled) {
                    LOG.debug("Handshake successful. Creating IDSCP2 connection {}...", id)
                }
                // create the connection, complete the future and register it to the fsm as listener
                val connection = connectionFactory(fsm, id)
                connectionFuture.complete(connection)

                // close the connection if it was cancelled
                if (connectionFuture.isCancelled) {
                    connection.close()
                }
            } catch (t: Throwable) {
                // idscp2 handshake failed
                LOG.error("Error in IDSCP2 handshake task", t)
                connectionFuture.completeExceptionally(t)
            }
        }
        return true
    }
}
