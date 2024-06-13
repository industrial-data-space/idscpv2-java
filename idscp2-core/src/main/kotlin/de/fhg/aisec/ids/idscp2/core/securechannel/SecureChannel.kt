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
package de.fhg.aisec.ids.idscp2.core.securechannel

import de.fhg.aisec.ids.idscp2.api.drivers.SecureChannelEndpoint
import de.fhg.aisec.ids.idscp2.api.fsm.ScFsmListener
import de.fhg.aisec.ids.idscp2.api.securechannel.SecureChannelListener
import de.fhg.aisec.ids.idscp2.core.FastLatch
import org.slf4j.LoggerFactory
import java.security.cert.X509Certificate

/**
 * A secureChannel which is the secure underlying basis of the IDSCP2 protocol,
 * that implements a secureChannelListener
 *
 * @author Leon Beckmann (leon.beckmann@aisec.fraunhofer.de)
 */
class SecureChannel(private val endpoint: SecureChannelEndpoint, private val peerCertificate: X509Certificate) :
    SecureChannelListener {
    // This latch is used to block Threads performing on[Message/Error/Close] calls until fsm is available
    private val fsmLatch = FastLatch()
    private lateinit var fsm: ScFsmListener

    /*
     * close the secure channel forever
     */
    fun close() {
        if (LOG.isTraceEnabled) {
            LOG.trace("Close secure channel")
        }
        endpoint.close()
    }

    fun remotePeer(): String = endpoint.remotePeer()

    /*
     * Send data via the secure channel endpoint to the peer connector
     *
     * return true if the data has been sent successfully, else false
     */
    fun send(msg: ByteArray): Boolean {
        if (LOG.isTraceEnabled) {
            LOG.trace("Send message via secure channel")
        }
        return endpoint.send(msg)
    }

    override fun onMessage(data: ByteArray) {
        if (LOG.isTraceEnabled) {
            LOG.trace("New raw data has been received via the secure channel")
        }
        fsmLatch.await()
        fsm.onMessage(data)
    }

    override fun onError(t: Throwable) {
        if (LOG.isTraceEnabled) {
            LOG.debug("Error occurred in secure channel")
        }
        fsmLatch.await()
        // Tell fsm an error occurred in secure channel
        fsm.onError(t)
    }

    override fun onClose() {
        if (LOG.isTraceEnabled) {
            LOG.debug("Secure channel received EOF")
        }
        fsmLatch.await()
        // Tell fsm secure channel received EOF
        fsm.onClose()
    }

    val isConnected: Boolean
        get() = endpoint.isConnected

    /*
     * set the corresponding finite state machine, pass peer certificate to FSM
     */
    fun setFsm(fsm: ScFsmListener) {
        LOG.trace("Bind FSM to secure channel and pass peer certificate to FSM")
        this.fsm = fsm
        fsm.setPeerX509Certificate(peerCertificate)
        fsmLatch.unlock()
    }

    companion object {
        private val LOG = LoggerFactory.getLogger(SecureChannel::class.java)
    }
}
