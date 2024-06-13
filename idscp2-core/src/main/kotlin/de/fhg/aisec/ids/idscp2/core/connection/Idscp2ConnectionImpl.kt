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
package de.fhg.aisec.ids.idscp2.core.connection

import de.fhg.aisec.ids.idscp2.api.connection.Idscp2Connection
import de.fhg.aisec.ids.idscp2.api.connection.Idscp2ConnectionListener
import de.fhg.aisec.ids.idscp2.api.connection.Idscp2MessageListener
import de.fhg.aisec.ids.idscp2.api.drivers.VerifiedDat
import de.fhg.aisec.ids.idscp2.api.error.Idscp2Exception
import de.fhg.aisec.ids.idscp2.api.error.Idscp2NotConnectedException
import de.fhg.aisec.ids.idscp2.api.error.Idscp2TimeoutException
import de.fhg.aisec.ids.idscp2.api.error.Idscp2WouldBlockException
import de.fhg.aisec.ids.idscp2.api.fsm.FSM
import de.fhg.aisec.ids.idscp2.api.fsm.FsmResultCode
import de.fhg.aisec.ids.idscp2.core.forEachResilient
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineExceptionHandler
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import org.slf4j.LoggerFactory

/**
 * The IDSCP2 Connection class holds connections between connectors
 *
 * @author Leon Beckmann (leon.beckmann@aisec.fraunhofer.de)
 * @author Michael Lux (michael.lux@aisec.fraunhofer.de)
 */
class Idscp2ConnectionImpl(private val fsm: FSM, override val id: String) : Idscp2Connection {

    private val connectionListeners = LinkedHashSet<Idscp2ConnectionListener>()
    private val messageListeners = LinkedHashSet<Idscp2MessageListener>()
    private val connectionDeferred = CompletableDeferred<Unit>()
    private var closed = false
    private var closeMutex = Mutex()

    override fun unlockMessaging() {
        connectionDeferred.complete(Unit)
    }

    /**
     * Close the idscp connection
     */
    override fun close() {
        if (LOG.isInfoEnabled) {
            LOG.info("Closing connection {}...", id)
        }

        // we have to unlock connection listeners to avoid deadlocks with onError()
        // which would block the closedLock until connection listeners are available
        // to avoid error loss
        connectionDeferred.complete(Unit)

        /*
         * When closing the connection, also the secure channel and its sockets
         * will be closed. This could lead to errors at the socket listener thread, which
         * should not be passed to the user again. Therefore, we have to remember that
         * the connection has been closed and check this at the onError function.
         *
         * Since the success of the closure depends on weather the connection has been started
         * or not, we should synchronize this sequence to avoid race conditions on the error
         * parsing, as well as avoiding error message loss.
         */
        runBlocking {
            closeMutex.withLock {
                when (val res = fsm.closeConnection()) {
                    FsmResultCode.FSM_NOT_STARTED -> {
                        // not closed
                        throw Idscp2Exception("Handshake not started: " + res.value)
                    }
                    else -> {
                        // closed
                        closed = true
                        if (LOG.isDebugEnabled) {
                            LOG.debug("IDSCP2 connection {} closed", id)
                        }
                    }
                }
            }
        }
    }

    /**
     * Send data to the peer IDSCP2 connector
     */

    override fun nonBlockingSend(msg: ByteArray) {
        LOG.debug("Sending data (non-blocking) via connection {}...", id)

        when (val res = fsm.send(msg)) {
            FsmResultCode.OK -> return
            FsmResultCode.WOULD_BLOCK -> throw Idscp2WouldBlockException("Idscp2 connection still waiting for ack")
            FsmResultCode.IO_ERROR, FsmResultCode.FSM_LOCKED ->
                throw Idscp2Exception("Connection aborted: " + res.value)
            FsmResultCode.NOT_CONNECTED ->
                throw Idscp2NotConnectedException("Idscp2 connection temporarily not available")
            else -> throw Idscp2Exception("Idscp2 error occurred while sending data: " + res.value)
        }
    }

    override fun blockingSend(msg: ByteArray, timeout: Long, retryInterval: Long) {
        LOG.debug("Sending data (blocking) via connection {}...", id)

        val start = System.currentTimeMillis()

        while (true) {
            val now = System.currentTimeMillis()
            if (now >= start + timeout) {
                throw Idscp2TimeoutException("Idscp2 connection temporarily not available")
            }

            when (val res = fsm.send(msg)) {
                FsmResultCode.OK -> return
                FsmResultCode.WOULD_BLOCK -> {
                    // wait and repeat, fsm currently in wait_for_ack state
                    if (retryInterval > 0) {
                        Thread.sleep(retryInterval)
                    }
                    continue
                }
                FsmResultCode.IO_ERROR, FsmResultCode.FSM_LOCKED ->
                    throw Idscp2Exception("Connection aborted: " + res.value)
                FsmResultCode.NOT_CONNECTED ->
                    throw Idscp2NotConnectedException("Idscp2 connection temporarily not available")
                else -> throw Idscp2Exception("Idscp2 error occurred while sending data: " + res.value)
            }
        }
    }

    override fun repeatRa() {
        LOG.info("Repeat RA for connection {}...", id)

        // match result
        when (val res = fsm.repeatRa()) {
            FsmResultCode.OK -> return
            FsmResultCode.FSM_LOCKED, FsmResultCode.IO_ERROR ->
                throw Idscp2Exception("Connection aborted: " + res.value)
            FsmResultCode.RA_ERROR ->
                throw Idscp2Exception("RA action failed: " + res.value)
            else -> throw Idscp2Exception("Error occurred: " + res.value)
        }
    }

    override fun onMessage(msg: ByteArray) {
        ioScope.launch {
            LOG.trace("Async message processing started...")
            // When unlock is called, although not synchronized, this will eventually stop blocking.
            connectionDeferred.await()
            synchronized(messageListeners) {
                LOG.debug("Received new IDSCP Message, notifying {} listeners", messageListeners.size)
                messageListeners.forEachResilient(LOG) { l: Idscp2MessageListener ->
                    l.onMessage(this@Idscp2ConnectionImpl, msg)
                }
            }
        }
    }

    override fun onError(t: Throwable) {
        ioScope.launch {
            closeMutex.withLock {
                // Check if connection has already been closed, then we do not pass errors to the user
                if (!closed) {
                    connectionDeferred.await()
                    // Iterate over copy to prevent ConcurrentModificationExceptions from changes during iteration.
                    val copyList: List<Idscp2ConnectionListener>
                    synchronized(connectionListeners) {
                        copyList = ArrayList(connectionListeners)
                    }
                    copyList.forEachResilient(LOG) { l: Idscp2ConnectionListener -> l.onError(t) }
                }
            }
        }
    }

    override fun onClose() {
        ioScope.launch {
            connectionDeferred.await()
            if (LOG.isInfoEnabled) {
                LOG.info("Connection with id {} is closing, notify listeners...", id)
            }
            // Iterate over copy to prevent ConcurrentModificationExceptions from changes during iteration.
            val copyList: List<Idscp2ConnectionListener>
            synchronized(connectionListeners) {
                copyList = ArrayList(connectionListeners)
            }
            copyList.forEachResilient(LOG) { l: Idscp2ConnectionListener -> l.onClose() }
        }
    }

    override fun remotePeer(): String = fsm.remotePeer

    /**
     * Check if the idscp connection is currently established
     *
     * @return Connection established state
     */
    override val isConnected: Boolean
        get() = fsm.isConnected

    override val isClosed: Boolean
        get() = fsm.isFsmLocked

    override val localDat: ByteArray
        get() = fsm.localDat

    override val peerDat: VerifiedDat
        get() = fsm.peerDat

    override fun addConnectionListener(listener: Idscp2ConnectionListener) {
        synchronized(connectionListeners) {
            connectionListeners.add(listener)
        }
    }

    override fun removeConnectionListener(listener: Idscp2ConnectionListener): Boolean {
        synchronized(connectionListeners) {
            return connectionListeners.remove(listener)
        }
    }

    override fun addMessageListener(listener: Idscp2MessageListener) {
        synchronized(messageListeners) {
            messageListeners.add(listener)
        }
    }

    override fun removeMessageListener(listener: Idscp2MessageListener): Boolean {
        synchronized(messageListeners) {
            return messageListeners.remove(listener)
        }
    }

    override fun toString(): String = "Idscp2ConnectionImpl($id)"

    companion object {
        private val LOG = LoggerFactory.getLogger(Idscp2ConnectionImpl::class.java)
        private val ioScope = CoroutineScope(
            Dispatchers.IO + SupervisorJob() + CoroutineExceptionHandler { _, throwable ->
                LOG.error("Error in async connection code", throwable)
            }
        )
    }
}
