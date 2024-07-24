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

import com.google.protobuf.InvalidProtocolBufferException
import de.fhg.aisec.ids.idscp2.api.configuration.AttestationConfig
import de.fhg.aisec.ids.idscp2.api.connection.Idscp2Connection
import de.fhg.aisec.ids.idscp2.api.drivers.DapsDriver
import de.fhg.aisec.ids.idscp2.api.drivers.RaProverDriver
import de.fhg.aisec.ids.idscp2.api.drivers.RaVerifierDriver
import de.fhg.aisec.ids.idscp2.api.drivers.VerifiedDat
import de.fhg.aisec.ids.idscp2.api.error.Idscp2HandshakeException
import de.fhg.aisec.ids.idscp2.api.fsm.Event
import de.fhg.aisec.ids.idscp2.api.fsm.FSM
import de.fhg.aisec.ids.idscp2.api.fsm.FsmResultCode
import de.fhg.aisec.ids.idscp2.api.fsm.FsmState
import de.fhg.aisec.ids.idscp2.api.fsm.InternalControlMessage
import de.fhg.aisec.ids.idscp2.api.fsm.RaProverFsmListener
import de.fhg.aisec.ids.idscp2.api.fsm.RaVerifierFsmListener
import de.fhg.aisec.ids.idscp2.api.fsm.ScFsmListener
import de.fhg.aisec.ids.idscp2.api.fsm.State
import de.fhg.aisec.ids.idscp2.api.raregistry.RaProverDriverRegistry
import de.fhg.aisec.ids.idscp2.api.raregistry.RaVerifierDriverRegistry
import de.fhg.aisec.ids.idscp2.core.messages.Idscp2MessageHelper
import de.fhg.aisec.ids.idscp2.core.securechannel.SecureChannel
import de.fhg.aisec.ids.idscp2.messages.IDSCP2.IdscpAck
import de.fhg.aisec.ids.idscp2.messages.IDSCP2.IdscpData
import de.fhg.aisec.ids.idscp2.messages.IDSCP2.IdscpMessage
import org.slf4j.LoggerFactory
import java.security.cert.X509Certificate
import java.util.concurrent.CompletableFuture
import java.util.concurrent.locks.ReentrantLock
import kotlin.concurrent.withLock

/**
 * The finite state machine FSM of the IDSCP2 protocol
 *
 *
 * Manages IDSCP2 Handshake, Re-Attestation, DAT-ReRequest and DAT-Re-Validation. Delivers
 * Internal Control Messages and Idscp2Messages to the target receivers,
 * creates and manages the states and its transitions and implements security restriction to protect
 * the protocol against misuse and faulty, insecure or evil driver implementations.
 *
 * @author Leon Beckmann (leon.beckmann@aisec.fraunhofer.de)
 */
class FSMImpl<CC : Idscp2Connection>(
    private val secureChannel: SecureChannel,
    private val dapsDriver: DapsDriver,
    attestationConfig: AttestationConfig,
    ackTimeoutDelay: Long,
    handshakeTimeoutDelay: Long,
    private val connectionId: String,
    private val connection: CompletableFuture<CC>
) : RaProverFsmListener,
    RaVerifierFsmListener,
    ScFsmListener,
    FSM {
    /*  -----------   IDSCP2 Protocol States   ---------- */
    private val states = HashMap<FsmState, State>()

    private var currentState: State

    /*  ----------------   end of states   --------------- */
    override var raProverDriver: RaProverDriver<*>? = null
        private set
    override var raVerifierDriver: RaVerifierDriver<*>? = null
        private set

    /**
     * RA Driver Thread ID to identify the driver threads and check if messages are provided by
     * the current active driver or by any old driver, whose lifetime is already over
     *
     * Only one driver can be valid at a time
     */
    private var currentRaProverId: String? = // avoid messages from old prover drivers
        null
    private var currentRaVerifierId: String? = // avoid messages from old verifier drivers
        null

    /**
     * RA Mechanisms, calculated during handshake in WAIT_FOR_HELLO_STATE
     */
    private lateinit var proverMechanism: String // RA prover mechanism
    private lateinit var verifierMechanism: String // RA Verifier mechanism

    /**
     * A FIFO-fair synchronization lock for the finite state machine
     */
    private val fsmIsBusy = ReentrantLock(true)

    /**
     * A condition to ensure no idscp messages can be provided by the secure channel to the fsm
     * before the handshake was started
     */
    private val onMessageBlock = fsmIsBusy.newCondition()

    /**
     * A condition for the idscp2 handshake to wait until the handshake was successful and the
     * connection is established or the handshake failed and the fsm is locked forever
     */
    private val idscpHandshakeLock = fsmIsBusy.newCondition()
    private var handshakeResultAvailable = false

    /**
     * Check if FSM is closed forever
     */
    private var isLocked = false

    /**
     * Check if AckFlag is set
     */
    override var ackFlag = false
        set(value) {
            field = value
            if (!value) {
                this.bufferedIdscpData = null
            }
        }
    private var bufferedIdscpData: IdscpMessage? = null

    /**
     * Alternating Bit
     */
    private var expectedAlternatingBit = AlternatingBit()
    private var nextSendAlternatingBit = AlternatingBit()

    /* ---------------------- Timers ---------------------- */
    private val datTimer: DynamicTimer
    private val raTimer: StaticTimer
    private val handshakeTimer: StaticTimer
    private val proverHandshakeTimer: StaticTimer
    private val verifierHandshakeTimer: StaticTimer
    private val ackTimer: StaticTimer

    /**
     * Peer certificate
     */
    private lateinit var peerCertificate: X509Certificate

    /**
     * Local peer dynamic attribute token
     */
    override var localDat: ByteArray = "INVALID_DAT".toByteArray()

    /**
     * Remote peer dynamic attribute token
     */
    override var peerDat: VerifiedDat = VerifiedDat("INVALID_DAT".toByteArray(), "INVALID", 0)

    override val remotePeer: String
        get() = secureChannel.remotePeer()

    private fun checkForFsmCycles() {
        // check if current thread holds already the fsm lock, then we have a circle
        // this runs into an issue: onControlMessage must be called only from other threads!
        // if the current thread currently stuck within a fsm transition it will trigger another
        // transition on the old state and undefined behaviour occurred
        //
        // The IDSCP2 core and default driver will not run into this issue. It's a protection for
        // avoiding incorrect usage of the IDSCP2 library from further driver implementations
        //
        // Example:
        // Thread A stuck within a transition t1 that calls a function that calls
        // onControlMessage(InternalError). Then the error is handled in the current
        // state and the fsm will switch into state STATE_CLOSED and close all resources.
        //
        // Afterwards, the thread will continue the old transition t1 that might use some of the
        // closed resources and switch in a non-closed STATE, e.g. STATE_ESTABLISHED.
        // So our fsm would be broken and the behaviour is undefined and could leak security
        // vulnerabilities
        //
        if (fsmIsBusy.isHeldByCurrentThread) {
            val e = RuntimeException(
                "The current thread holds the fsm lock already. " +
                    "A circle might occur that could lead to undefined behaviour within the fsm"
            )
            // Log exception before throwing, since some threads swallow the exception without any notification
            LOG.error(e.message, e)
            throw e
        }
    }

    /**
     * Get a new IDSCP2 Message from the secure channel and provide it as an event to the fsm
     *
     * The checkForFsmCycles method first checks for risky thread cycles that occur by incorrect
     * driver implementations
     */
    override fun onMessage(data: ByteArray) {
        // check for incorrect usage
        checkForFsmCycles()

        // parse message and create new IDSCP Message event, then pass it to current state and
        // update new state
        val message: IdscpMessage = try {
            IdscpMessage.parseFrom(data)
        } catch (e: InvalidProtocolBufferException) {
            LOG.warn("Cannot parse raw data into IdscpMessage {}", data)
            return
        }
        val event = Event(message)
        // must wait when fsm is in state STATE_CLOSED --> wait() will be notified when fsm is
        // leaving STATE_CLOSED
        fsmIsBusy.withLock {
            while (currentState == states[FsmState.STATE_CLOSED]) {
                if (isLocked) {
                    return
                }
                try {
                    LOG.trace("Awaiting onMessageBlock...")
                    onMessageBlock.await() // while waiting the fsmIsBusy lock is free for other threads
                } catch (e: InterruptedException) {
                    Thread.currentThread().interrupt()
                }
            }
            if (LOG.isTraceEnabled) {
                LOG.trace("Feed message event {} to FSM...", event)
            }
            feedEvent(event)
        }
    }

    /**
     * An internal control message (ICM) occurred, provide it to the fsm as an event
     */
    private fun onControlMessage(controlMessage: InternalControlMessage) {
        // create Internal Control Message Event and pass it to current state and update new state
        val e = Event(controlMessage)
        fsmIsBusy.withLock {
            feedEvent(e)
        }
    }

    override fun onRaProverMessage(controlMessage: InternalControlMessage, raMessage: ByteArray) {
        processRaProverEvent(Event(controlMessage, Idscp2MessageHelper.createIdscpRaProverMessage(raMessage)))
    }

    override fun onRaProverMessage(controlMessage: InternalControlMessage) {
        processRaProverEvent(Event(controlMessage))
    }

    /**
     * API for RaProver to provide Prover Messages to the fsm
     *
     * The checkForFsmCycles method first checks for risky thread cycles that occur by incorrect
     * driver implementations
     *
     * Afterwards the fsm lock is requested
     *
     * When the RaProverThread does not match the active prover tread id, the event will be
     * ignored, else the event is provided to the fsm
     */
    private fun processRaProverEvent(e: Event) {
        // check for incorrect usage
        checkForFsmCycles()
        fsmIsBusy.withLock {
            @Suppress("DEPRECATION")
            if (Thread.currentThread().id.toString() == currentRaProverId) {
                feedEvent(e)
            } else {
                LOG.warn("An old or unknown Thread (${Thread.currentThread().id}) calls onRaProverMessage()")
            }
        }
    }

    override fun onRaVerifierMessage(controlMessage: InternalControlMessage, raMessage: ByteArray) {
        processRaVerifierEvent(Event(controlMessage, Idscp2MessageHelper.createIdscpRaVerifierMessage(raMessage)))
    }

    override fun onRaVerifierMessage(controlMessage: InternalControlMessage) {
        processRaVerifierEvent(Event(controlMessage))
    }

    override val remotePeerDat: VerifiedDat
        get() = peerDat

    /**
     * API for RaVerifier to provide Verifier Messages to the fsm
     *
     * The checkForFsmCycles method first checks for risky thread cycles that occur by incorrect
     * driver implementations
     *
     * Afterwards the fsm lock is requested
     *
     * When the RaVerifierDriver does not match the active verifier thread id, the event will be
     * ignored, else the event is provided to the fsm
     */
    private fun processRaVerifierEvent(e: Event) {
        // check for incorrect usage
        checkForFsmCycles()
        fsmIsBusy.withLock {
            @Suppress("DEPRECATION")
            if (Thread.currentThread().id.toString() == currentRaVerifierId) {
                feedEvent(e)
            } else {
                LOG.warn("An old or unknown Thread (${Thread.currentThread().id}) calls onRaVerifierMessage()")
            }
        }
    }

    private fun onUpperEvent(event: Event): FsmResultCode {
        // check for incorrect usage
        checkForFsmCycles()
        fsmIsBusy.withLock {
            return feedEvent(event)
        }
    }

    /**
     * Feed the event to the current state and execute the runEntry method if the state has changed
     *
     * @return FsmResultCode, the result of the success of the triggered transition
     */
    private fun feedEvent(event: Event): FsmResultCode {
        val prevState = currentState
        val result = currentState.feedEvent(event)
        currentState = result.nextState
        if (prevState != currentState) {
            currentState.runEntryCode(this)
        }
        return result.code
    }

    /**
     * API to terminate the idscp connection by the user
     *
     * The checkForFsmCycles method first checks for risky thread cycles that occur by incorrect
     * driver implementations
     */
    override fun closeConnection(): FsmResultCode {
        // check for incorrect usage
        if (LOG.isTraceEnabled) {
            LOG.trace("Sending stop message to connection peer...")
        }
        return onUpperEvent(Event(InternalControlMessage.IDSCP_STOP))
    }

    /**
     * API for the user to start the IDSCP2 handshake
     *
     * The checkForFsmCycles method first checks for risky thread cycles that occur by incorrect
     * driver implementations
     */
    @Throws(Idscp2HandshakeException::class)
    fun startIdscpHandshake() {
        // check for incorrect usage
        checkForFsmCycles()
        try {
            fsmIsBusy.withLock {
                if (currentState == states[FsmState.STATE_CLOSED]) {
                    if (isLocked) {
                        throw Idscp2HandshakeException("FSM is in a final closed state forever")
                    }

                    // trigger handshake init
                    LOG.trace("Sending START_IDSCP_HANDSHAKE message...")
                    onControlMessage(InternalControlMessage.START_IDSCP_HANDSHAKE)

                    // wait until handshake was successful or failed
                    while (!handshakeResultAvailable) {
                        idscpHandshakeLock.await()
                    }

                    // check if not  connected and locked forever, then the handshake has failed
                    if (!isConnected && isLocked) {
                        // handshake failed, throw exception
                        throw Idscp2HandshakeException("Handshake failed")
                    }
                } else {
                    throw Idscp2HandshakeException("Handshake has already been started")
                }
            }
        } catch (e: InterruptedException) {
            throw Idscp2HandshakeException("Handshake failed because thread was interrupted")
        }
    }

    /**
     * Send idscp data from the fsm via the secure channel to the peer
     */
    override fun sendFromFSM(message: IdscpMessage): Boolean {
        // send messages from fsm
        return try {
            secureChannel.send(message.toByteArray())
        } catch (e: Exception) {
            // catch secure channel exception within an FSM transition to avoid transition cancellation
            LOG.error("Exception occurred during sending data via the secure channel.", e)
            false
        }
    }

    /**
     * Provide an Internal Control Message to the FSM
     *
     * The checkForFsmCycles method first checks for risky thread cycles that occur by incorrect
     * driver implementations
     */
    override fun onError(t: Throwable) {
        // Broadcast the error to the respective listeners when the fsm is not yet locked
        if (!isFsmLocked) {
            connection.thenAccept { it.onError(t) }
        }

        // Check for incorrect usage
        checkForFsmCycles()
        onControlMessage(InternalControlMessage.ERROR)
    }

    /**
     * Provide an Internal Control Message to the FSM, caused by a secure channel closure
     *
     * The checkForFsmCycles method first checks for risky thread cycles that occur by incorrect
     * driver implementations
     */
    override fun onClose() {
        onUpperEvent(Event(InternalControlMessage.IDSCP_STOP))
    }

    /**
     * Set the peer Certificate from the secure channel and pass it to the DAPS driver
     */
    override fun setPeerX509Certificate(certificate: X509Certificate) {
        this.peerCertificate = certificate
    }

    override val remotePeerCertificate: X509Certificate
        get() = this.peerCertificate

    /**
     * Send idscp message from the User via the secure channel
     */
    override fun send(msg: ByteArray?): FsmResultCode {
        val idscpMessage = Idscp2MessageHelper.createIdscpDataMessage(msg)
        return onUpperEvent(Event(InternalControlMessage.SEND_DATA, idscpMessage))
    }

    /**
     * Repeat RA Verification if remote peer, triggered by User
     */
    override fun repeatRa(): FsmResultCode = onUpperEvent(Event(InternalControlMessage.REPEAT_RA))

    /**
     * Get local Dat
     */
    override val dynamicAttributeToken: ByteArray
        // Get token from DAPS driver, update local token and return it
        get() = try {
            dapsDriver.token.also { localDat = it }
        } catch (e: Exception) {
            LOG.error("Exception occurred during requesting DAT from DAPS:", e)
            "INVALID_DAT".toByteArray()
        }

    /**
     * Check if FSM is in STATE ESTABLISHED
     */
    override val isConnected: Boolean
        get() = currentState == states[FsmState.STATE_ESTABLISHED] ||
            currentState == states[FsmState.STATE_WAIT_FOR_ACK]

    /**
     * Notify handshake lock about result
     */
    override fun notifyHandshakeCompleteLock() {
        fsmIsBusy.withLock {
            handshakeResultAvailable = true
            idscpHandshakeLock.signal()
        }
    }

    /**
     * Calculate the RaProver mechanism
     *
     * The remote peer decides about its verifier mechanism, so we have to prefer remoteExpected list
     *
     * @return The String of the cipher or null if no match was found
     */
    override fun getRaProverMechanism(
        localSupportedProver: Array<String>,
        remoteExpectedVerifier: Array<String>
    ): String? {
        if (localSupportedProver.isEmpty()) {
            LOG.warn("Got empty RA localSupportedProver suite")
            return null
        }

        if (remoteExpectedVerifier.isEmpty()) {
            LOG.warn("Got empty RA remoteExpectedVerifier suite")
            return null
        }

        if (LOG.isTraceEnabled) {
            LOG.trace(
                "Calculate RA prover mechanism for given local provers: {} " +
                    "and remote verifiers: {}",
                localSupportedProver.contentToString(),
                remoteExpectedVerifier.contentToString()
            )
        }

        val match = matchRaMechanisms(remoteExpectedVerifier, localSupportedProver.toHashSet())
        if (LOG.isDebugEnabled) {
            LOG.debug("RA prover mechanism: '{}'", match)
        }
        return match
    }

    /**
     * Calculate the RaVerifier mechanism
     *
     * We have to decide our verifier mechanism, so we have to prefer localExpected list
     *
     * @return The String of the cipher or null if no match was found
     */
    override fun getRaVerifierMechanism(
        localExpectedVerifier: Array<String>,
        remoteSupportedProver: Array<String>
    ): String? {
        if (localExpectedVerifier.isEmpty()) {
            LOG.warn("Got empty RA localExpectedVerifier suite")
            return null
        }

        if (remoteSupportedProver.isEmpty()) {
            LOG.warn("Got empty RA remoteSupportedProver suite")
            return null
        }

        if (LOG.isTraceEnabled) {
            LOG.trace(
                "Calculate RA verifier mechanism for given local verifiers: {} " +
                    "and remote provers: {}",
                localExpectedVerifier.contentToString(),
                remoteSupportedProver.contentToString()
            )
        }

        val match = matchRaMechanisms(localExpectedVerifier, remoteSupportedProver.toHashSet())
        if (LOG.isDebugEnabled) {
            LOG.debug("Selected RA verifier mechanism: '{}'", match)
        }
        return match
    }

    private fun matchRaMechanisms(primary: Array<String>, secondary: Set<String>): String? {
        for (p in primary) {
            if (p in secondary) {
                return p
            }
        }
        // no match
        return null
    }

    /**
     * Stop current RaVerifier if active and start the RaVerifier from the
     * RaVerifierDriver Registry that matches the verifier mechanism
     *
     * @return false if no match was found
     */
    override fun restartRaVerifierDriver(): Boolean {
        // assume verifier mechanism is set
        stopRaVerifierDriver()
        raVerifierDriver = RaVerifierDriverRegistry.startRaVerifierDriver(verifierMechanism, this)
        return raVerifierDriver?.let {
            // safe the thread ID
            @Suppress("DEPRECATION")
            currentRaVerifierId = it.id.toString()
            if (LOG.isTraceEnabled) {
                LOG.trace("Start verifier_handshake timeout")
            }
            verifierHandshakeTimer.resetTimeout()
            true
        } ?: run {
            LOG.error("Cannot create instance of RA_VERIFIER_DRIVER")
            currentRaVerifierId = ""
            false
        }
    }

    /**
     * Terminate the RaVerifierDriver
     */
    override fun stopRaVerifierDriver() {
        verifierHandshakeTimer.cancelTimeout()
        raVerifierDriver?.let {
            if (it.isAlive) {
                it.interrupt()
                // run in fire-and-forget manner to avoid cycles caused by protocol misuse
                Thread.startVirtualThread { it.terminate() }
            }
        }
    }

    /**
     * Stop current RaProver if active and start the RaProver from the
     * RaProverDriver Registry that matches the prover mechanism
     *
     * @return false if no match was found
     */
    override fun restartRaProverDriver(): Boolean {
        // assume prover mechanism is set
        stopRaProverDriver()
        raProverDriver = RaProverDriverRegistry.startRaProverDriver(proverMechanism, this)
        return raProverDriver?.let {
            // Save the thread ID
            @Suppress("DEPRECATION")
            currentRaProverId = it.id.toString()
            if (LOG.isTraceEnabled) {
                LOG.trace("Start prover_handshake timeout")
            }
            proverHandshakeTimer.resetTimeout()
            true
        } ?: run {
            LOG.error("Cannot create instance of RA_PROVER_DRIVER")
            currentRaProverId = ""
            false
        }
    }

    /**
     * Terminate the RaProverDriver
     */
    private fun stopRaProverDriver() {
        proverHandshakeTimer.cancelTimeout()
        raProverDriver?.let {
            if (it.isAlive) {
                // Run in fire-and-forget manner to avoid cycles caused by protocol misuse
                Thread.startVirtualThread { it.terminate() }
            }
        }
    }

    /**
     * Lock the fsm forever, terminate the timers and drivers, close the secure channel
     * and notify handshake lock if necessary
     */
    override fun shutdownFsm() {
        if (LOG.isTraceEnabled) {
            LOG.trace("Shutting down FSM of connection {}...", connectionId)
            LOG.trace("Running close handlers of connection {}...", connectionId)
        }

        if (LOG.isTraceEnabled) {
            LOG.trace("Mark FSM as terminated...")
        }
        isLocked = true

        // run in fire-and-forget manner to avoid cycles caused by protocol misuse
        Thread.startVirtualThread {
            if (LOG.isTraceEnabled) {
                LOG.trace("Closing secure channel of connection {}...", connectionId)
            }
            secureChannel.close()
        }

        if (LOG.isTraceEnabled) {
            LOG.trace("Clearing timeouts...")
        }
        datTimer.cancelTimeout()
        raTimer.cancelTimeout()
        handshakeTimer.cancelTimeout()
        ackTimer.cancelTimeout()
        if (LOG.isTraceEnabled) {
            LOG.trace("Stopping RA components...")
        }
        // Cancels proverHandshakeTimer
        stopRaProverDriver()
        // Cancels verifierHandshakeTimer
        stopRaVerifierDriver()

        // Notify upper layer via handshake or closeListener
        if (!handshakeResultAvailable) {
            LOG.trace("Notify handshake lock...")
            notifyHandshakeCompleteLock()
        }

        connection.thenAccept { it.onClose() }
    }

    override val isFsmLocked: Boolean
        get() = isLocked

    override fun getState(state: FsmState): State = states[state] ?: throw NoSuchElementException("State unknown")

    override fun setRaMechanisms(proverMechanism: String, verifierMechanism: String) {
        this.proverMechanism = proverMechanism
        this.verifierMechanism = verifierMechanism
    }

    override val bufferedIdscpMessage: IdscpMessage?
        get() = bufferedIdscpData

    /**
     * Handle IdscpAck
     * @return true if everything if ack flag was cleared correctly, else false
     */
    override fun recvAck(idscpAck: IdscpAck): Boolean {
        if (ackFlag) {
            if (LOG.isTraceEnabled) {
                LOG.trace("Received IdscpAck with alternating bit {}, cancel flag in fsm", idscpAck.alternatingBit)
            }
            if (nextSendAlternatingBit.asBoolean() != idscpAck.alternatingBit) {
                LOG.trace("Received IdscpAck with wrong alternating bit. Ignoring")
            } else {
                ackFlag = false
                ackTimer.cancelTimeout()
                if (LOG.isTraceEnabled) {
                    LOG.trace("Alternate nextSend bit from {}", nextSendAlternatingBit.asBoolean())
                }
                nextSendAlternatingBit.alternate()
                return true
            }
        } else {
            LOG.warn("Received unexpected IdscpAck")
        }
        return false
    }

    override fun recvData(idscpData: IdscpData) {
        if (LOG.isTraceEnabled) {
            LOG.trace("Received IdscpData with alternating bit {}", idscpData.alternatingBit)
        }

        if (idscpData.alternatingBit != expectedAlternatingBit.asBoolean()) {
            LOG.trace("Received IdscpData with unexpected alternating bit. Could be an old packet replayed. Ignore it.")
        } else {
            // Forward payload data to upper layer. Make sure that the upper layer handles this asynchronously!
            connection.thenAccept { it.onMessage(idscpData.data.toByteArray()) }

            if (LOG.isTraceEnabled) {
                LOG.trace("Send IdscpAck with received alternating bit {}", idscpData.alternatingBit)
            }
            if (!sendFromFSM(Idscp2MessageHelper.createIdscpAckMessage(idscpData.alternatingBit))) {
                LOG.error("Cannot send ACK")
            }
            if (LOG.isTraceEnabled) {
                LOG.trace("Alternate expected bit from {}", expectedAlternatingBit.asBoolean())
            }
            expectedAlternatingBit.alternate()
        }
    }

    override fun setBufferedIdscpData(message: IdscpMessage) {
        this.bufferedIdscpData = message
    }

    companion object {
        private val LOG = LoggerFactory.getLogger(FSM::class.java)
    }

    init {
        val handshakeTimeoutHandler = Runnable {
            if (LOG.isTraceEnabled) {
                LOG.trace("HANDSHAKE_TIMER_EXPIRED")
            }
            onControlMessage(InternalControlMessage.TIMEOUT)
        }
        val datTimeoutHandler = Runnable {
            if (LOG.isTraceEnabled) {
                LOG.trace("DAT_TIMER_EXPIRED")
            }
            onControlMessage(InternalControlMessage.DAT_TIMER_EXPIRED)
        }
        val raTimeoutHandler = Runnable {
            if (LOG.isTraceEnabled) {
                LOG.trace("RA_TIMER_EXPIRED")
            }
            onControlMessage(InternalControlMessage.REPEAT_RA)
        }
        val proverTimeoutHandler = Runnable {
            if (LOG.isTraceEnabled) {
                LOG.trace("RA_PROVER_HANDSHAKE_TIMER_EXPIRED")
            }
            onControlMessage(InternalControlMessage.TIMEOUT)
        }
        val verifierTimeoutHandler = Runnable {
            if (LOG.isTraceEnabled) {
                LOG.trace("RA_VERIFIER_HANDSHAKE_TIMER_EXPIRED")
            }
            onControlMessage(InternalControlMessage.TIMEOUT)
        }
        val ackTimeoutHandler = Runnable {
            if (LOG.isTraceEnabled) {
                LOG.trace("ACK_TIMER_EXPIRED")
            }
            onControlMessage(InternalControlMessage.ACK_TIMER_EXPIRED)
        }

        datTimer = DynamicTimer(fsmIsBusy, datTimeoutHandler)
        handshakeTimer = StaticTimer(fsmIsBusy, handshakeTimeoutHandler, handshakeTimeoutDelay)
        proverHandshakeTimer = StaticTimer(fsmIsBusy, proverTimeoutHandler, handshakeTimeoutDelay)
        verifierHandshakeTimer = StaticTimer(fsmIsBusy, verifierTimeoutHandler, handshakeTimeoutDelay)
        raTimer = StaticTimer(fsmIsBusy, raTimeoutHandler, attestationConfig.raTimeoutDelay)
        ackTimer = StaticTimer(fsmIsBusy, ackTimeoutHandler, ackTimeoutDelay)

        /* ------------- FSM STATE Initialization -------------*/
        val closedState = StateClosed(
            this,
            onMessageBlock,
            attestationConfig
        )
        states[FsmState.STATE_CLOSED] = closedState
        // Set initial state to STATE_CLOSED
        currentState = closedState
        states[FsmState.STATE_WAIT_FOR_HELLO] = StateWaitForHello(
            this,
            handshakeTimer,
            datTimer,
            dapsDriver,
            attestationConfig
        )
        states[FsmState.STATE_WAIT_FOR_RA] = StateWaitForRa(
            this,
            handshakeTimer,
            verifierHandshakeTimer,
            proverHandshakeTimer,
            raTimer
        )
        states[FsmState.STATE_WAIT_FOR_RA_PROVER] = StateWaitForRaProver(
            this,
            raTimer,
            handshakeTimer,
            proverHandshakeTimer,
            ackTimer
        )
        states[FsmState.STATE_WAIT_FOR_RA_VERIFIER] = StateWaitForRaVerifier(
            this,
            raTimer,
            handshakeTimer,
            verifierHandshakeTimer,
            ackTimer
        )
        states[FsmState.STATE_WAIT_FOR_DAT_AND_RA] = StateWaitForDatAndRa(
            this,
            handshakeTimer,
            proverHandshakeTimer,
            datTimer,
            dapsDriver
        )
        states[FsmState.STATE_WAIT_FOR_DAT_AND_RA_VERIFIER] = StateWaitForDatAndRaVerifier(
            this,
            handshakeTimer,
            datTimer,
            dapsDriver
        )
        states[FsmState.STATE_ESTABLISHED] = StateEstablished(
            this,
            raTimer,
            handshakeTimer,
            ackTimer,
            nextSendAlternatingBit
        )
        states[FsmState.STATE_WAIT_FOR_ACK] = StateWaitForAck(
            this,
            raTimer,
            handshakeTimer,
            ackTimer
        )
    }
}
