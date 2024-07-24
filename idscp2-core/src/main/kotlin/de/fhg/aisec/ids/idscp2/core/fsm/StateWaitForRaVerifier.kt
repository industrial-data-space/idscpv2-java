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

import de.fhg.aisec.ids.idscp2.api.fsm.Event
import de.fhg.aisec.ids.idscp2.api.fsm.FSM
import de.fhg.aisec.ids.idscp2.api.fsm.FsmResult
import de.fhg.aisec.ids.idscp2.api.fsm.FsmResultCode
import de.fhg.aisec.ids.idscp2.api.fsm.FsmState
import de.fhg.aisec.ids.idscp2.api.fsm.InternalControlMessage
import de.fhg.aisec.ids.idscp2.api.fsm.Transition
import de.fhg.aisec.ids.idscp2.core.messages.Idscp2MessageHelper
import de.fhg.aisec.ids.idscp2.messages.IDSCP2.IdscpClose.CloseCause
import de.fhg.aisec.ids.idscp2.messages.IDSCP2.IdscpMessage
import org.slf4j.LoggerFactory

/**
 * The Wait_For_Ra_Verifier State of the FSM of the IDSCP2 protocol.
 * Waits only for the RaVerifier Result to decide whether the connection will be established
 *
 * @author Leon Beckmann (leon.beckmann@aisec.fraunhofer.de)
 */
class StateWaitForRaVerifier(
    fsm: FSM,
    raTimer: StaticTimer,
    handshakeTimer: StaticTimer,
    verifierHandshakeTimer: StaticTimer,
    ackTimer: StaticTimer
) : RaState() {
    override fun runEntryCode(fsm: FSM) {
        if (LOG.isTraceEnabled) {
            LOG.trace("Switched to state STATE_WAIT_FOR_RA_VERIFIER")
        }
    }

    companion object {
        private val LOG = LoggerFactory.getLogger(StateWaitForRaVerifier::class.java)
    }

    init {

        /*---------------------------------------------------
         * STATE_WAIT_FOR_RA_VERIFIER - Transition Description
         * ---------------------------------------------------
         * onICM: error ---> {stop RA_VERIFIER} ---> STATE_CLOSED
         * onICM: close ---> {send IDSCP_CLOSE, stop RA_VERIFIER} ---> STATE_CLOSED
         * onICM: dat_timeout ---> {send IDSCP_DAT_EXPIRED, cancel raV} ---> STATE_WAIT_FOR_DAT_AND_RA_VERIFIER
         * onICM: timeout ---> {send IDSCP_CLOSE, stop RA_VERIFIER} ---> STATE_CLOSED
         * onICM: ra_verifier_ok ---> {set ra timeout} ---> STATE_ESTABLISHED / STATE_WAIT_FOR_ACK
         * onICM: ra_verifier_failed ---> {send IDSCP_CLOSE} ---> STATE_CLOSED
         * onICM: ra_verifier_msg ---> {send IDSCP_RA_VERIFIER} ---> STATE_WAIT_FOR_RA_VERIFIER
         * onMessage: IDSCP_ACK ---> {cancel Ack flag} ---> STATE_WAIT_FOR_RA
         * onMessage: IDSCP_DAT_EXPIRED ---> {send IDSCP_DAT, start RA_PROVER} ---> STATE_WAIT_FOR_RA
         * onMessage: IDSCP_CLOSE ---> {stop RA_VERIFIER} ---> STATE_CLOSED
         * onMessage: IDSCP_RA_PROVER ---> {delegat to RA_VERIFIER} ---> STATE_WAIT_FOR_RA_VERIFIER
         * onMessage: IDSCP_RE_RA ---> {start RA_PROVER} ---> STATE_WAIT_FOR_RA
         * ALL_OTHER_MESSAGES ---> {} ---> STATE_WAIT_FOR_RA_VERIFIER
         * --------------------------------------------------- */
        addTransition(
            InternalControlMessage.IDSCP_STOP.value,
            Transition {
                if (LOG.isTraceEnabled) {
                    LOG.trace("Send IDSC_CLOSE")
                }
                fsm.sendFromFSM(
                    Idscp2MessageHelper.createIdscpCloseMessage(
                        "User close",
                        CloseCause.USER_SHUTDOWN
                    )
                )
                FsmResult(FsmResultCode.OK, fsm.getState(FsmState.STATE_CLOSED))
            }
        )

        addTransition(
            InternalControlMessage.ERROR.value,
            Transition {
                LOG.warn("An internal control error occurred")
                FsmResult(FsmResultCode.OK, fsm.getState(FsmState.STATE_CLOSED))
            }
        )

        addTransition(
            InternalControlMessage.REPEAT_RA.value,
            Transition {
                // already re-attestating
                FsmResult(FsmResultCode.OK, this)
            }
        )

        addTransition(
            InternalControlMessage.SEND_DATA.value,
            Transition {
                FsmResult(FsmResultCode.NOT_CONNECTED, this)
            }
        )

        addTransition(
            InternalControlMessage.TIMEOUT.value,
            Transition {
                LOG.warn("Handshake timeout occurred. Send IDSCP_CLOSE")
                fsm.sendFromFSM(Idscp2MessageHelper.createIdscpCloseMessage("Handshake timeout", CloseCause.TIMEOUT))
                FsmResult(FsmResultCode.OK, fsm.getState(FsmState.STATE_CLOSED))
            }
        )

        addTransition(
            InternalControlMessage.DAT_TIMER_EXPIRED.value,
            Transition {
                if (LOG.isDebugEnabled) {
                    LOG.debug("DAT expired, request new DAT from peer and trigger a re-attestation")
                }
                if (LOG.isTraceEnabled) {
                    LOG.trace("Send IDSCP_DAT_EXPIRED")
                }
                fsm.stopRaVerifierDriver()
                if (!fsm.sendFromFSM(Idscp2MessageHelper.createIdscpDatExpiredMessage())) {
                    LOG.warn("Cannot send DatExpired message")
                    return@Transition FsmResult(FsmResultCode.IO_ERROR, fsm.getState(FsmState.STATE_CLOSED))
                }
                if (LOG.isTraceEnabled) {
                    LOG.trace("Start Handshake Timer")
                }
                handshakeTimer.resetTimeout()
                FsmResult(FsmResultCode.OK, fsm.getState(FsmState.STATE_WAIT_FOR_DAT_AND_RA_VERIFIER))
            }
        )

        addTransition(
            InternalControlMessage.RA_VERIFIER_OK.value,
            Transition {
                if (LOG.isTraceEnabled) {
                    LOG.trace("Received RA_VERIFIER OK. Start RA Timer")
                }
                verifierHandshakeTimer.cancelTimeout()
                raTimer.resetTimeout()
                if (fsm.ackFlag) {
                    ackTimer.start()
                    return@Transition FsmResult(FsmResultCode.OK, fsm.getState(FsmState.STATE_WAIT_FOR_ACK))
                } else {
                    return@Transition FsmResult(FsmResultCode.OK, fsm.getState(FsmState.STATE_ESTABLISHED))
                }
            }
        )

        addTransition(
            InternalControlMessage.RA_VERIFIER_FAILED.value,
            Transition {
                LOG.warn("RA_VERIFIER failed. Send IDSCP_CLOSE")
                fsm.sendFromFSM(
                    Idscp2MessageHelper.createIdscpCloseMessage(
                        "RA_VERIFIER failed",
                        CloseCause.RA_VERIFIER_FAILED
                    )
                )
                FsmResult(FsmResultCode.OK, fsm.getState(FsmState.STATE_CLOSED))
            }
        )

        addTransition(
            InternalControlMessage.RA_VERIFIER_MSG.value,
            Transition { event: Event ->
                if (LOG.isTraceEnabled) {
                    LOG.trace("Send IDSCP_RA_VERIFIER")
                }
                if (!fsm.sendFromFSM(event.idscpMessage)) {
                    LOG.warn("Cannot send ra verifier message")
                    return@Transition FsmResult(FsmResultCode.IO_ERROR, fsm.getState(FsmState.STATE_CLOSED))
                }
                FsmResult(FsmResultCode.OK, this)
            }
        )

        addTransition(
            IdscpMessage.IDSCPCLOSE_FIELD_NUMBER,
            Transition {
                if (LOG.isTraceEnabled) {
                    LOG.trace("Received IDSCP_CLOSE")
                }
                FsmResult(FsmResultCode.OK, fsm.getState(FsmState.STATE_CLOSED))
            }
        )

        addTransition(
            IdscpMessage.IDSCPDATEXPIRED_FIELD_NUMBER,
            Transition {
                if (LOG.isDebugEnabled) {
                    LOG.debug("Peer is requesting a new DAT, followed by a re-attestation")
                }
                if (!fsm.sendFromFSM(Idscp2MessageHelper.createIdscpDatMessage(fsm.dynamicAttributeToken))) {
                    LOG.warn("Cannot send DAT message")
                    return@Transition FsmResult(FsmResultCode.IO_ERROR, fsm.getState(FsmState.STATE_CLOSED))
                }
                if (!fsm.restartRaProverDriver()) {
                    LOG.warn("Cannot run RA prover, close idscp connection")
                    return@Transition FsmResult(FsmResultCode.RA_ERROR, fsm.getState(FsmState.STATE_CLOSED))
                }
                FsmResult(FsmResultCode.OK, fsm.getState(FsmState.STATE_WAIT_FOR_RA))
            }
        )

        addTransition(
            IdscpMessage.IDSCPRAPROVER_FIELD_NUMBER,
            Transition { event: Event ->
                if (LOG.isTraceEnabled) {
                    LOG.trace("Delegate received IDSCP_RA_PROVER to RA_VERIFIER")
                }

                if (!event.idscpMessage.hasIdscpRaProver()) {
                    // this should never happen
                    LOG.warn("IDSCP_RA_PROVER Message not available")
                    return@Transition FsmResult(FsmResultCode.RA_ERROR, fsm.getState(FsmState.STATE_CLOSED))
                }

                fsm.raVerifierDriver?.let {
                    // Run in fire-and-forget manner to avoid cycles caused by protocol misuse
                    Thread.startVirtualThread {
                        it.delegate(event.idscpMessage.idscpRaProver.data.toByteArray())
                    }
                } ?: run {
                    LOG.warn("RaProverDriver not available")
                    return@Transition FsmResult(FsmResultCode.RA_ERROR, fsm.getState(FsmState.STATE_CLOSED))
                }

                FsmResult(FsmResultCode.OK, this)
            }
        )

        addTransition(
            IdscpMessage.IDSCPRERA_FIELD_NUMBER,
            Transition {
                if (LOG.isDebugEnabled) {
                    LOG.debug("Peer is requesting a re-attestation")
                }
                if (!fsm.restartRaProverDriver()) {
                    LOG.warn("Cannot run RA prover, close idscp connection")
                    return@Transition FsmResult(FsmResultCode.RA_ERROR, fsm.getState(FsmState.STATE_CLOSED))
                }
                FsmResult(FsmResultCode.OK, fsm.getState(FsmState.STATE_WAIT_FOR_RA))
            }
        )

        addTransition(
            IdscpMessage.IDSCPACK_FIELD_NUMBER,
            Transition {
                fsm.recvAck(it.idscpMessage.idscpAck)
                FsmResult(FsmResultCode.OK, this)
            }
        )

        setNoTransitionHandler {
            if (LOG.isTraceEnabled) {
                LOG.trace("No transition available for given event $it")
                LOG.trace("Stay in state STATE_WAIT_FOR_RA_VERIFIER")
            }
            FsmResult(FsmResultCode.UNKNOWN_TRANSITION, this)
        }
    }
}
