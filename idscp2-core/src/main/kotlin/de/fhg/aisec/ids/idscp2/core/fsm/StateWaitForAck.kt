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

import de.fhg.aisec.ids.idscp2.api.fsm.FSM
import de.fhg.aisec.ids.idscp2.api.fsm.FsmResult
import de.fhg.aisec.ids.idscp2.api.fsm.FsmResultCode
import de.fhg.aisec.ids.idscp2.api.fsm.FsmState
import de.fhg.aisec.ids.idscp2.api.fsm.InternalControlMessage
import de.fhg.aisec.ids.idscp2.api.fsm.State
import de.fhg.aisec.ids.idscp2.api.fsm.Transition
import de.fhg.aisec.ids.idscp2.core.messages.Idscp2MessageHelper
import de.fhg.aisec.ids.idscp2.messages.IDSCP2.IdscpClose.CloseCause
import de.fhg.aisec.ids.idscp2.messages.IDSCP2.IdscpMessage
import org.slf4j.LoggerFactory

/**
 * The Established State of the FSM of the IDSCP2 protocol.
 * Allows message exchange over the IDSCP2 protocol between two connectors
 *
 * @author Leon Beckmann (leon.beckmann@aisec.fraunhofer.de)
 */
class StateWaitForAck(fsm: FSM, raTimer: StaticTimer, handshakeTimer: StaticTimer, ackTimer: StaticTimer) : State() {

    override fun runEntryCode(fsm: FSM) {
        if (LOG.isTraceEnabled) {
            LOG.trace("Switched to state STATE_WAIT_FOR_ACK")
        }
    }

    companion object {
        private val LOG = LoggerFactory.getLogger(StateWaitForAck::class.java)
    }

    init {

        /*---------------------------------------------------
         * STATW_WAIT_FOR_ACK - Transition Description
         * ---------------------------------------------------
         * onICM: error ---> {timeouts.cancel(), send IDSCP_CLOSE} ---> STATE_CLOSED
         * onICM: stop ---> {timeouts.cancel()} ---> STATE_CLOSED
         * onICM: re_ra ---> {send IDSCP_RE_RA, start RA_VERIFIER} ---> STATE_WAIT_FOR_RA_VERIFIER
         * onICM: send_data ---> {send IDS_DATA} ---> STATE_WAIT_FOR_ACK
         * onICM: dat_timeout ---> {send IDSCP_DAT_EXPIRED} ---> STATE_WAIT_FOR_DAT_AND_RA_VERIFIER
         * onICM. ackTimeout --> {send IDSCP_DATA again} --> STATE_WAIT_FOR_ACK
         * onMessage: IDSCP_DATA ---> {delegate to connection} ---> STATE_WAIT_FOR_ACK
         * onMessage: IDSCP_ACK ---> {clear ACK flag} ---> STATE_ESTABLISHED
         * onMessage: IDSCP_RERA ---> {start RA_PROVER} ---> STATE_WAIT_FOR_RA_PROVER
         * onMessage: IDSCP_DAT_EXPIRED ---> {send IDSCP_DAT, start RA_PROVER} ---> STATE_WAIT_FOR_RA_PROVER
         * onMessage: IDSCP_CLOSE ---> {timeouts.cancel()} ---> STATE_CLOSED
         * ALL_OTHER_MESSAGES ---> {} ---> STATE_ESTABLISHED
         * --------------------------------------------------- */
        addTransition(
            InternalControlMessage.ERROR.value,
            Transition {
                LOG.warn("Error occurred, close idscp connection")
                FsmResult(FsmResultCode.OK, fsm.getState(FsmState.STATE_CLOSED))
            }
        )

        addTransition(
            InternalControlMessage.IDSCP_STOP.value,
            Transition {
                if (LOG.isTraceEnabled) {
                    LOG.trace("Send IDSCP_CLOSE")
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
            InternalControlMessage.REPEAT_RA.value,
            Transition {
                if (LOG.isDebugEnabled) {
                    LOG.debug("Re-Attestation triggered")
                }
                if (LOG.isTraceEnabled) {
                    LOG.trace("Send IDSCP_RE_RA, start RA_VERIFIER")
                }
                raTimer.cancelTimeout()
                ackTimer.cancelTimeout()
                if (!fsm.sendFromFSM(Idscp2MessageHelper.createIdscpReRaMessage(""))) {
                    LOG.warn("Cannot send ReRa message")
                    return@Transition FsmResult(FsmResultCode.IO_ERROR, fsm.getState(FsmState.STATE_CLOSED))
                }
                if (!fsm.restartRaVerifierDriver()) {
                    LOG.warn("Cannot run RA verifier, close idscp connection")
                    return@Transition FsmResult(FsmResultCode.RA_ERROR, fsm.getState(FsmState.STATE_CLOSED))
                }
                FsmResult(FsmResultCode.OK, fsm.getState(FsmState.STATE_WAIT_FOR_RA_VERIFIER))
            }
        )

        addTransition(
            InternalControlMessage.SEND_DATA.value,
            Transition {
                LOG.warn("Cannot send data in STATE_WAIT_FOR_ACK")
                FsmResult(FsmResultCode.WOULD_BLOCK, this)
            }
        )

        addTransition(
            InternalControlMessage.DAT_TIMER_EXPIRED.value,
            Transition {
                raTimer.cancelTimeout()
                ackTimer.cancelTimeout()
                if (LOG.isDebugEnabled) {
                    LOG.debug("DAT expired, request new DAT from peer and trigger a re-attestation")
                }
                if (LOG.isTraceEnabled) {
                    LOG.trace("Send IDSCP_DAT_EXPIRED")
                }
                if (!fsm.sendFromFSM(Idscp2MessageHelper.createIdscpDatExpiredMessage())) {
                    LOG.warn("Cannot send DatExpired message")
                    return@Transition FsmResult(FsmResultCode.IO_ERROR, fsm.getState(FsmState.STATE_CLOSED))
                }
                if (LOG.isTraceEnabled) {
                    LOG.trace("Set handshake timeout")
                }
                handshakeTimer.resetTimeout()
                FsmResult(FsmResultCode.OK, fsm.getState(FsmState.STATE_WAIT_FOR_DAT_AND_RA_VERIFIER))
            }
        )

        addTransition(
            InternalControlMessage.ACK_TIMER_EXPIRED.value,
            Transition {
                if (fsm.ackFlag) {
                    fsm.bufferedIdscpMessage?.let {
                        if (LOG.isTraceEnabled) {
                            LOG.trace("ACK_timeout occurred. Sending buffered IdscpData again...")
                        }
                        return@Transition if (!fsm.sendFromFSM(it)) {
                            LOG.warn("Cannot send IdscpData, shutdown FSM")
                            FsmResult(FsmResultCode.IO_ERROR, fsm.getState(FsmState.STATE_CLOSED))
                        } else {
                            ackTimer.start()
                            FsmResult(FsmResultCode.OK, this)
                        }
                    }
                }
                LOG.warn("No IdscpData message buffered in state WAIT_FOR_ACK. Shutdown")
                return@Transition FsmResult(
                    FsmResultCode.IDSCP_DATA_NOT_CACHED,
                    fsm.getState(FsmState.STATE_CLOSED)
                )
            }
        )

        addTransition(
            IdscpMessage.IDSCPRERA_FIELD_NUMBER,
            Transition {
                if (LOG.isDebugEnabled) {
                    LOG.debug("Peer is requesting a re-attestation")
                }
                if (!fsm.restartRaProverDriver()) {
                    LOG.warn("Cannot run Ra prover, close idscp connection")
                    return@Transition FsmResult(FsmResultCode.RA_ERROR, fsm.getState(FsmState.STATE_CLOSED))
                }
                ackTimer.cancelTimeout()
                FsmResult(FsmResultCode.OK, fsm.getState(FsmState.STATE_WAIT_FOR_RA_PROVER))
            }
        )

        addTransition(
            IdscpMessage.IDSCPDATEXPIRED_FIELD_NUMBER,
            Transition {
                if (LOG.isDebugEnabled) {
                    LOG.debug("Peer is requesting a new DAT, followed by a re-attestation")
                }
                if (!fsm.sendFromFSM(Idscp2MessageHelper.createIdscpDatMessage(fsm.dynamicAttributeToken))) {
                    LOG.warn("Cannot send Dat message")
                    return@Transition FsmResult(FsmResultCode.IO_ERROR, fsm.getState(FsmState.STATE_CLOSED))
                }
                if (!fsm.restartRaProverDriver()) {
                    LOG.warn("Cannot run Ra prover, close idscp connection")
                    return@Transition FsmResult(FsmResultCode.RA_ERROR, fsm.getState(FsmState.STATE_CLOSED))
                }
                ackTimer.cancelTimeout()
                FsmResult(FsmResultCode.OK, fsm.getState(FsmState.STATE_WAIT_FOR_RA_PROVER))
            }
        )

        addTransition(
            IdscpMessage.IDSCPDATA_FIELD_NUMBER,
            Transition {
                fsm.recvData(it.idscpMessage.idscpData)
                FsmResult(FsmResultCode.OK, this)
            }
        )

        addTransition(
            IdscpMessage.IDSCPACK_FIELD_NUMBER,
            Transition {
                if (fsm.recvAck(it.idscpMessage.idscpAck)) {
                    FsmResult(FsmResultCode.OK, fsm.getState(FsmState.STATE_ESTABLISHED))
                } else {
                    FsmResult(FsmResultCode.OK, this)
                }
            }
        )

        addTransition(
            IdscpMessage.IDSCPCLOSE_FIELD_NUMBER,
            Transition {
                if (LOG.isTraceEnabled) {
                    LOG.trace("Receive IDSCP_CLOSED")
                }
                FsmResult(FsmResultCode.OK, fsm.getState(FsmState.STATE_CLOSED))
            }
        )

        setNoTransitionHandler {
            if (LOG.isTraceEnabled) {
                LOG.trace("No transition available for given event $it")
                LOG.trace("Stay in state STATE_WAIT_FOR_ACK")
            }
            FsmResult(FsmResultCode.UNKNOWN_TRANSITION, this)
        }
    }
}
