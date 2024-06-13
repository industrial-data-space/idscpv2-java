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

import de.fhg.aisec.ids.idscp2.api.configuration.AttestationConfig
import de.fhg.aisec.ids.idscp2.api.fsm.FSM
import de.fhg.aisec.ids.idscp2.api.fsm.FsmResult
import de.fhg.aisec.ids.idscp2.api.fsm.FsmResultCode
import de.fhg.aisec.ids.idscp2.api.fsm.FsmState
import de.fhg.aisec.ids.idscp2.api.fsm.InternalControlMessage
import de.fhg.aisec.ids.idscp2.api.fsm.State
import de.fhg.aisec.ids.idscp2.api.fsm.Transition
import de.fhg.aisec.ids.idscp2.core.messages.Idscp2MessageHelper
import org.slf4j.LoggerFactory
import java.util.Arrays
import java.util.concurrent.locks.Condition
import java.util.stream.Collectors

/**
 * The Closed State of the FSM of the IDSCP2 protocol.
 * The FSM is in the Closed state either before any transition was triggered (in this case, the
 * Closed State is the FSM Start state) or after the connection was closed (in this case, the
 * Closed State is the FSM final state without any outgoing transitions)
 *
 *
 * When the FSM go from any State into the Closed State again, the FSM is locked forever and all
 * involved actors like RaDrivers and Timers will be terminated
 *
 * @author Leon Beckmann (leon.beckmann@aisec.fraunhofer.de)
 */
internal class StateClosed(fsm: FSM, onMessageLock: Condition, attestationConfig: AttestationConfig) : State() {

    private fun runExitCode(onMessageLock: Condition) {
        // State Closed exit code
        onMessageLock.signalAll() // enables fsm.onMessage()
    }

    override fun runEntryCode(fsm: FSM) {
        // State Closed entry code
        if (LOG.isTraceEnabled) {
            LOG.trace("Switched to state STATE_CLOSED")
        }
        fsm.shutdownFsm()
    }

    companion object {
        private val LOG = LoggerFactory.getLogger(StateClosed::class.java)
    }

    init {

        /*---------------------------------------------------
         * STATE_CLOSED - Transition Description
         * ---------------------------------------------------
         * onICM: start_handshake --> {send IDSCP_HELLO, set handshake_timeout} --> STATE_WAIT_FOR_HELLO
         * ALL_OTHER_MESSAGES ---> STATE_CLOSED
         * --------------------------------------------------- */
        addTransition(
            InternalControlMessage.START_IDSCP_HANDSHAKE.value,
            Transition {
                if (fsm.isFsmLocked) {
                    if (LOG.isTraceEnabled) {
                        LOG.trace("Cannot start handshake, because FSM is locked forever. Ignored.")
                    }
                    return@Transition FsmResult(FsmResultCode.FSM_LOCKED, this)
                }

                // FSM not locked, start handshake
                if (LOG.isTraceEnabled) {
                    LOG.trace("Get DAT Token vom DAT driver...")
                }
                val dat = fsm.dynamicAttributeToken
                if (LOG.isTraceEnabled) {
                    LOG.trace("Send IDSCP_HELLO")
                }
                val idscpHello = Idscp2MessageHelper.createIdscpHelloMessage(
                    dat,
                    attestationConfig.supportedAttestationSuite,
                    attestationConfig.expectedAttestationSuite
                )
                if (!fsm.sendFromFSM(idscpHello)) {
                    LOG.warn("Cannot send IdscpHello. Close connection")
                    runEntryCode(fsm)
                    onMessageLock.signalAll()
                    return@Transition FsmResult(FsmResultCode.IO_ERROR, this)
                }
                runExitCode(onMessageLock)
                FsmResult(FsmResultCode.OK, fsm.getState(FsmState.STATE_WAIT_FOR_HELLO))
            }
        )

        addTransition(
            InternalControlMessage.REPEAT_RA.value,
            Transition {
                if (LOG.isTraceEnabled) {
                    LOG.trace("Received RepeatRa in STATE_CLOSED, ignored.")
                }

                // return either FSM_LOCKED or FSM_NOT_STARTED
                if (fsm.isFsmLocked) {
                    FsmResult(FsmResultCode.FSM_LOCKED, this)
                } else {
                    FsmResult(FsmResultCode.FSM_NOT_STARTED, this)
                }
            }
        )

        addTransition(
            InternalControlMessage.SEND_DATA.value,
            Transition {
                if (LOG.isTraceEnabled) {
                    LOG.trace("Received SEND in STATE_CLOSED, ignored.")
                }

                // return either FSM_LOCKED or FSM_NOT_STARTED
                if (fsm.isFsmLocked) {
                    FsmResult(FsmResultCode.FSM_LOCKED, this)
                } else {
                    FsmResult(FsmResultCode.FSM_NOT_STARTED, this)
                }
            }
        )

        addTransition(
            InternalControlMessage.IDSCP_STOP.value,
            Transition {
                if (LOG.isTraceEnabled) {
                    LOG.trace("Received STOP in STATE_CLOSED, ignored.")
                }

                // return either FSM_LOCKED or FSM_NOT_STARTED
                if (fsm.isFsmLocked) {
                    FsmResult(FsmResultCode.FSM_LOCKED, this)
                } else {
                    FsmResult(FsmResultCode.FSM_NOT_STARTED, this)
                }
            }
        )

        setNoTransitionHandler {
            if (LOG.isTraceEnabled) {
                LOG.trace(
                    "No transition available for given event {}, stack trace for analysis:\n{}",
                    it,
                    Arrays.stream(Thread.currentThread().stackTrace)
                        .skip(1)
                        .map { obj: StackTraceElement -> obj.toString() }
                        .collect(Collectors.joining("\n"))
                )
                LOG.trace("Stay in state STATE_CLOSED")
            }
            FsmResult(FsmResultCode.UNKNOWN_TRANSITION, this)
        }
    }
}
