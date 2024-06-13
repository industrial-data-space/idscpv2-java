/*-
 * ========================LICENSE_START=================================
 * idscp2-api
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
package de.fhg.aisec.ids.idscp2.api.fsm

import de.fhg.aisec.ids.idscp2.messages.IDSCP2.IdscpMessage

/**
 * An Event class for the Finite State Machine. Triggers a transition and holds
 * either an IdscpMessage or an InternalControlMessage, or both in special cases.
 *
 * @author Leon Beckmann (leon.beckmann@aisec.fraunhofer.de)
 */
class Event {
    enum class EventType {
        IDSCP_MESSAGE,
        INTERNAL_CONTROL_MESSAGE
    }

    val key: Any?
    val type: EventType
    lateinit var idscpMessage: IdscpMessage
        private set
    private lateinit var controlMessage: InternalControlMessage

    /**
     * Create an event with an Internal Control Message
     */
    constructor(controlMessage: InternalControlMessage) {
        key = controlMessage.value
        type = EventType.INTERNAL_CONTROL_MESSAGE
        this.controlMessage = controlMessage
    }

    /**
     * Create an event with an Idscp2 Message
     */
    constructor(idscpMessage: IdscpMessage) {
        key = idscpMessage.messageCase.number
        type = EventType.IDSCP_MESSAGE
        this.idscpMessage = idscpMessage
    }

    /**
     * Create an event for outgoing RaProver, RaVerifier, IdscpData messages
     *
     * throws an IllegalStateException if this event is requested for other purposes
     */
    constructor(controlMessage: InternalControlMessage, idscpMessage: IdscpMessage) {
        if (controlMessage == InternalControlMessage.RA_PROVER_MSG ||
            controlMessage == InternalControlMessage.RA_VERIFIER_MSG ||
            controlMessage == InternalControlMessage.SEND_DATA
        ) {
            key = controlMessage.value
            type = EventType.INTERNAL_CONTROL_MESSAGE
            this.idscpMessage = idscpMessage
            this.controlMessage = controlMessage
        } else {
            throw IllegalStateException(
                "This constructor must only be used by RA_PROVER, " +
                    "RA_VERIFIER for message passing and for SEND_DATA, encountered $controlMessage"
            )
        }
    }

    private fun idscpMessageAsString(): String = if (idscpMessage.hasIdscpData()) {
        "<hidden payload>"
    } else {
        idscpMessage.toString()
    }

    override fun toString(): String = "Event {" +
        "key=" + key +
        ", type=" + type +
        ", idscpMessage: " + (if (::idscpMessage.isInitialized) idscpMessageAsString() else null) +
        ", controlMessage: " + (if (::controlMessage.isInitialized) controlMessage else null) +
        "}"
}
