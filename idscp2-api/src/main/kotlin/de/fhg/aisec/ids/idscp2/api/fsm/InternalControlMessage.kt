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

/**
 * An enum that wraps the internal control messages of the IDSCP2 protocol to trigger transitions
 * by non-IDSCP2-message-events
 *
 * @author Leon Beckmann (leon.beckmann@aisec.fraunhofer.de)
 */
enum class InternalControlMessage(val value: String) {
    // Using unique values that are different from IdscpMessage.MessageCase to identify event.key
    START_IDSCP_HANDSHAKE("ICM_START"),
    IDSCP_STOP("ICM_STOP"),
    DAT_TIMER_EXPIRED("ICM_DAT_TIMER_EXPIRED"),
    REPEAT_RA("ICM_REPEAT_RA"),
    SEND_DATA("ICM_SEND_DATA"),
    RA_VERIFIER_OK("ICM_RA_V_OK"),
    RA_VERIFIER_FAILED("ICM_RA_V_FAILED"),
    RA_PROVER_OK("ICM_RA_P_OK"),
    RA_PROVER_FAILED("ICM_RA_P_FAILED"),
    RA_PROVER_MSG("ICM_RA_PROVER_MSG"),
    RA_VERIFIER_MSG("ICM_RA_VERIFIER_MSG"),
    ERROR("ICM_ERROR"),
    TIMEOUT("ICM_TIMEOUT"),
    ACK_TIMER_EXPIRED("ICM_ACK_TIMER_EXPIRED")
}
