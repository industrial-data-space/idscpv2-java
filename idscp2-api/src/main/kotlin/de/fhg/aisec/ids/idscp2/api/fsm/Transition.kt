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
 * Transition class for State machine, provides a doTransition method
 * that returns the fsm result containing of the next state for a given event and the result code
 *
 * @author Leon Beckmann (leon.beckmann@aisec.fraunhofer.de)
 */
class Transition(private val eventHandler: (Event) -> FsmResult) {
    fun doTransition(e: Event): FsmResult = eventHandler(e)
}
