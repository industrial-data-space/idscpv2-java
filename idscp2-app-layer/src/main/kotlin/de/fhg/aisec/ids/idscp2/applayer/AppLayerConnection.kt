/*-
 * ========================LICENSE_START=================================
 * idscp2-app-layer
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
package de.fhg.aisec.ids.idscp2.applayer

import com.google.protobuf.ByteString
import de.fhg.aisec.ids.idscp2.api.connection.Idscp2Connection
import de.fhg.aisec.ids.idscp2.api.connection.Idscp2MessageListener
import de.fhg.aisec.ids.idscp2.api.fsm.FSM
import de.fhg.aisec.ids.idscp2.applayer.listeners.GenericMessageListener
import de.fhg.aisec.ids.idscp2.applayer.listeners.IdsMessageListener
import de.fhg.aisec.ids.idscp2.applayer.messages.AppLayer
import de.fhg.aisec.ids.idscp2.core.connection.Idscp2ConnectionImpl
import de.fhg.aisec.ids.idscp2.core.forEachResilient
import de.fraunhofer.iais.eis.Message
import org.slf4j.LoggerFactory
import java.util.Collections
import java.util.WeakHashMap

class AppLayerConnection private constructor(private val idscp2Connection: Idscp2Connection) :
    Idscp2Connection by idscp2Connection {
    private val idscp2MessageListener: Idscp2MessageListener = Idscp2MessageListener { _, data ->
        try {
            val appLayerMessage = AppLayer.AppLayerMessage.parseFrom(data)
            if (LOG.isTraceEnabled) {
                LOG.trace("Received AppLayerMessage ${appLayerMessage.messageCase}")
            }
            when (appLayerMessage.messageCase) {
                AppLayer.AppLayerMessage.MessageCase.GENERICMESSAGE -> {
                    val genericMessage = appLayerMessage.genericMessage
                    val header = genericMessage.header
                    val payload = genericMessage.payload?.toByteArray()
                    val extraHeaders = genericMessage.extraHeadersList.associate { it.name to it.value }
                    synchronized(genericMessageListeners) {
                        genericMessageListeners.forEachResilient(LOG) { listener ->
                            listener.onMessage(this, header, payload?.copyOf(), extraHeaders)
                        }
                    }
                }
                AppLayer.AppLayerMessage.MessageCase.IDSMESSAGE -> {
                    val idsMessage = appLayerMessage.idsMessage
                    val header = idsMessage.header?.let {
                        Utils.SERIALIZER.deserialize(it, Message::class.java)
                    }
                    val payload = idsMessage.payload?.toByteArray()
                    val extraHeaders = idsMessage.extraHeadersList.associate { it.name to it.value }
                    synchronized(idsMessageListeners) {
                        idsMessageListeners.forEachResilient(LOG) { listener ->
                            listener.onMessage(this, header, payload?.copyOf(), extraHeaders)
                        }
                    }
                }
                else -> LOG.warn("Unknown IDSCP2 app layer message type encountered.")
            }
        } catch (e: Exception) {
            LOG.error("Error processing AppLayerMessage", e)
        }
    }
    private val genericMessageListeners: MutableSet<GenericMessageListener> = LinkedHashSet()
    private val idsMessageListeners: MutableSet<IdsMessageListener> = LinkedHashSet()

    constructor(fsm: FSM, id: String) : this(Idscp2ConnectionImpl(fsm, id)) {
        idscp2Connection.addMessageListener(idscp2MessageListener)
    }

    fun sendGenericMessage(header: String?, payload: ByteArray?, headers: Map<String, String>?) {
        val message = AppLayer.AppLayerMessage.newBuilder()
            .setGenericMessage(
                AppLayer.GenericMessage.newBuilder()
                    .also { messageBuilder ->
                        if (header != null) {
                            messageBuilder.header = header
                        }
                        if (payload != null) {
                            messageBuilder.payload = ByteString.copyFrom(payload)
                        }
                        headers?.forEach {
                            messageBuilder.addExtraHeadersBuilder().run {
                                name = it.key
                                value = it.value
                            }
                        }
                    }
                    .build()
            )
            .build()
        idscp2Connection.nonBlockingSend(message.toByteArray())
    }

    fun addGenericMessageListener(listener: GenericMessageListener) {
        synchronized(genericMessageListeners) {
            genericMessageListeners += listener
        }
        if (LOG.isTraceEnabled) {
            LOG.trace("Added GenericMessageListener $listener for connection {}", idscp2Connection.id)
        }
    }

    fun removeGenericMessageListener(listener: GenericMessageListener) {
        synchronized(genericMessageListeners) {
            genericMessageListeners.remove(listener)
        }
    }

    fun sendIdsMessage(
        header: Message?,
        payload: ByteArray?,
        headers: Map<String, String>?,
        sendTimeout: Long = DEFAULT_TIMEOUT
    ) {
        val message = AppLayer.AppLayerMessage.newBuilder()
            .setIdsMessage(
                AppLayer.IdsMessage.newBuilder()
                    .also { messageBuilder ->
                        if (header != null) {
                            messageBuilder.header = Utils.SERIALIZER.serialize(header)
                        }
                        if (payload != null) {
                            messageBuilder.payload = ByteString.copyFrom(payload)
                        }
                        headers?.forEach {
                            messageBuilder.addExtraHeadersBuilder().run {
                                name = it.key
                                value = it.value
                            }
                        }
                    }
                    .build()
            )
            .build()
        idscp2Connection.blockingSend(message.toByteArray(), sendTimeout)
    }

    fun addIdsMessageListener(listener: IdsMessageListener) {
        synchronized(idsMessageListeners) {
            idsMessageListeners += listener
        }
        if (LOG.isTraceEnabled) {
            LOG.trace("Added IdsMessageListener $listener for connection {}", idscp2Connection.id)
        }
    }

    fun removeIdsMessageListener(listener: IdsMessageListener) {
        synchronized(idsMessageListeners) {
            idsMessageListeners.remove(listener)
        }
    }

    override fun toString(): String = "AppLayerConnection($id)"

    companion object {
        private val LOG = LoggerFactory.getLogger(AppLayerConnection::class.java)
        private val appLayerConnections = Collections.synchronizedMap(
            WeakHashMap<Idscp2Connection, AppLayerConnection>()
        )
        private const val DEFAULT_TIMEOUT = 10000L

        fun from(idscp2Connection: Idscp2Connection): AppLayerConnection = if (idscp2Connection is AppLayerConnection) {
            idscp2Connection
        } else {
            appLayerConnections.computeIfAbsent(idscp2Connection) { AppLayerConnection(it) }
        }
    }
}
