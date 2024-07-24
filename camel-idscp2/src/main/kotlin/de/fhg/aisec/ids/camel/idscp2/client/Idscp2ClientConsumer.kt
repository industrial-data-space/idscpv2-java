/*-
 * ========================LICENSE_START=================================
 * camel-idscp2
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
package de.fhg.aisec.ids.camel.idscp2.client

import de.fhg.aisec.ids.camel.idscp2.Constants.IDS_HEADER
import de.fhg.aisec.ids.camel.idscp2.ListenerManager
import de.fhg.aisec.ids.camel.idscp2.Utils
import de.fhg.aisec.ids.idscp2.api.connection.Idscp2ConnectionListener
import de.fhg.aisec.ids.idscp2.applayer.AppLayerConnection
import de.fhg.aisec.ids.idscp2.applayer.listeners.GenericMessageListener
import de.fhg.aisec.ids.idscp2.applayer.listeners.IdsMessageListener
import de.fraunhofer.iais.eis.Message
import org.apache.camel.Processor
import org.apache.camel.support.DefaultConsumer
import org.slf4j.LoggerFactory
import java.util.concurrent.CompletableFuture

/**
 * The IDSCP2 client consumer.
 */
class Idscp2ClientConsumer(private val endpoint: Idscp2ClientEndpoint, processor: Processor) :
    DefaultConsumer(endpoint, processor),
    GenericMessageListener,
    IdsMessageListener {
    private lateinit var connectionFuture: CompletableFuture<AppLayerConnection>
    private var retryCount = 0L

    private fun connect() {
        connectionFuture = if (retryCount == 0L) {
            endpoint.makeConnection()
        } else {
            LOG.debug("Resetting connection...")
            endpoint.resetConnection(connectionFuture)
        }
        connectionFuture.thenAccept {
            retryCount = 0
            if (endpoint.useIdsMessages) {
                it.addIdsMessageListener(this@Idscp2ClientConsumer)
            } else {
                it.addGenericMessageListener(this@Idscp2ClientConsumer)
            }
            it.addConnectionListener(object : Idscp2ConnectionListener {
                override fun onError(t: Throwable) {
                    LOG.error("Error in Idscp2ClientConsumer connection", t)
                }

                override fun onClose() {
                    if (!isStoppingOrStopped) {
                        LOG.debug(
                            "IDSCP2 client consumer connection {} closed without stop, trying reconnect...",
                            if (connectionFuture.isDone) connectionFuture.get().id else "<pending>"
                        )
                        connect()
                    }
                }
            })
            it.unlockMessaging()
        }
        connectionFuture.exceptionally {
            if (retryCount == endpoint.maxRetries) {
                LOG.error("IDSCP2 connection finally failed, invoking error handler...")
                handleException(it)
            } else {
                retryCount += 1
                LOG.warn(
                    "Connection failed, do retry # $retryCount/${endpoint.maxRetries} " +
                        "after ${endpoint.retryDelayMs} ms...",
                    it
                )
                Thread.startVirtualThread {
                    // Sleep for retryDelayMs
                    Thread.sleep(endpoint.retryDelayMs)
                    // Retry connect
                    connect()
                }
            }
            null
        }
    }

    override fun doStart() {
        super.doStart()
        connect()
    }

    public override fun doStop() {
        LOG.debug(
            "Stopping/releasing IDSCP2 client consumer connection {}...",
            if (connectionFuture.isDone) connectionFuture.get().id else "<pending>"
        )
        endpoint.releaseConnection(connectionFuture)
    }

    override fun onMessage(
        connection: AppLayerConnection,
        header: Message?,
        payload: ByteArray?,
        extraHeaders: Map<String, String>
    ) {
        if (LOG.isTraceEnabled) {
            LOG.trace("Idscp2ClientConsumer received IdsMessage with header:\n{}", header)
        }
        onMessage(connection, header as Any?, payload, extraHeaders)
    }

    override fun onMessage(
        connection: AppLayerConnection,
        header: String?,
        payload: ByteArray?,
        extraHeaders: Map<String, String>
    ) {
        if (LOG.isTraceEnabled) {
            LOG.trace("Idscp2ClientConsumer received GenericMessage with header:\n{}", header)
        }
        onMessage(connection, header as Any?, payload, extraHeaders)
    }

    private fun onMessage(
        connection: AppLayerConnection,
        header: Any?,
        payload: ByteArray?,
        extraHeaders: Map<String, String>?
    ) {
        val exchange = endpoint.createExchange()
        // Ensures that Exchange has an ID
        exchange.exchangeId
        if (endpoint.useIdsMessages) {
            ListenerManager.publishExchangeEvent(connection, exchange)
        }
        try {
            createUoW(exchange)
            // Set relevant information
            exchange.message.let { message ->
                message.setHeader(IDS_HEADER, header)
                message.setBody(payload, ByteArray::class.java)
                endpoint.copyHeadersRegexObject?.let { regex ->
                    extraHeaders?.forEach {
                        if (regex.matches(it.key)) {
                            message.setHeader(it.key, it.value)
                        }
                    }
                }
            }
            // Do processing
            processor.process(exchange)
            // Handle response
            exchange.message.let { message ->
                val responseHeader = message.getHeader(IDS_HEADER)
                val responseBody = message.getBody(ByteArray::class.java)
                val responseExtraHeaders = endpoint.copyHeadersRegexObject?.let { regex ->
                    message.headers
                        .filter { regex.matches(it.key) }
                        .map { it.key to it.value.toString() }
                        .toMap()
                }
                if (responseBody != null || responseHeader != null) {
                    if (endpoint.useIdsMessages) {
                        connection.sendIdsMessage(
                            responseHeader?.let { Utils.finalizeMessage(responseHeader, connection) },
                            responseBody,
                            responseExtraHeaders
                        )
                    } else {
                        connection.sendGenericMessage(responseHeader?.toString(), responseBody, responseExtraHeaders)
                    }
                }
            }
        } finally {
            doneUoW(exchange)
        }
    }

    companion object {
        private val LOG = LoggerFactory.getLogger(Idscp2ClientConsumer::class.java)
    }
}
