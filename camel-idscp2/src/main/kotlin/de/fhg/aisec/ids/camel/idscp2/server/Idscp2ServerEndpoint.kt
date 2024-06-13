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
@file:Suppress("DEPRECATION")

package de.fhg.aisec.ids.camel.idscp2.server

import de.fhg.aisec.ids.camel.idscp2.Idscp2Endpoint
import de.fhg.aisec.ids.camel.idscp2.ListenerManager
import de.fhg.aisec.ids.camel.idscp2.Utils
import de.fhg.aisec.ids.camel.idscp2.doCommonEndpointConfiguration
import de.fhg.aisec.ids.idscp2.api.Idscp2EndpointListener
import de.fhg.aisec.ids.idscp2.api.configuration.AttestationConfig
import de.fhg.aisec.ids.idscp2.api.configuration.Idscp2Configuration
import de.fhg.aisec.ids.idscp2.api.connection.Idscp2ConnectionListener
import de.fhg.aisec.ids.idscp2.applayer.AppLayerConnection
import de.fhg.aisec.ids.idscp2.defaultdrivers.remoteattestation.dummy.RaProverDummy
import de.fhg.aisec.ids.idscp2.defaultdrivers.remoteattestation.dummy.RaProverDummy2
import de.fhg.aisec.ids.idscp2.defaultdrivers.remoteattestation.dummy.RaVerifierDummy
import de.fhg.aisec.ids.idscp2.defaultdrivers.remoteattestation.dummy.RaVerifierDummy2
import de.fhg.aisec.ids.idscp2.defaultdrivers.securechannel.tls13.NativeTlsConfiguration
import org.apache.camel.Consumer
import org.apache.camel.Processor
import org.apache.camel.Producer
import org.apache.camel.spi.UriEndpoint
import org.apache.camel.spi.UriParam
import org.apache.camel.support.DefaultEndpoint
import org.apache.camel.support.jsse.SSLContextParameters
import org.slf4j.LoggerFactory

@UriEndpoint(
    scheme = "idscp2server",
    title = "IDSCP2 Server Socket",
    syntax = "idscp2server://host:port",
    label = "ids"
)
class Idscp2ServerEndpoint(uri: String?, override val remaining: String, component: Idscp2ServerComponent?) :
    DefaultEndpoint(uri, component),
    Idscp2EndpointListener<AppLayerConnection>,
    Idscp2Endpoint {
    private var server: CamelIdscp2Server? = null
    private val consumers: MutableSet<Idscp2ServerConsumer> = HashSet()

    @UriParam(
        label = "common",
        description = "An optional Idscp2Configuration instance. " +
            "Takes precedence over other parameters included in this configuration."
    )
    override var idscp2Configuration: Idscp2Configuration? = null

    @UriParam(
        label = "common",
        description = "An optional NativeTlsConfiguration.Builder instance. " +
            "Takes precedence over other parameters included in this configuration, except for " +
            "the host and port settings, which will be applied from the URI passed to the component"
    )
    override var secureChannelConfigurationBuilder: NativeTlsConfiguration.Builder? = null

    override lateinit var secureChannelConfiguration: NativeTlsConfiguration

    @UriParam(
        label = "security",
        description = "The transport encryption SSL context for the IDSCP2 endpoint"
    )
    @Deprecated("Deprecated in favor of secureChannelConfigurationBuilder")
    override var transportSslContextParameters: SSLContextParameters? = null

    @UriParam(
        label = "security",
        description = "The DAPS authentication SSL context for the IDSCP2 endpoint"
    )
    @Deprecated("Deprecated in favor of idscp2Configuration")
    override var dapsSslContextParameters: SSLContextParameters? = null

    @UriParam(
        label = "security",
        description = "The SSL context for the IDSCP2 endpoint (deprecated)"
    )
    @Deprecated("Deprecated in favor of idscp2Configuration and secureChannelConfigurationBuilder")
    override var sslContextParameters: SSLContextParameters? = null

    @UriParam(
        label = "security",
        description = "Whether to verify the hostname of the client."
    )
    var tlsClientHostnameVerification: Boolean = true

    @UriParam(
        label = "security",
        description = "The validity time of remote attestation and DAT in milliseconds",
        defaultValue = "600000"
    )
    @Deprecated("Deprecated in favor of idscp2Configuration")
    override var dapsRaTimeoutDelay: Long = AttestationConfig.DEFAULT_RA_TIMEOUT_DELAY.toLong()

    @UriParam(
        label = "common",
        description = "Enable IdsMessage headers (Required for Usage Control)",
        defaultValue = "false"
    )
    var useIdsMessages: Boolean = false

    @UriParam(
        label = "common",
        description = "Locally supported Remote Attestation Suite IDs, separated by \"|\"",
        defaultValue = "${RaProverDummy2.RA_PROVER_DUMMY2_ID}|${RaProverDummy.RA_PROVER_DUMMY_ID}"
    )
    @Deprecated("Deprecated in favor of idscp2Configuration")
    override var supportedRaSuites: String = "${RaProverDummy2.RA_PROVER_DUMMY2_ID}|${RaProverDummy.RA_PROVER_DUMMY_ID}"

    @UriParam(
        label = "common",
        description = "Expected Remote Attestation Suite IDs, separated by \"|\", " +
            "each communication peer must support at least one",
        defaultValue = "${RaVerifierDummy2.RA_VERIFIER_DUMMY2_ID}|${RaVerifierDummy.RA_VERIFIER_DUMMY_ID}"
    )
    @Deprecated("Deprecated in favor of idscp2Configuration")
    override var expectedRaSuites: String =
        "${RaVerifierDummy2.RA_VERIFIER_DUMMY2_ID}|${RaVerifierDummy.RA_VERIFIER_DUMMY_ID}"

    @UriParam(
        label = "common",
        description = "Regex for Camel Headers to transfer/copy to/from IDSCP2 via \"extraHeaders\"",
        defaultValue = ""
    )
    var copyHeadersRegex: String? = null

    val copyHeadersRegexObject: Regex? by lazy {
        copyHeadersRegex?.let { Regex(it) }
    }

    @Synchronized
    fun addConsumer(consumer: Idscp2ServerConsumer) {
        consumers.add(consumer)
        if (useIdsMessages) {
            server?.allConnections?.forEach { it.addIdsMessageListener(consumer) }
        } else {
            server?.allConnections?.forEach { it.addGenericMessageListener(consumer) }
        }
    }

    @Synchronized
    fun removeConsumer(consumer: Idscp2ServerConsumer) {
        if (useIdsMessages) {
            server?.allConnections?.forEach { it.removeIdsMessageListener(consumer) }
        } else {
            server?.allConnections?.forEach { it.removeGenericMessageListener(consumer) }
        }
        consumers.remove(consumer)
    }

    @Synchronized
    fun sendMessage(header: Any?, body: ByteArray?, extraHeaders: Map<String, String>?) {
        server?.let { server ->
            server.allConnections.forEach { connection ->
                if (useIdsMessages) {
                    connection.sendIdsMessage(
                        header?.let { Utils.finalizeMessage(it, connection) },
                        body,
                        extraHeaders
                    )
                } else {
                    connection.sendGenericMessage(header?.toString(), body, extraHeaders)
                }
            }
        }
    }

    @Synchronized
    override fun createProducer(): Producer = Idscp2ServerProducer(this)

    @Synchronized
    override fun createConsumer(processor: Processor): Consumer = Idscp2ServerConsumer(this, processor)

    @Synchronized
    override fun onConnection(connection: AppLayerConnection) {
        if (LOG.isDebugEnabled) {
            LOG.debug("New IDSCP2 connection on $endpointUri, register consumer listeners")
        }
        if (useIdsMessages) {
            consumers.forEach { connection.addIdsMessageListener(it) }
        } else {
            consumers.forEach { connection.addGenericMessageListener(it) }
        }
        // notify connection listeners
        ListenerManager.publishConnectionEvent(connection, this)
        // Handle connection errors and closing
        connection.addConnectionListener(object : Idscp2ConnectionListener {
            override fun onError(t: Throwable) {
                LOG.error("Error in Idscp2ServerEndpoint-managed connection", t)
            }

            override fun onClose() {
                if (useIdsMessages) {
                    consumers.forEach { connection.removeIdsMessageListener(it) }
                } else {
                    consumers.forEach { connection.removeGenericMessageListener(it) }
                }
            }
        })
    }

    @Synchronized
    public override fun doStart() {
        if (LOG.isDebugEnabled) {
            LOG.debug("Starting IDSCP2 server endpoint $endpointUri")
        }

        this.doCommonEndpointConfiguration {
            if (!tlsClientHostnameVerification) {
                it.unsafeDisableHostnameVerification()
            }
        }

        (component as Idscp2ServerComponent).getServer(
            requireNotNull(idscp2Configuration) { "Lifecycle error: idscp2Configuration is null" },
            secureChannelConfiguration,
            useIdsMessages
        ).let {
            server = it
            // Add this endpoint to this server's Idscp2EndpointListener set
            it.addEndpointListener(this)
        }
    }

    @Synchronized
    public override fun doStop() {
        if (LOG.isDebugEnabled) {
            LOG.debug("Stopping IDSCP2 server endpoint $endpointUri")
        }
        // Remove this endpoint from the server's Idscp2EndpointListener set
        server?.removeEndpointListener(this)
        idscp2Configuration?.let {
            (component as Idscp2ServerComponent).freeServer(it)
        }
    }

    companion object {
        private val LOG = LoggerFactory.getLogger(Idscp2ServerEndpoint::class.java)
    }
}
