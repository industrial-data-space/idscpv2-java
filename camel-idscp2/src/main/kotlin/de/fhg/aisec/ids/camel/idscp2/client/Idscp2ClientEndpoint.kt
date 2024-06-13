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

package de.fhg.aisec.ids.camel.idscp2.client

import de.fhg.aisec.ids.camel.idscp2.Idscp2Endpoint
import de.fhg.aisec.ids.camel.idscp2.ListenerManager
import de.fhg.aisec.ids.camel.idscp2.RefCountingHashMap
import de.fhg.aisec.ids.camel.idscp2.doCommonEndpointConfiguration
import de.fhg.aisec.ids.idscp2.api.configuration.AttestationConfig
import de.fhg.aisec.ids.idscp2.api.configuration.Idscp2Configuration
import de.fhg.aisec.ids.idscp2.applayer.AppLayerConnection
import de.fhg.aisec.ids.idscp2.defaultdrivers.remoteattestation.dummy.RaProverDummy
import de.fhg.aisec.ids.idscp2.defaultdrivers.remoteattestation.dummy.RaProverDummy2
import de.fhg.aisec.ids.idscp2.defaultdrivers.remoteattestation.dummy.RaVerifierDummy
import de.fhg.aisec.ids.idscp2.defaultdrivers.remoteattestation.dummy.RaVerifierDummy2
import de.fhg.aisec.ids.idscp2.defaultdrivers.securechannel.tls13.NativeTLSDriver
import de.fhg.aisec.ids.idscp2.defaultdrivers.securechannel.tls13.NativeTlsConfiguration
import org.apache.camel.Processor
import org.apache.camel.Producer
import org.apache.camel.spi.UriEndpoint
import org.apache.camel.spi.UriParam
import org.apache.camel.support.DefaultEndpoint
import org.apache.camel.support.jsse.SSLContextParameters
import org.slf4j.LoggerFactory
import java.util.concurrent.CompletableFuture

@UriEndpoint(
    scheme = "idscp2client",
    title = "IDSCP2 Client Socket",
    syntax = "idscp2client://host:port",
    label = "ids"
)
class Idscp2ClientEndpoint(uri: String?, override val remaining: String, component: Idscp2ClientComponent?) :
    DefaultEndpoint(uri, component),
    Idscp2Endpoint {
    private val secureChannelDriver = NativeTLSDriver<AppLayerConnection>()

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
        description = "The validity time of remote attestation and DAT in milliseconds",
        defaultValue = "600000"
    )
    @Deprecated("Deprecated in favor of idscp2Configuration")
    override var dapsRaTimeoutDelay: Long = AttestationConfig.DEFAULT_RA_TIMEOUT_DELAY.toLong()

    @UriParam(
        label = "client",
        description = "Used to make N endpoints share the same connection, " +
            "e.g. for using a consumer to receive responses to the requests of another producer"
    )
    var connectionShareId: String? = null

    @UriParam(
        label = "client,producer",
        description = "Makes the client producer block and wait for a reply message from the server"
    )
    var awaitResponse: Boolean = false

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

    @UriParam(
        label = "client",
        description = "Max attempts to connect to the IDSCP2 server",
        defaultValue = "3"
    )
    var maxRetries: Long = 3

    @UriParam(
        label = "client",
        description = "Delay after an failed connection attempt to the server, in milliseconds",
        defaultValue = "5000"
    )
    var retryDelayMs: Long = 5000

    @UriParam(
        label = "client",
        description = "Timeout when waiting for a response, in milliseconds",
        defaultValue = "5000"
    )
    var responseTimeout: Long = 5000

    val copyHeadersRegexObject: Regex? by lazy {
        copyHeadersRegex?.let { Regex(it) }
    }

    private fun makeConnectionInternal(): CompletableFuture<AppLayerConnection> {
        if (LOG.isDebugEnabled) {
            LOG.debug("Creating new connection...")
        }
        return secureChannelDriver.connect(
            ::AppLayerConnection,
            requireNotNull(idscp2Configuration) { "Lifecycle error: idscp2Configuration is null" },
            secureChannelConfiguration
        ).thenApply { c ->
            if (useIdsMessages) {
                c.addIdsMessageListener { connection, header, _, _ ->
                    header?.let { ListenerManager.publishTransferContractEvent(connection, it.transferContract) }
                }
            }
            // Notify connection listeners
            ListenerManager.publishConnectionEvent(c, this)
            c
        }
    }

    fun makeConnection(): CompletableFuture<AppLayerConnection> = connectionShareId?.let {
        sharedConnections.computeIfAbsent(it) {
            makeConnectionInternal()
        }
    } ?: makeConnectionInternal()

    fun releaseConnection(connectionFuture: CompletableFuture<AppLayerConnection>) {
        connectionShareId?.let { sharedConnections.release(it) } ?: releaseConnectionInternal(connectionFuture)
    }

    fun resetConnection(
        connectionFuture: CompletableFuture<AppLayerConnection>
    ): CompletableFuture<AppLayerConnection> {
        connectionShareId?.let { sharedConnections.remove(it) } ?: releaseConnectionInternal(connectionFuture)
        return makeConnection()
    }

    override fun createProducer(): Producer = Idscp2ClientProducer(this)

    override fun createConsumer(processor: Processor): org.apache.camel.Consumer = Idscp2ClientConsumer(this, processor)

    public override fun doStart() {
        if (LOG.isDebugEnabled) {
            LOG.debug("Starting IDSCP2 client endpoint $endpointUri")
        }

        this.doCommonEndpointConfiguration()
    }

    public override fun doStop() {
        LOG.debug("Stopping IDSCP2 client endpoint $endpointUri")
    }

    companion object {
        private val LOG = LoggerFactory.getLogger(Idscp2ClientEndpoint::class.java)
        private val sharedConnections = RefCountingHashMap<String, CompletableFuture<AppLayerConnection>> {
            releaseConnectionInternal(it)
        }

        private fun releaseConnectionInternal(connectionFuture: CompletableFuture<AppLayerConnection>) {
            if (LOG.isDebugEnabled) {
                LOG.debug("Releasing connection...")
            }
            if (connectionFuture.isDone) {
                // Exceptional completion includes cancellation
                if (!connectionFuture.isCompletedExceptionally) {
                    connectionFuture.get().close()
                }
            } else {
                connectionFuture.cancel(true)
            }
        }
    }
}
