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
package de.fhg.aisec.ids.idscp2.defaultdrivers.securechannel.tls13.client

import de.fhg.aisec.ids.idscp2.api.configuration.Idscp2Configuration
import de.fhg.aisec.ids.idscp2.api.connection.Idscp2Connection
import de.fhg.aisec.ids.idscp2.api.drivers.SecureChannelEndpoint
import de.fhg.aisec.ids.idscp2.api.error.Idscp2Exception
import de.fhg.aisec.ids.idscp2.api.fsm.FSM
import de.fhg.aisec.ids.idscp2.api.securechannel.SecureChannelListener
import de.fhg.aisec.ids.idscp2.core.fsm.AsyncIdscp2Factory
import de.fhg.aisec.ids.idscp2.core.securechannel.SecureChannel
import de.fhg.aisec.ids.idscp2.defaultdrivers.securechannel.tls13.NativeTlsConfiguration
import de.fhg.aisec.ids.idscp2.defaultdrivers.securechannel.tls13.TLSConstants
import de.fhg.aisec.ids.idscp2.defaultdrivers.securechannel.tls13.TLSSessionVerificationHelper
import de.fhg.aisec.ids.idscp2.keystores.PreConfiguration
import org.slf4j.LoggerFactory
import java.io.DataOutputStream
import java.io.IOException
import java.net.InetSocketAddress
import java.net.Socket
import java.security.cert.X509Certificate
import java.util.concurrent.CompletableFuture
import javax.net.ssl.HandshakeCompletedEvent
import javax.net.ssl.HandshakeCompletedListener
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLHandshakeException
import javax.net.ssl.SSLPeerUnverifiedException
import javax.net.ssl.SSLProtocolException
import javax.net.ssl.SSLSocket

/**
 * A TLS Client that notifies an Idscp2ServerFactory when a secure channel was created and the
 * TLS handshake is done. The client is notified from an InputListenerThread when new data are
 * available and transfer it to the SecureChannelListener
 *
 * @author Leon Beckmann (leon.beckmann@aisec.fraunhofer.de)
 */
class TLSClient<CC : Idscp2Connection>(
    private val connectionFactory: (FSM, String) -> CC,
    private val clientConfiguration: Idscp2Configuration,
    private val nativeTlsConfiguration: NativeTlsConfiguration,
    private val connectionFuture: CompletableFuture<CC>
) : HandshakeCompletedListener,
    DataAvailableListener,
    SecureChannelEndpoint {
    private val clientSocket: Socket
    private lateinit var dataOutputStream: DataOutputStream
    private lateinit var inputListenerThread: InputListenerThread
    private val listenerPromise = CompletableFuture<SecureChannelListener>()
    private var remotePeer = "NotConnected"

    /**
     * Connect to TLS server and start TLS Handshake. When an exception is thrown
     * in connect() the NativeTlsDriver will catch it and complete the connection
     * future with an Exception.
     *
     * This should not make the server maintain a broken connection, since either
     * the TLS handshake or the IDSCP2 handshake will fail on server side, which
     * will trigger a full connection cleanup.
     */
    fun connect(hostname: String, port: Int) {
        val sslSocket = clientSocket as SSLSocket?

        if (sslSocket == null || sslSocket.isClosed) {
            throw Idscp2Exception("Client socket is not available")
        }
        try {
            sslSocket.connect(InetSocketAddress(hostname, port))
            if (LOG.isTraceEnabled) {
                LOG.trace("Client is connected to server {}:{}", hostname, port)
            }

            // set clientSocket timeout to allow safeStop()
            clientSocket.soTimeout = nativeTlsConfiguration.socketTimeout
            dataOutputStream = DataOutputStream(clientSocket.getOutputStream())

            // Add inputListener but start it not before handshake is complete
            inputListenerThread =
                InputListenerThread("IDSCP2-Client-Worker-$hostname:$port", clientSocket.getInputStream(), this)

            if (LOG.isTraceEnabled) {
                LOG.trace("Start TLS Handshake")
            }
            sslSocket.addHandshakeCompletedListener(this)
            sslSocket.startHandshake()
        } catch (e: SSLHandshakeException) {
            cleanup()
            throw Idscp2Exception("TLS Handshake failed", e)
        } catch (e: SSLProtocolException) {
            cleanup()
            throw Idscp2Exception("TLS Handshake failed", e)
        } catch (e: IOException) {
            cleanup()
            throw Idscp2Exception("Connecting TLS client to server failed", e)
        }
    }

    /**
     * This function is either used for cleaning up broken TLS connections after handshake failure
     * or hostname verification failure. At this stage, the input listener has not started
     * yet and the secure channel has not been registered as listener promise yet.
     *
     * Or it is used for closing the TLS connection from the FSM on FSM shutdown. In this case, the
     * input listener is available.
     */
    private fun cleanup() {
        if (LOG.isTraceEnabled) {
            LOG.trace("Cleanup TLS connection...")
        }
        if (::inputListenerThread.isInitialized) {
            inputListenerThread.safeStop()
        }
        if (!clientSocket.isClosed) {
            try {
                clientSocket.close()
            } catch (e: IOException) {
                // we do not want to transmit an error here, since the secure channel might not be
                // established yet and an error after FSM shutdown will be ignored.
            }
        }
    }

    override fun onClose() {
        listenerPromise.thenAccept { obj: SecureChannelListener -> obj.onClose() }
    }

    override fun onError(e: Throwable) {
        listenerPromise.thenAccept { listener: SecureChannelListener -> listener.onError(e) }
    }

    override fun onMessage(bytes: ByteArray) {
        listenerPromise.thenAccept { listener: SecureChannelListener -> listener.onMessage(bytes) }
    }

    override fun close() {
        cleanup()
    }

    override fun send(bytes: ByteArray): Boolean = if (!isConnected) {
        LOG.warn("Client cannot send data because TLS socket is not connected")
        false
    } else if (!inputListenerThread.running) {
        LOG.debug("Client cannot send data because socket is not in running state anymore.")
        false
    } else {
        try {
            LOG.trace("Client is sending message...")
            dataOutputStream.run {
                writeInt(bytes.size)
                write(bytes)
                flush()
            }
            true
        } catch (e: Exception) {
            LOG.warn("Client could not send data", e)
            false
        }
    }

    override val isConnected: Boolean
        get() = clientSocket.isConnected

    override fun remotePeer(): String = remotePeer

    override fun handshakeCompleted(handshakeCompletedEvent: HandshakeCompletedEvent) {
        // start receiving listener after TLS Handshake was successful
        if (LOG.isTraceEnabled) {
            LOG.trace("TLS Handshake was successful")
        }

        // check if connection future has been cancelled by the user
        if (connectionFuture.isCancelled) {
            cleanup()
            return
        }

        // verify tls session on application layer: hostname verification, certificate validity
        try {
            val sslSession = handshakeCompletedEvent.session

            // get peer certificate
            val certificates = sslSession.peerCertificates
            if (certificates.isEmpty()) {
                throw SSLPeerUnverifiedException("Missing peer certificate")
            }
            val peerCert = certificates[0] as X509Certificate

            TLSSessionVerificationHelper.verifyTlsSession(
                sslSession.peerHost,
                sslSession.peerPort,
                peerCert,
                nativeTlsConfiguration.hostnameVerificationEnabled
            )
            if (LOG.isTraceEnabled) {
                LOG.trace("TLS session is valid")
            }
            remotePeer = "${sslSession.peerHost}:${sslSession.peerPort}"

            // Create secure channel, register secure channel as message listener and notify IDSCP2 Configuration
            val secureChannel = SecureChannel(this, peerCert)

            // Set the secure channel to this endpoint
            listenerPromise.complete(secureChannel)

            // Initiate idscp2 connection asynchronously. The connection will be created using the future.
            val success = AsyncIdscp2Factory.initiateIdscp2Connection(
                secureChannel,
                clientConfiguration,
                connectionFactory,
                connectionFuture
            )

            // Start the listener thread when the future was not cancelled
            if (success) {
                inputListenerThread.start()
            }
        } catch (e: Exception) {
            cleanup() // the server will not maintain a broken connection, since FSM handshake would timeout
            connectionFuture.completeExceptionally(
                Idscp2Exception("TLS session was not valid", e)
            )
        }
    }

    companion object {
        private val LOG = LoggerFactory.getLogger(TLSClient::class.java)
    }

    init {
        // init TLS Client

        // get array of TrustManagers, that contains only one instance of X509ExtendedTrustManager, which enables
        // hostVerification and algorithm constraints
        val myTrustManager = nativeTlsConfiguration.trustManager

        // get array of KeyManagers, that contains only one instance of X509ExtendedKeyManager, which enables
        // connection specific key selection via key alias
        val myKeyManager = PreConfiguration.getX509ExtKeyManager(
            nativeTlsConfiguration.keyPassword,
            nativeTlsConfiguration.keyStorePath,
            nativeTlsConfiguration.keyStorePassword
        )
        val sslContext = SSLContext.getInstance(TLSConstants.TLS_INSTANCE)
        sslContext.init(myKeyManager, arrayOf(myTrustManager), null)
        val socketFactory = sslContext.socketFactory

        // create server socket
        clientSocket = socketFactory.createSocket()
        val sslSocket = clientSocket as SSLSocket

        // set TLS constraints
        val sslParameters = sslSocket.sslParameters
        sslParameters.useCipherSuitesOrder = false // use server priority order
        sslParameters.needClientAuth = true
        sslParameters.protocols = TLSConstants.TLS_ENABLED_PROTOCOLS // only TLSv1.3
        sslParameters.cipherSuites = TLSConstants.TLS_ENABLED_CIPHERS // only allow strong cipher
//        sslParameters.endpointIdentificationAlgorithm = "HTTPS";  // is done in application layer
        sslSocket.sslParameters = sslParameters
        if (LOG.isTraceEnabled) {
            LOG.trace("TLS Client was initialized successfully")
        }
    }
}
