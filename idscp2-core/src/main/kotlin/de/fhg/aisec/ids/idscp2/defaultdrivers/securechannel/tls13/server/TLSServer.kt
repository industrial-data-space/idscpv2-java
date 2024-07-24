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
package de.fhg.aisec.ids.idscp2.defaultdrivers.securechannel.tls13.server

import de.fhg.aisec.ids.idscp2.api.configuration.Idscp2Configuration
import de.fhg.aisec.ids.idscp2.api.connection.Idscp2Connection
import de.fhg.aisec.ids.idscp2.api.drivers.SecureServer
import de.fhg.aisec.ids.idscp2.api.fsm.FSM
import de.fhg.aisec.ids.idscp2.api.server.ServerConnectionListener
import de.fhg.aisec.ids.idscp2.defaultdrivers.securechannel.tls13.NativeTlsConfiguration
import de.fhg.aisec.ids.idscp2.defaultdrivers.securechannel.tls13.TLSConstants
import de.fhg.aisec.ids.idscp2.keystores.PreConfiguration
import org.slf4j.LoggerFactory
import java.io.IOException
import java.net.ServerSocket
import java.net.SocketException
import java.net.SocketTimeoutException
import java.util.concurrent.CompletableFuture
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLServerSocket
import javax.net.ssl.SSLSocket

/**
 * A TLS Server that listens on a given port from the Idscp2Settings and create new
 * TLSServerThreads for incoming connections
 *
 * @author Leon Beckmann (leon.beckmann@aisec.fraunhofer.de)
 */
class TLSServer<CC : Idscp2Connection>(
    private val connectionListenerPromise: CompletableFuture<ServerConnectionListener<CC>>,
    private val nativeTlsConfiguration: NativeTlsConfiguration,
    private val serverConfiguration: Idscp2Configuration,
    private val connectionFactory: (FSM, String) -> CC
) : Runnable,
    SecureServer {

    @Volatile
    override var isRunning = false
        private set
    private val serverSocket: ServerSocket
    private val serverThread: Thread

    override fun run() {
        if (serverSocket.isClosed) {
            LOG.warn("ServerSocket has been closed, server thread is stopping now.")
            return
        }
        isRunning = true
        if (LOG.isTraceEnabled) {
            LOG.trace("TLS server started, entering accept() loop...")
        }
        while (isRunning) {
            try {
                /*
                 * accept for new (incoming) ssl sockets. A timeout exception is thrown
                 * after x seconds of inactivity to allow a clean stop via the safeStop() method
                 */
                val sslSocket = serverSocket.accept() as SSLSocket

                try {
                    if (LOG.isTraceEnabled) {
                        LOG.trace("New TLS client has connected. Creating new server thread...")
                    }

                    // create a connection future that will give the new idscp2 connection to the idscp2 server
                    val connectionFuture = CompletableFuture<CC>()
                    connectionFuture.thenAccept { connection ->
                        connectionListenerPromise.thenAccept { it.onConnectionCreated(connection) }
                    }.exceptionally {
                        // either the TLS handshake or the idscp2 handshake failed, both will clean up the server thread
                        LOG.warn("Idscp2Connection creation failed", it)
                        null
                    }

                    // Create a connection future that will register the connection to the server and notify the user
                    TLSServerThread(
                        sslSocket,
                        connectionFuture,
                        nativeTlsConfiguration,
                        serverConfiguration,
                        connectionFactory
                    )
                } catch (serverThreadException: Exception) {
                    LOG.warn("Error while creating/starting TLSServerThread", serverThreadException)
                }
            } catch (e: SocketTimeoutException) {
                // timeout on serverSocket blocking functions was reached
                // in this way we can catch safeStop() function, that makes isRunning false
                // without closing the serverSocket, so we can stop and restart the server
                // alternative: close serverSocket. But then we cannot reuse it
            } catch (e: SocketException) {
                if (LOG.isTraceEnabled) {
                    LOG.trace("Server socket has been closed.")
                }
                isRunning = false
            } catch (e: IOException) {
                LOG.warn("Error during TLS server socket accept, notifying error handlers...")
                isRunning = false
            }
        }
        if (!serverSocket.isClosed) {
            try {
                serverSocket.close()
            } catch (e: IOException) {
                LOG.warn("Cannot close TLS server socket", e)
            }
        }
    }

    override fun safeStop() {
        if (LOG.isTraceEnabled) {
            LOG.trace("Stopping tls server")
        }

        /*
         * Set the volatile running variable to false. The serverSocket will receive
         * a socket timeout after at least 5 seconds while it is blocked in accept()
         * and will then check again if isRunning is still true
         */
        isRunning = false

        try {
            serverThread.join()
        } catch (e: InterruptedException) {
            LOG.warn("InterruptedException whilst waiting for server stop", e)
            Thread.currentThread().interrupt()
        }
    }

    companion object {
        private val LOG = LoggerFactory.getLogger(TLSServer::class.java)
    }

    init {

        /* init server for TCP/TLS communication */

        // Get array of TrustManagers, that contains only one instance of X509ExtendedTrustManager,
        // which enables host verification and algorithm constraints
        if (LOG.isTraceEnabled) {
            LOG.trace("Creating trust manager for TLS server...")
        }
        val myTrustManager = nativeTlsConfiguration.trustManager

        // Get array of KeyManagers, that contains only one instance of X509ExtendedKeyManager,
        // which enables connection specific key selection via key alias
        if (LOG.isTraceEnabled) {
            LOG.trace("Creating key manager for TLS server...")
        }
        val myKeyManager = PreConfiguration.getX509ExtKeyManager(
            nativeTlsConfiguration.keyPassword,
            nativeTlsConfiguration.keyStorePath,
            nativeTlsConfiguration.keyStorePassword
        )

        if (LOG.isTraceEnabled) {
            LOG.trace("Setting TLS security attributes and creating TLS server socket...")
        }
        // Create TLS context based on keyManager and trustManager
        val sslContext = SSLContext.getInstance(TLSConstants.TLS_INSTANCE)
        sslContext.init(myKeyManager, arrayOf(myTrustManager), null)
        val socketFactory = sslContext.serverSocketFactory
        serverSocket = socketFactory.createServerSocket(nativeTlsConfiguration.serverPort)
        // Set timeout for serverSocket.accept()
        serverSocket.soTimeout = nativeTlsConfiguration.socketTimeout
        val sslServerSocket = serverSocket as SSLServerSocket

        // Set TLS constraints
        val sslParameters = sslServerSocket.sslParameters
        sslParameters.useCipherSuitesOrder = true // server determines priority-order of algorithms in CipherSuite
        sslParameters.needClientAuth = true // client must authenticate
        sslParameters.protocols = TLSConstants.TLS_ENABLED_PROTOCOLS // only TLSv1.3
        sslParameters.cipherSuites = TLSConstants.TLS_ENABLED_CIPHERS // only allow strong cipher suite
        sslServerSocket.sslParameters = sslParameters

        if (LOG.isTraceEnabled) {
            LOG.trace("Starting TLS server...")
        }
        serverThread = Thread.ofVirtual().name("TLS Server Thread " +
            nativeTlsConfiguration.host + ":" + nativeTlsConfiguration.serverPort).start(this)
    }
}
