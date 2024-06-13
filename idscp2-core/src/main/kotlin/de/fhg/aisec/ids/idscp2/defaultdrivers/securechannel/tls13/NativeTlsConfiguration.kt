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
package de.fhg.aisec.ids.idscp2.defaultdrivers.securechannel.tls13

import de.fhg.aisec.ids.idscp2.api.error.Idscp2Exception
import de.fhg.aisec.ids.idscp2.keystores.PreConfiguration
import java.nio.file.Path
import javax.net.ssl.X509TrustManager

/**
 * NativeTLS SecureChannel configuration class, contains information about NativeTLS stuff
 *
 * @author Leon Beckmann (leon.beckmann@aisec.fraunhofer.de)
 */
class NativeTlsConfiguration private constructor() {
    var serverPort = DEFAULT_SERVER_PORT
        private set
    var host = "localhost"
        private set
    private lateinit var trustStorePath: Path
    private lateinit var trustStorePassword: CharArray
    private var trustManagerInstance: X509TrustManager? = null
    lateinit var keyPassword: CharArray
        private set
    lateinit var keyStorePath: Path
        private set
    lateinit var keyStorePassword: CharArray
        private set
    lateinit var certificateAlias: String
        private set
    var keyStoreKeyType = "RSA"
        private set
    var socketTimeout: Int = DEFAULT_SOCKET_TIMEOUT
        private set
    var hostnameVerificationEnabled = true
        private set
    val trustManager by lazy {
        trustManagerInstance ?: PreConfiguration.getX509ExtTrustManager(trustStorePath, trustStorePassword)
    }

    class Builder {
        private val config = NativeTlsConfiguration()
        fun setHost(host: String): Builder {
            config.host = host
            return this
        }

        fun setServerPort(serverPort: Int): Builder {
            config.serverPort = serverPort
            return this
        }

        fun setTrustStorePath(path: Path): Builder {
            config.trustStorePath = path
            return this
        }

        fun setTrustStorePassword(pwd: CharArray): Builder {
            config.trustStorePassword = pwd
            return this
        }

        fun setTrustManager(trustManager: X509TrustManager): Builder {
            config.trustManagerInstance = trustManager
            return this
        }

        fun setKeyPassword(pwd: CharArray): Builder {
            config.keyPassword = pwd
            return this
        }

        fun setKeyStorePath(path: Path): Builder {
            config.keyStorePath = path
            return this
        }

        fun setKeyStorePassword(pwd: CharArray): Builder {
            config.keyStorePassword = pwd
            return this
        }

        fun setCertificateAlias(alias: String): Builder {
            config.certificateAlias = alias
            return this
        }

        fun setKeyStoreKeyType(keyType: String): Builder {
            config.keyStoreKeyType = keyType
            return this
        }

        fun setServerSocketTimeout(timeout: Int): Builder {
            config.socketTimeout = timeout
            return this
        }

        fun unsafeDisableHostnameVerification(): Builder {
            config.hostnameVerificationEnabled = false
            return this
        }

        fun build(): NativeTlsConfiguration {
            if (config.trustManagerInstance == null &&
                !(config::trustStorePath.isInitialized && config::trustStorePassword.isInitialized)
            ) {
                throw Idscp2Exception(
                    "Cannot build NativeTlsConfiguration: Neither trustManager, " +
                        "nor trustStorePath + trustStorePassword have been set!"
                )
            }
            if (!config::keyPassword.isInitialized) {
                throw Idscp2Exception("Cannot build NativeTlsConfiguration: keyPassword has not been set!")
            }
            if (!config::keyStorePath.isInitialized) {
                throw Idscp2Exception("Cannot build NativeTlsConfiguration: keyStorePath has not been set!")
            }
            if (!config::keyStorePassword.isInitialized) {
                throw Idscp2Exception("Cannot build NativeTlsConfiguration: keyStorePassword has not been set!")
            }
            if (!config::certificateAlias.isInitialized) {
                throw Idscp2Exception("Cannot build NativeTlsConfiguration: certificateAlias has not been set!")
            }
            return config
        }
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as NativeTlsConfiguration

        if (serverPort != other.serverPort) return false
        if (host != other.host) return false
        if (trustStorePath != other.trustStorePath) return false
        if (!trustStorePassword.contentEquals(other.trustStorePassword)) return false
        if (!keyPassword.contentEquals(other.keyPassword)) return false
        if (keyStorePath != other.keyStorePath) return false
        if (!keyStorePassword.contentEquals(other.keyStorePassword)) return false
        if (certificateAlias != other.certificateAlias) return false
        if (keyStoreKeyType != other.keyStoreKeyType) return false
        if (socketTimeout != other.socketTimeout) return false
        if (hostnameVerificationEnabled != other.hostnameVerificationEnabled) return false

        return true
    }

    override fun hashCode(): Int {
        var result = serverPort
        result = 31 * result + host.hashCode()
        result = 31 * result + trustStorePath.hashCode()
        result = 31 * result + trustStorePassword.contentHashCode()
        result = 31 * result + keyPassword.contentHashCode()
        result = 31 * result + keyStorePath.hashCode()
        result = 31 * result + keyStorePassword.contentHashCode()
        result = 31 * result + certificateAlias.hashCode()
        result = 31 * result + keyStoreKeyType.hashCode()
        result = 31 * result + socketTimeout.hashCode()
        result = 31 * result + hostnameVerificationEnabled.hashCode()
        return result
    }

    override fun toString(): String =
        "Idscp2Configuration(serverPort=$serverPort, host='$host', trustStorePath=$trustStorePath, " +
            "trustStorePassword=${trustStorePassword.contentToString()}, " +
            "keyStorePath=$keyStorePath, keyStorePassword=${keyStorePassword.contentToString()}, " +
            "certificateAlias='$certificateAlias', " +
            "keyStoreKeyType='$keyStoreKeyType', " + "socketTimeout='$socketTimeout', " +
            "hostnameVerificationEnabled='$hostnameVerificationEnabled'"

    companion object {
        const val DEFAULT_SERVER_PORT = 29292
        const val DEFAULT_SOCKET_TIMEOUT: Int = 5000
    }
}
