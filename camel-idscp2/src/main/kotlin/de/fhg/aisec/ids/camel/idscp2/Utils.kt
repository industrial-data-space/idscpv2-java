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
package de.fhg.aisec.ids.camel.idscp2

import de.fhg.aisec.ids.idscp2.api.configuration.AttestationConfig
import de.fhg.aisec.ids.idscp2.api.configuration.Idscp2Configuration
import de.fhg.aisec.ids.idscp2.api.connection.Idscp2Connection
import de.fhg.aisec.ids.idscp2.daps.aisecdaps.AisecDapsDriver
import de.fhg.aisec.ids.idscp2.daps.aisecdaps.AisecDapsDriverConfig
import de.fhg.aisec.ids.idscp2.defaultdrivers.securechannel.tls13.NativeTlsConfiguration
import de.fhg.aisec.ids.idscp2.keystores.KeyStoreUtil
import de.fraunhofer.iais.eis.DynamicAttributeToken
import de.fraunhofer.iais.eis.DynamicAttributeTokenBuilder
import de.fraunhofer.iais.eis.Message
import de.fraunhofer.iais.eis.TokenFormat
import org.apache.camel.support.jsse.SSLContextParameters
import org.slf4j.Logger
import org.slf4j.LoggerFactory
import java.net.URI
import java.nio.charset.StandardCharsets
import java.nio.file.Paths
import java.util.GregorianCalendar
import java.util.regex.Pattern
import javax.net.ssl.X509TrustManager
import javax.xml.datatype.DatatypeFactory
import javax.xml.datatype.XMLGregorianCalendar

object Utils {
    private val LOG: Logger = LoggerFactory.getLogger(Utils::class.java)

    lateinit var senderAgentProducer: () -> URI
    lateinit var issuerProducer: () -> URI

    @Suppress("MemberVisibilityCanBePrivate")
    lateinit var infomodelVersion: String
    var dapsUrlProducer: () -> String = { Constants.DEFAULT_DAPS_URL }

    @Suppress("MemberVisibilityCanBePrivate")
    fun createGregorianCalendarTimestamp(timeInput: Long): XMLGregorianCalendar =
        DatatypeFactory.newInstance().newXMLGregorianCalendar(
            GregorianCalendar().apply { timeInMillis = timeInput }
        )

    fun finalizeMessage(messageBuilder: Any, connection: Idscp2Connection): Message {
        if (messageBuilder is Message) {
            if (LOG.isDebugEnabled) {
                LOG.debug(
                    "Object passed to finalizeMessage is already a Message, MessageBuilder is required. " +
                        "No methods will be called."
                )
            }
            return messageBuilder
        }
        try {
            if (LOG.isDebugEnabled) {
                LOG.debug("Finalizing IDS MessageBuilder object...")
            }
            messageBuilder::class.java.apply {
                getMethod("_securityToken_", DynamicAttributeToken::class.java)
                    .invoke(
                        messageBuilder,
                        DynamicAttributeTokenBuilder()
                            ._tokenFormat_(TokenFormat.JWT)
                            ._tokenValue_(String(connection.localDat, StandardCharsets.UTF_8))
                            .build()
                    )
                getMethod("_senderAgent_", URI::class.java).invoke(messageBuilder, senderAgentProducer())
                getMethod("_issuerConnector_", URI::class.java).invoke(messageBuilder, issuerProducer())
                getMethod("_issued_", XMLGregorianCalendar::class.java)
                    .invoke(messageBuilder, createGregorianCalendarTimestamp(System.currentTimeMillis()))
                getMethod("_modelVersion_", String::class.java).invoke(messageBuilder, infomodelVersion)
                val message = getMethod("build").invoke(messageBuilder)
                if (message !is Message) {
                    throw CamelIdscp2Exception(
                        "InfoModel message build failed! build() did not return a Message object!"
                    )
                }
                return message
            }
        } catch (upa: UninitializedPropertyAccessException) {
            throw CamelIdscp2Exception(
                "At least one property of de.fhg.aisec.ids.camel.idscp2.Utils has not been " +
                    "properly initialized. This is a mandatory requirement for initialization " +
                    "of IDSCP Messages within the IDSCP2 Camel Adapter!",
                upa
            )
        } catch (t: Throwable) {
            throw CamelIdscp2Exception(
                "Failed to finalize IDS MessageBuilder, " +
                    "the object passed as IDSCP2 header must be an IDS MessageBuilder.",
                t
            )
        }
    }
}

val URI_REGEX: Pattern = Pattern.compile("(.*?)(?::(\\d+))?/?$")

fun Idscp2Endpoint.doCommonEndpointConfiguration(
    secureChannelConfigurationBlock: ((NativeTlsConfiguration.Builder) -> Unit)? = null
) {
    // Use the provided NativeTlsConfiguration.Builder, or create a new one
    val secureChannelConfigBuilder = secureChannelConfigurationBuilder ?: run { NativeTlsConfiguration.Builder() }

    val transportSslContextParameters = transportSslContextParameters ?: sslContextParameters
    // If no Builder has been passed, perform configuration based on passed individual parameters
    if (secureChannelConfigurationBuilder == null) {
        transportSslContextParameters?.let {
            secureChannelConfigBuilder.applySslContextParameters(it)
        }
    }

    // Always set (or overwrite) the host and port with information passed by component URI
    val remainingMatcher = URI_REGEX.matcher(remaining)
    require(remainingMatcher.matches()) { "$remaining is not a valid URI remainder, must be \"host:port\"." }
    val matchResult = remainingMatcher.toMatchResult()
    val host = matchResult.group(1)
    val port = matchResult.group(2)?.toInt() ?: NativeTlsConfiguration.DEFAULT_SERVER_PORT
    secureChannelConfigBuilder.setHost(host).setServerPort(port)
    // Always execute secureChannelConfigurationBlock (hostname verification cannot be disabled via beans)
    secureChannelConfigurationBlock?.invoke(secureChannelConfigBuilder)
    // Finalize the NativeTlsConfiguration
    secureChannelConfiguration = secureChannelConfigBuilder.build()

    if (idscp2Configuration == null) {
        // create attestation config
        val localAttestationConfig = AttestationConfig.Builder()
            .setSupportedRaSuite(supportedRaSuites.split('|').toTypedArray())
            .setExpectedRaSuite(expectedRaSuites.split('|').toTypedArray())
            .setRaTimeoutDelay(dapsRaTimeoutDelay)
            .build()

        // create daps config
        val dapsDriverConfigBuilder = AisecDapsDriverConfig.Builder()
            .setDapsUrl(Utils.dapsUrlProducer())

        (dapsSslContextParameters ?: sslContextParameters)?.let {
            dapsDriverConfigBuilder.applySslContextParameters(it, transportSslContextParameters)
        }

        // create idscp config
        idscp2Configuration = Idscp2Configuration.Builder()
            .setAttestationConfig(localAttestationConfig)
            .setDapsDriver(AisecDapsDriver(dapsDriverConfigBuilder.build()))
            .build()
    }
}

fun NativeTlsConfiguration.Builder.applySslContextParameters(
    sslContextParameters: SSLContextParameters
): NativeTlsConfiguration.Builder = apply {
    sslContextParameters.let { scp ->
        setKeyPassword(
            scp.keyManagers?.keyPassword?.toCharArray()
                ?: "password".toCharArray()
        )
        scp.keyManagers?.keyStore?.resource?.let { setKeyStorePath(Paths.get(it)) }
        scp.keyManagers?.keyStore?.type?.let { setKeyStoreKeyType(it) }
        setKeyStorePassword(
            scp.keyManagers?.keyStore?.password?.toCharArray()
                ?: "password".toCharArray()
        )
        scp.trustManagers?.trustManager?.let { setTrustManager(it as X509TrustManager) }
        scp.trustManagers?.keyStore?.resource?.let { setTrustStorePath(Paths.get(it)) }
        setTrustStorePassword(
            scp.trustManagers?.keyStore?.password?.toCharArray()
                ?: "password".toCharArray()
        )
        setCertificateAlias(scp.certAlias ?: "1")
    }
}

fun AisecDapsDriverConfig.Builder.applySslContextParameters(
    dapsSslContextParameters: SSLContextParameters,
    transportSslContextParameters: SSLContextParameters? = null
): AisecDapsDriverConfig.Builder = apply {
    dapsSslContextParameters.let { scp ->
        setKeyPassword(
            scp.keyManagers?.keyPassword?.toCharArray()
                ?: "password".toCharArray()
        )
        scp.keyManagers?.keyStore?.resource?.let { setKeyStorePath(Paths.get(it)) }
        setKeyStorePassword(
            scp.keyManagers?.keyStore?.password?.toCharArray()
                ?: "password".toCharArray()
        )
        scp.trustManagers?.trustManager?.let { setTrustManager(it) }
        scp.trustManagers?.keyStore?.resource?.let { setTrustStorePath(Paths.get(it)) }
        setTrustStorePassword(
            scp.trustManagers?.keyStore?.password?.toCharArray()
                ?: "password".toCharArray()
        )
        setKeyAlias(scp.certAlias ?: "1")
    }
    // Load transport SSL certificates and create fingerprints
    transportSslContextParameters?.let { scp ->
        scp.keyManagers?.keyStore?.resource?.let { Paths.get(it) }?.let { keyStorePath ->
            scp.keyManagers?.keyStore?.password?.toCharArray()?.let { keyStorePassword ->
                val ks = KeyStoreUtil.loadKeyStore(keyStorePath, keyStorePassword)
                loadTransportCertsFromKeystore(ks)
            }
        }
    }
}
