package de.fhg.aisec.ids.idscp2.example

import de.fhg.aisec.ids.idscp2.default_drivers.daps.aisec_daps.DefaultDapsDriver
import de.fhg.aisec.ids.idscp2.default_drivers.daps.aisec_daps.DefaultDapsDriverConfig
import de.fhg.aisec.ids.idscp2.default_drivers.daps.aisec_daps.SecurityProfile
import de.fhg.aisec.ids.idscp2.default_drivers.daps.aisec_daps.SecurityRequirements
import de.fhg.aisec.ids.idscp2.default_drivers.rat.dummy.RatProverDummy
import de.fhg.aisec.ids.idscp2.default_drivers.rat.dummy.RatVerifierDummy
import de.fhg.aisec.ids.idscp2.default_drivers.secure_channel.tlsv1_3.NativeTlsConfiguration
import de.fhg.aisec.ids.idscp2.idscp_core.api.configuration.AttestationConfig
import de.fhg.aisec.ids.idscp2.idscp_core.api.configuration.Idscp2Configuration
import java.nio.file.Paths
import java.util.*

object RunTLSClient {
    @JvmStatic
    fun main(args: Array<String>) {

        val keyStorePath = Paths.get(Objects.requireNonNull(RunTLSClient::class.java.classLoader
                .getResource("ssl/consumer-keystore.p12")).path)

        val trustStorePath = Paths.get(Objects.requireNonNull(RunTLSClient::class.java.classLoader
                .getResource("ssl/truststore.p12")).path)

        val localAttestationConfig = AttestationConfig.Builder()
                .setSupportedRatSuite(arrayOf(RatProverDummy.RAT_PROVER_DUMMY_ID))
                .setExpectedRatSuite(arrayOf(RatVerifierDummy.RAT_VERIFIER_DUMMY_ID))
                .setRatTimeoutDelay(300 * 1000) // 300 seconds
                .build()

        // create daps driver
        val securityRequirements = SecurityRequirements.Builder()
                .setRequiredSecurityLevel(SecurityProfile.TRUSTED)
                .build()

        val dapsDriver = DefaultDapsDriver(DefaultDapsDriverConfig.Builder()
                .setKeyStorePath(keyStorePath)
                .setTrustStorePath(trustStorePath)
                .setDapsUrl("https://daps.aisec.fraunhofer.de")
                .setSecurityRequirements(securityRequirements)
                .build())

        // create idscp2 config
        val settings = Idscp2Configuration.Builder()
                .setAckTimeoutDelay(500) //  500 ms
                .setHandshakeTimeoutDelay(5 * 1000) // 5 seconds
                .setAttestationConfig(localAttestationConfig)
                .setDapsDriver(dapsDriver)
                .build()

        // create secureChannel config
        val nativeTlsConfiguration = NativeTlsConfiguration.Builder()
                .setKeyStorePath(keyStorePath)
                .setTrustStorePath(trustStorePath)
                .setCertificateAlias("1.0.1")
                .setHost("provider-core")
                .build()

        val initiator = Idscp2ClientInitiator()
        initiator.init(settings, nativeTlsConfiguration)
    }
}