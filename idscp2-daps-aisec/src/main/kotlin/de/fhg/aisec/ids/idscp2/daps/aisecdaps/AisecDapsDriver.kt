/*-
 * ========================LICENSE_START=================================
 * idscp2-daps-aisec
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
package de.fhg.aisec.ids.idscp2.daps.aisecdaps

import com.fasterxml.jackson.databind.ObjectMapper
import de.fhg.aisec.ids.idscp2.api.drivers.DapsDriver
import de.fhg.aisec.ids.idscp2.api.drivers.VerifiedDat
import de.fhg.aisec.ids.idscp2.api.error.DatException
import de.fhg.aisec.ids.idscp2.api.toHexString
import de.fhg.aisec.ids.idscp2.keystores.PreConfiguration
import io.jsonwebtoken.Jwts
import io.ktor.client.HttpClient
import io.ktor.client.call.body
import io.ktor.client.engine.java.Java
import io.ktor.client.plugins.HttpRequestRetry
import io.ktor.client.plugins.HttpTimeout
import io.ktor.client.plugins.cache.HttpCache
import io.ktor.client.plugins.contentnegotiation.ContentNegotiation
import io.ktor.client.request.forms.submitForm
import io.ktor.client.request.request
import io.ktor.client.statement.bodyAsText
import io.ktor.http.HttpStatusCode
import io.ktor.http.Parameters
import io.ktor.http.cacheControl
import io.ktor.serialization.jackson.jackson
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.runBlocking
import org.bouncycastle.asn1.ASN1OctetString
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier
import org.bouncycastle.asn1.x509.Extension
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier
import org.jose4j.http.SimpleResponse
import org.jose4j.jwa.AlgorithmConstraints
import org.jose4j.jwk.HttpsJwks
import org.jose4j.jws.AlgorithmIdentifiers
import org.jose4j.jwt.JwtClaims
import org.jose4j.jwt.NumericDate
import org.jose4j.jwt.consumer.JwtConsumerBuilder
import org.jose4j.keys.resolvers.HttpsJwksVerificationKeyResolver
import org.slf4j.LoggerFactory
import java.net.URI
import java.nio.charset.StandardCharsets
import java.security.Key
import java.security.KeyManagementException
import java.security.NoSuchAlgorithmException
import java.security.cert.X509Certificate
import java.time.Instant
import java.util.Collections.synchronizedMap
import java.util.Date
import java.util.concurrent.locks.ReentrantLock
import javax.net.ssl.SSLContext
import javax.net.ssl.TrustManager
import kotlin.concurrent.withLock

/**
 * Default DAPS Driver Implementation for requesting valid dynamicAttributeToken and verifying DAT
 *
 * @author Michael Lux (michael.lux@aisec.fraunhofer.de)
 * @author Leon Beckmann (leon.beckmann@aisec.fraunhofer.de)
 * @author Gerd Brost (gerd.brost@aisec.fraunhofer.de)
 */
class AisecDapsDriver(private val config: AisecDapsDriverConfig) : DapsDriver {
    // Security requirements can be modified at runtime
    private var securityRequirements: SecurityRequirements? = config.securityRequirements
    private val privateKey: Key = PreConfiguration.getKey(
        config.keyStorePath,
        config.keyStorePassword,
        config.keyAlias,
        config.keyPassword
    )
    private val dapsUrl: String = config.dapsUrl
    private val localPeerCertificate: X509Certificate =
        PreConfiguration.getCertificate(
            config.keyStorePath,
            config.keyStorePassword,
            config.keyAlias
        )

    // requires hexLookup to be existent
    private val connectorUUID: String = extractConnectorUUID(localPeerCertificate)

    /**
     * The token, that will be issued until the renewalTime is over. This mechanism reduces the number
     * of DAPS requests which might be problematic for higher scaling peers.
     * When a connection is requesting a token when the renewalTime is over then the currentToken
     * will be overwritten by a new requested DAT from the DAPS. The new renewalTime is calculated by
     * the renewalThreshold:
     *
     * renewalTime = now + tokenValidityTime (in seconds) * renewalThreshold
     *
     * The threshold must be in (0;1]
     */
    private var currentToken: ByteArray = "INVALID_TOKEN".toByteArray()
    private var renewalTime: NumericDate = NumericDate.now()
    override val renewalThreshold = config.dapsTokenRenewalThreshold
    private val renewalLock = ReentrantLock(true)

    // create ssl socket factory for secure
    private val sslContext: SSLContext = try {
        SSLContext.getInstance("TLS").apply {
            init(null, arrayOf(config.trustManager), null)
        }
    } catch (e: NoSuchAlgorithmException) {
        LOG.error("Cannot init AisecDapsDriver", e)
        throw RuntimeException(e)
    } catch (e: KeyManagementException) {
        LOG.error("Cannot init AisecDapsDriver", e)
        throw RuntimeException(e)
    }

    /**
     * Ktor HTTP client for DAPS communication
     */
    private val httpClient = HTTP_CLIENTS.computeIfAbsent(config.trustManager) {
        HttpClient(Java) {
            engine {
                config {
                    sslContext(sslContext)
                }
            }
            install(HttpCache)
            install(ContentNegotiation) {
                jackson()
            }
            install(HttpRequestRetry) {
                retryOnServerErrors(3)
                retryOnExceptionIf(3) { _, _ -> true }
                exponentialDelay()
            }
            // Should be installed AFTER HttpRequestRetry, see retryOnException() docs!
            install(HttpTimeout) {
                requestTimeoutMillis = 1500
            }
        }
    }

    /**
     * Extract connector UUID: SKI:keyid:AKI from X509 Certificate
     * @param certificate The certificate to extract the UUID from
     */
    private fun extractConnectorUUID(certificate: X509Certificate): String {
        // GET 2.5.29.35 AuthorityKeyIdentifier
        val akiOid = Extension.authorityKeyIdentifier.id
        val rawAuthorityKeyIdentifier = certificate.getExtensionValue(akiOid)
        val akiOc = ASN1OctetString.getInstance(rawAuthorityKeyIdentifier)
        val aki = AuthorityKeyIdentifier.getInstance(akiOc.octets)
        val authorityKeyIdentifier = aki.keyIdentifier
        val akiResult = authorityKeyIdentifier.toHexString(":").uppercase()

        // GET 2.5.29.14 SubjectKeyIdentifier
        val skiOid = Extension.subjectKeyIdentifier.id
        val rawSubjectKeyIdentifier = certificate.getExtensionValue(skiOid)
        val ski0c = ASN1OctetString.getInstance(rawSubjectKeyIdentifier)
        val ski = SubjectKeyIdentifier.getInstance(ski0c.octets)
        val subjectKeyIdentifier = ski.keyIdentifier
        val skiResult = subjectKeyIdentifier.toHexString(":").uppercase()

        if (LOG.isDebugEnabled) {
            LOG.debug("AKI: $akiResult")
            LOG.debug("SKI: $skiResult")
        }

        return "$skiResult:keyid:$akiResult"
    }

    /**
     * Cached DAPS metadata, also for instances not featuring /.well-known/oauth-authorization-server,
     * see below.
     */
    private var dapsMeta: DapsMeta? = null

    /**
     * Expiration timestamp for cached DAPS metadata, in ms
     */
    private var dapsMetaExpire = 0L

    private fun getDapsMeta(): DapsMeta {
        if (dapsMetaExpire > System.currentTimeMillis()) {
            dapsMeta?.let {
                if (LOG.isDebugEnabled) {
                    LOG.debug(
                        "Reusing DAPS meta, remaining validity: {} seconds",
                        (dapsMetaExpire - System.currentTimeMillis()) / 1000
                    )
                }
                return it
            }
        }

        val dapsUri = URI.create(dapsUrl)

        return runBlocking(Dispatchers.IO) {
            val response = httpClient.request(
                "${dapsUri.scheme}://${dapsUri.host}/.well-known/oauth-authorization-server${dapsUri.path}"
            )
            if (response.status.value in 200..299) {
                DapsMeta.fromJson(response.body()).also { dm ->
                    val maxAge = response.cacheControl()
                        .first { it.value.startsWith("max-age=") }
                        .value.split("=").getOrNull(1)?.toInt()
                    if (LOG.isTraceEnabled) {
                        LOG.trace("DAPS meta: Cache-Control max-age: $maxAge")
                    }
                    dapsMetaExpire = response.responseTime.timestamp + ((maxAge ?: 0) * 1000L)
                    dapsMeta = dm
                }
            } else {
                if (response.status == HttpStatusCode.NotFound) {
                    LOG.warn(
                        "DAPS /.well-known/oauth-authorization-server not available, using fallback URLs." +
                            " Next retry to fetch DAPS meta in ${META_FALLBACK_LIFETIME_MS / 1000} seconds"
                    )
                } else {
                    LOG.error("Request was not successful, unexpected HTTP status ${response.status}")
                }
                // Fallback, if request was not successful
                DapsMeta.fromDapsUrl(dapsUrl).also {
                    // Cache metadata only for acceptable 404 (not found) error
                    if (response.status == HttpStatusCode.NotFound) {
                        dapsMetaExpire = System.currentTimeMillis() + META_FALLBACK_LIFETIME_MS
                        dapsMeta = it
                    }
                }
            }
        }
    }

    /**
     * Receive the signed and valid dynamic attribute token from the DAPS
     *
     * @throws DatException
     */
    override val token: ByteArray
        get() = renewalLock.withLock {
            try {
                if (NumericDate.now().isBefore(renewalTime)) {
                    // the current token is still valid
                    if (LOG.isDebugEnabled) {
                        LOG.debug("Issue cached DAT: {}", currentToken.toString(StandardCharsets.UTF_8))
                    }
                    return currentToken
                }

                // request a new token from the DAPS
                if (LOG.isInfoEnabled) {
                    LOG.info("Retrieving Dynamic Attribute Token from DAPS ...")
                }
                if (LOG.isDebugEnabled) {
                    LOG.debug("ConnectorUUID: $connectorUUID")
                }

                // Get OAuth server meta information (Issuer, URLs)
                val dapsMeta = getDapsMeta()

                // create signed JWT
                val expiration = Date.from(Instant.now().plusSeconds(86400))
                val issuedAt = Date.from(Instant.now())
                val notBefore = Date.from(Instant.now())

                val jwt = Jwts.builder()
                    .issuer(connectorUUID)
                    .subject(connectorUUID)
                    .claim("@context", "https://w3id.org/idsa/contexts/context.jsonld")
                    .claim("@type", "ids:DatRequestToken")
                    .expiration(expiration)
                    .issuedAt(issuedAt)
                    .notBefore(notBefore)
                    .audience().add(dapsMeta.tokenEndpoint).and()
                    .signWith(privateKey)
                    .compact()

                return runBlocking(Dispatchers.IO) {
                    val response = httpClient.submitForm(
                        dapsMeta.tokenEndpoint,
                        formParameters = Parameters.build {
                            append("grant_type", "client_credentials")
                            append("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer")
                            append("client_assertion", jwt)
                            append("scope", "idsc:IDS_CONNECTOR_ATTRIBUTES_ALL")
                            config.transportCertsSha256?.let {
                                append(
                                    "claims",
                                    ObjectMapper().writeValueAsString(
                                        mapOf(
                                            "access_token" to mapOf(
                                                "transportCertsSha256" to mapOf(
                                                    "value" to it
                                                )
                                            )
                                        )
                                    )
                                )
                            }
                        }
                    )

                    // check for valid response
                    if (response.status != HttpStatusCode.OK) {
                        LOG.error(
                            "Failed to request token issued with parameters: Issuer: {}, Subject: {}, " +
                                "Expiration: {}, IssuedAt: {}, NotBefore: {}, Audience: {}, Response body: {}",
                            connectorUUID,
                            connectorUUID,
                            expiration,
                            issuedAt,
                            notBefore,
                            dapsMeta.tokenEndpoint,
                            response.bodyAsText()
                        )
                        throw DatException("Received non-200 status: ${response.status}")
                    }

                    val json: Map<String, Any> = response.body()
                    if (LOG.isDebugEnabled) {
                        LOG.debug("Acquired DAT from {}", dapsMeta.tokenEndpoint)
                    }

                    val token = if (json.containsKey("access_token")) {
                        json["access_token"].toString().also {
                            if (LOG.isDebugEnabled) {
                                LOG.debug("Received DAT from DAPS: {}", it)
                            }
                        }
                    } else if (json.containsKey("error")) {
                        throw DatException("DAPS reported error: ${json["error"]}")
                    } else {
                        throw DatException("DAPS response does not contain \"access_token\" or \"error\" field.")
                    }

                    innerVerifyToken(
                        token.toByteArray(StandardCharsets.UTF_8),
                        null,
                        null,
                        true,
                        dapsMeta
                    )
                    token.toByteArray(StandardCharsets.UTF_8)
                }
            } catch (e: Throwable) {
                throw if (e is DatException) {
                    e
                } else {
                    DatException("Error whilst retrieving DAT", e)
                }
            }
        }

    /**
     * Public verifyToken API, used from the IDSCP2 protocol. Security requirements are used from the DAPS config
     * Peer certificate is used for verifying DAT subject
     *
     * @return The number of seconds this DAT is valid
     * @throws DatException
     */
    override fun verifyToken(dat: ByteArray, peerCertificateFingerprint: String): VerifiedDat =
        innerVerifyToken(dat, securityRequirements, peerCertificateFingerprint, false)

    /**
     * Verify a given dynamic attribute token, given the security attributes as parameter.
     *
     * If the security requirements is not null and an instance of the SecurityRequirements class
     * the method will also check the provided security attributes of the connector that belongs
     * to the provided DAT
     *
     * The peer certificate is used for validating the fingerprints in the DAT against the peer
     *
     * @return The number of seconds this DAT is valid
     * @throws DatException
     */
    private fun innerVerifyToken(
        dat: ByteArray,
        securityRequirements: SecurityRequirements?,
        peerCertificateFingerprint: String?,
        setCurrentToken: Boolean,
        dapsMeta: DapsMeta = getDapsMeta()
    ): VerifiedDat {
        if (LOG.isDebugEnabled) {
            LOG.debug("Verifying dynamic attribute token...")
        }

        // JWKS using DAPS JWKS endpoint
        val httpsJwks = HttpsJwks(dapsMeta.jwksUri).apply {
            // Use SimpleGet-Adapter using the common, cached OkHttpClient
            setSimpleHttpGet { url ->
                object : SimpleResponse {
                    val response = runBlocking(Dispatchers.IO) {
                        val request = httpClient.request(url)
                        Triple(request.status, request.headers, request.bodyAsText())
                    }

                    override fun getStatusCode() = response.first.value

                    override fun getStatusMessage() = response.first.description

                    override fun getHeaderNames() = response.second.names()

                    override fun getHeaderValues(name: String) = response.second.getAll(name)

                    override fun getBody() = response.third
                }
            }
        }
        // Create JWKS key resolver that selects JWK based on key ID in jwt header
        val jwksKeyResolver = HttpsJwksVerificationKeyResolver(httpsJwks)

        // create validation requirements
        val jwtConsumer = JwtConsumerBuilder()
            .setRequireExpirationTime() // has expiration time
            .setAllowedClockSkewInSeconds(30) // leeway in validation time
            .setRequireSubject() // has subject
            .setExpectedAudience(true, "IDS_Connector", TARGET_AUDIENCE)
            .setExpectedIssuer(dapsMeta.issuer)
            .setVerificationKeyResolver(jwksKeyResolver)
            .setJweAlgorithmConstraints(
                AlgorithmConstraints(
                    AlgorithmConstraints.ConstraintType.PERMIT,
                    AlgorithmIdentifiers.RSA_USING_SHA256
                )
            )
            .build()

        val verifiedDat: VerifiedDat
        val validityTime: Long
        val claims: JwtClaims
        try {
            claims = jwtConsumer.processToClaims(String(dat, StandardCharsets.UTF_8))
            verifiedDat = VerifiedDat(dat, claims.subject, claims.expirationTime.value)
            validityTime = claims.expirationTime.value - (System.currentTimeMillis() / 1000)
        } catch (e: Exception) {
            throw DatException("Error during DAT verification", e)
        }

        if (setCurrentToken) {
            // overwrite current local token in daps driver instance
            currentToken = dat
            renewalTime = NumericDate.now().apply {
                addSeconds(verifiedDat.remainingValidity(renewalThreshold))
            }
        }

        // in case of validating remote DAT check the expected fingerprint from the DAT against the peers cert fingerprint
        peerCertificateFingerprint?.let {
            if (LOG.isDebugEnabled) {
                LOG.debug("Validate peer certificate fingerprint against expected fingerprint from DAT")
            }

            val datCertFingerprints: List<String> = when {
                claims.isClaimValueStringList("transportCertsSha256") -> {
                    claims.getStringListClaimValue("transportCertsSha256")
                }

                claims.isClaimValueString("transportCertsSha256") -> {
                    val fingerprint = claims.getStringClaimValue("transportCertsSha256")
                    listOf(fingerprint)
                }

                else -> {
                    throw DatException("Missing or invalid 'transportCertsSha256' format in DAT")
                }
            }

            // check if peer cert fingerprint is a valid fingerprint from the DAT
            if (!datCertFingerprints.contains(it)) {
                throw DatException(
                    "Fingerprint of peer certificate ($it) " +
                        "does not match any fingerprint from DAT ($datCertFingerprints)."
                )
            }
        }

        // check security requirements
        securityRequirements?.let {
            if (LOG.isDebugEnabled) {
                LOG.debug("Validate security attributes")
            }
            // parse security profile from DAT
            val securityProfile = claims.getStringClaimValue("securityProfile")
                ?: throw DatException("DAT does not contain securityProfile")
            val securityProfilePeer = SecurityProfile.fromString(securityProfile)
            if (securityProfilePeer < it.requiredSecurityLevel) {
                throw DatException(
                    "Peer does not support any valid trust profile: Required: " +
                        it.requiredSecurityLevel +
                        " given: " +
                        securityProfilePeer
                )
            }
            if (LOG.isDebugEnabled) {
                LOG.debug("Peer's supported security profile: {}", securityProfilePeer)
            }
        }
        if (LOG.isDebugEnabled) {
            LOG.debug("DAT is valid for {} seconds", validityTime)
        }

        return verifiedDat
    }

    companion object {
        private val LOG = LoggerFactory.getLogger(AisecDapsDriver::class.java)
        private const val TARGET_AUDIENCE = "idsc:IDS_CONNECTORS_ALL"

        // If DAPS doesn't provide metadata, retry after this timespan has elapsed
        private const val META_FALLBACK_LIFETIME_MS = 86_400_000L

        // OkHttpClient pool
        private val HTTP_CLIENTS = synchronizedMap(mutableMapOf<TrustManager, HttpClient>())
    }
}
