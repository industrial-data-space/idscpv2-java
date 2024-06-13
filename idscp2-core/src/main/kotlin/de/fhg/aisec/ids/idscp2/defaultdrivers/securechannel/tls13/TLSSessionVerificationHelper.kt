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

import org.bouncycastle.asn1.x509.GeneralName
import org.slf4j.LoggerFactory
import java.net.InetAddress
import java.security.cert.CertificateExpiredException
import java.security.cert.CertificateNotYetValidException
import java.security.cert.CertificateParsingException
import java.security.cert.X509Certificate
import java.util.Date
import java.util.regex.Pattern
import javax.net.ssl.SSLPeerUnverifiedException

/**
 * A class for verifying an established TLS Session on application layer
 * (application level security)
 *
 * @author Leon Beckmann (leon.beckmannn@aisec.fraunhofer.de)
 */
object TLSSessionVerificationHelper {
    private val LOG = LoggerFactory.getLogger(TLSSessionVerificationHelper::class.java)
    private val ipv4Pattern by lazy {
        Pattern.compile(
            "(([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.){3}([01]?\\d\\d?|2[0-4]\\d|25[0-5])",
            Pattern.CASE_INSENSITIVE
        )
    }
    private val ipv6Pattern by lazy {
        Pattern.compile("(([0-9a-f]{0,4}:){1,7}[0-9a-f]{0,4})", Pattern.CASE_INSENSITIVE)
    }

    /*
     * Checks if the ssl session is valid and the remote host can be trusted
     *
     * Due to the fact, that hostname verification is not specified in the secure socket layer,
     * we have to check if the connected hostname matches to the subject of the peer certificate to
     * avoid Man-In-The-Middle Attacks. This is required for every raw tls!
     *
     * Further we check the peer certificate validity to avoid the case that some of the certificates
     * in our local trust_store are not valid anymore and allow a peer connector to connect with an
     * expired certificate
     *
     * Throws SSlPeerUnverifiedException if peer certificate is not secure for this peer
     */
    @Throws(SSLPeerUnverifiedException::class)
    @JvmOverloads
    fun verifyTlsSession(
        host: String,
        port: Int,
        peerCert: X509Certificate,
        hostnameVerificationEnabled: Boolean,
        peerIsServer: Boolean = true
    ) {
        if (LOG.isTraceEnabled) {
            LOG.trace("Connected to {}:{}", host, port)
        }
        try {
            /*
             * Hostname verification is always enabled per default but the user can disable it using an as
             * danger marked function of the native tls configuration (e.g. for testing purposes)
             */
            if (hostnameVerificationEnabled) {
                /*
                 * According to RFC6125, hostname verification should be done against the certificate's
                 * subject alternative name's (SANs) DNSName field or the SANs IPAddress. In some legacy
                 * implementations, the check is done against the certificate's commonName, but this is
                 * deprecated for quite a while and is therefore not supported anymore in the IDSCP2 protocol.
                 */
                val sans = peerCert.subjectAlternativeNames
                    ?: throw SSLPeerUnverifiedException(
                        "No Subject alternative names for hostname " +
                            "verification provided"
                    )
                val acceptedDnsNames = ArrayList<String>()
                val acceptedIpAddresses = ArrayList<String>()
                for (subjectAltName in sans) {
                    if (subjectAltName.size != 2) {
                        continue
                    }
                    val value = subjectAltName[1]
                    when (subjectAltName[0] as Int?) {
                        GeneralName.dNSName -> if (value is String) {
                            acceptedDnsNames.add(value)
                        } else if (value is ByteArray) {
                            acceptedDnsNames.add(String(value))
                        }
                        GeneralName.iPAddress -> if (value is String) {
                            acceptedIpAddresses.add(value)
                        } else if (value is ByteArray) {
                            acceptedIpAddresses.add(String(value))
                        }
                        else -> {
                            if (LOG.isTraceEnabled) {
                                LOG.trace("Unhandled SAN type \"{}\" with value \"{}\"", subjectAltName[0], value)
                            }
                        }
                    }
                }

                if (isIpAddress(host)) {
                    // First, check IP addresses directly given by type-7-SANs
                    if (!acceptedIpAddresses.contains(host)) {
                        // Check IP addresses using DNS resolving
                        // This check is *weak* and should be accompanied by DAT fingerprint checking later on
                        val resolvedIps = acceptedDnsNames.flatMap {
                            try {
                                InetAddress.getAllByName(it).toList()
                            } catch (e: Throwable) {
                                emptyList()
                            }
                        }.map { it.hostAddress }
                        if (LOG.isTraceEnabled) {
                            LOG.trace("Resolved IPs: {}", resolvedIps.toSet().joinToString())
                        }
                        if (!resolvedIps.contains(host)) {
                            throw SSLPeerUnverifiedException(
                                "Hostname verification failed. Peer certificate does " +
                                    "not belong to peer host"
                            )
                        }
                    }
                } else {
                    // Check hostname
                    val hostLabels = host.split(".")
                    var found = false
                    for (entry in acceptedDnsNames) {
                        if (checkHostname(entry.trimEnd('.').split("."), hostLabels)) {
                            found = true
                            break
                        }
                    }
                    if (!found) {
                        throw SSLPeerUnverifiedException(
                            "Hostname verification failed. Peer certificate does " +
                                "not belong to peer host"
                        )
                    }
                }
            } else {
                if (peerIsServer) {
                    LOG.warn(
                        "DANGER: TLS server hostname verification is disabled. " +
                            "This is strongly discouraged except for testing purposes!"
                    )
                } else {
                    LOG.info(
                        "Client hostname verification is disabled. " +
                            "This may reduce connection security, please consider enabling it when applicable."
                    )
                }
            }

            // check certificate validity for now and at least one day
            val oneDay = Date().apply { this.time += 86_400_000 }
            peerCert.checkValidity()
            peerCert.checkValidity(oneDay)
        } catch (e: CertificateParsingException) {
            throw SSLPeerUnverifiedException("TLS Session Verification failed $e")
        } catch (e: CertificateNotYetValidException) {
            throw SSLPeerUnverifiedException("TLS Session Verification failed $e")
        } catch (e: CertificateExpiredException) {
            throw SSLPeerUnverifiedException("TLS Session Verification failed $e")
        }
    }

    /*
     * check if host is an IP Address
     */
    private fun isIpAddress(host: String): Boolean =
        ipv4Pattern.matcher(host).matches() || ipv6Pattern.matcher(host).matches()

    /*
     * match dNS Name
     */
    private fun checkHostname(dnsNameLabels: List<String>, hostNameLabels: List<String>): Boolean {
        /*
         * support wildcard matching of DNS names as described in RFC6125 Section 6.4.3
         *
         * Rules:
         * 1. The client SHOULD NOT attempt to match a presented identifier in which the wildcard
         * character comprises a label other than the left-most label
         * (e.g., do not match bar.*.example.net).
         *
         * 2. If the wildcard character is the only character of the left-most label in the
         * presented identifier, the client SHOULD NOT compare against anything but the left-most
         * label of the reference identifier (e.g., *.example.com would match foo.example.com but
         * not bar.foo.example.com or example.com).
         *
         * 3. The client MAY match a presented identifier in which the wildcard character is not the
         * only character of the label (e.g., baz*.example.net and *baz.example.net and
         * b*z.example.net would be taken to match baz1.example.net and foobaz.example.net and
         * buzz.example.net, respectively).  However, the client SHOULD NOT attempt to match a
         * presented identifier where the wildcard character is embedded within an A-label or
         * U-label of an internationalized domain name.
         */
        if (dnsNameLabels.size == hostNameLabels.size) { // include rule 2
            // all labels without the first one must match completely (rule 1)
            for (i in 1 until dnsNameLabels.size) {
                if (dnsNameLabels[i] != hostNameLabels[i]) {
                    return false
                }
            }

            // first label could include wildcard character '*' (rule 1+3)
            return hostNameLabels[0].matches(Regex(dnsNameLabels[0].replace("*", ".*")))
        }
        return false
    }
}
