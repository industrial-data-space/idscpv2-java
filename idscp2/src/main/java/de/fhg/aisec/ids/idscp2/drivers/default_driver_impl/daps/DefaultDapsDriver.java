package de.fhg.aisec.ids.idscp2.drivers.default_driver_impl.daps;

import de.fhg.aisec.ids.idscp2.drivers.default_driver_impl.keystores.PreConfiguration;
import de.fhg.aisec.ids.idscp2.drivers.interfaces.DapsDriver;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import okhttp3.*;
import org.jose4j.http.Get;
import org.jose4j.jwa.AlgorithmConstraints;
import org.jose4j.jwa.AlgorithmConstraints.ConstraintType;
import org.jose4j.jwk.HttpsJwks;
import org.jose4j.jws.AlgorithmIdentifiers;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.MalformedClaimException;
import org.jose4j.jwt.NumericDate;
import org.jose4j.jwt.consumer.InvalidJwtException;
import org.jose4j.jwt.consumer.JwtConsumer;
import org.jose4j.jwt.consumer.JwtConsumerBuilder;
import org.jose4j.keys.resolvers.HttpsJwksVerificationKeyResolver;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;
import org.json.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509ExtendedTrustManager;
import java.io.IOException;
import java.security.Key;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.Date;
import java.util.concurrent.TimeUnit;

/**
 * Default DAPS Driver Implementation for requesting valid dynamicAttributeToken and verifying DAT
 *
 * @author Leon Beckmann (leon.beckmann@aisec.fraunhofer.de)
 * @author Gerd Brost (gerd.brost@aisec.fraunhofer.de)
 */
public class DefaultDapsDriver implements DapsDriver {
    private static final Logger LOG = LoggerFactory.getLogger(DefaultDapsDriver.class);

    private final SSLSocketFactory sslSocketFactory; //ssl socket factory can be reused
    private final X509ExtendedTrustManager trustManager; //trust manager can be reused
    private final Key privateKey; //private key can be reused
    private final String dapsUrl;
    private final String targetAudience = "idsc:IDS_CONNECTORS_ALL";
    private final X509Certificate cert;

    public DefaultDapsDriver(DefaultDapsDriverConfig config) {
        this.dapsUrl = config.getDapsUrl();

        //create ssl socket factory for secure
        privateKey = PreConfiguration.getKey(
                config.getKeyStorePath(),
                config.getKeyStorePassword(),
                config.getKeyAlias()
        );

        cert = PreConfiguration.getCertificate(
            config.getKeyStorePath(),
            config.getKeyStorePassword(),
            config.getKeyAlias());

        TrustManager[] trustManagers = PreConfiguration.getX509ExtTrustManager(
                config.getTrustStorePath(),
                config.getTrustStorePassword()
        );

        this.trustManager = (X509ExtendedTrustManager) trustManagers[0];

        try {
            SSLContext sslContext = SSLContext.getInstance("TLS");
            sslContext.init(null, trustManagers, null);
            sslSocketFactory = sslContext.getSocketFactory();
        } catch (NoSuchAlgorithmException | KeyManagementException e) {
            LOG.error("Cannot init DefaultDapsDriver: {}", e.toString());
            throw new RuntimeException(e);
        }
    }

    /*
     * Receive the signed and valid dynamic attribute token from the DAPS
     *
     * return "INVALID_TOKEN" on failure
     */
    @Override
    public byte[] getToken() {
        String invalidToken = "INVALID_TOKEN";
        String token;

        LOG.info("Retrieving Dynamic Attribute Token from Daps ...");

        //Create connectorUUID
        // Get AKI
        //GET 2.5.29.14	SubjectKeyIdentifier / 2.5.29.35	AuthorityKeyIdentifier
        String aki_oid = Extension.authorityKeyIdentifier.getId();
        byte[] rawAuthorityKeyIndentifier = cert.getExtensionValue(aki_oid);
        ASN1OctetString akiOc = ASN1OctetString.getInstance(rawAuthorityKeyIndentifier);
        AuthorityKeyIdentifier aki = AuthorityKeyIdentifier.getInstance(akiOc.getOctets());
        byte[] authorityKeyIndentifier = aki.getKeyIdentifier();

        //GET SKI
        byte[] octets = DEROctetString.getInstance(rawAuthorityKeyIndentifier).getOctets();
        AuthorityKeyIdentifier authorityKeyIdentifier = AuthorityKeyIdentifier.getInstance(octets);
        byte[] keyIdentifier = authorityKeyIdentifier.getKeyIdentifier();
        String ski_oid = Extension.subjectKeyIdentifier.getId();
        byte[] rawSubjectKeyIdenfier = cert.getExtensionValue(ski_oid);
        ASN1OctetString ski0c = ASN1OctetString.getInstance(rawSubjectKeyIdenfier);
        SubjectKeyIdentifier ski = SubjectKeyIdentifier.getInstance(ski0c.getOctets());

        byte[] subjectKeyIdentifier = ski.getKeyIdentifier();

        DEROctetString dos = new DEROctetString(authorityKeyIndentifier);
        String aki_result = beatifyHex(encodeHexString(authorityKeyIndentifier).toUpperCase());
        String ski_result = beatifyHex(encodeHexString(subjectKeyIdentifier).toUpperCase());
        LOG.info("AKI: " + aki_result);
        LOG.info("SKI: " + ski_result);

        String connectorUUID = ski_result + "keyid:" + aki_result.substring(0, aki_result.length() - 1);

        //create signed JWT
        String jwt =
                Jwts.builder()
                        .setIssuer(connectorUUID)
                        .setSubject(connectorUUID)
                        .setExpiration(Date.from(Instant.now().plusSeconds(86400)))
                        .setIssuedAt(Date.from(Instant.now()))
                        .setNotBefore(Date.from(Instant.now()))
                        .setAudience(targetAudience)
                        .signWith(privateKey, SignatureAlgorithm.RS256).compact();

        //build http client and request for DAPS
        RequestBody formBody =
                new FormBody.Builder()
                        .add("grant_type", "client_credentials")
                        .add(
                                "client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer")
                        .add("client_assertion", jwt)
                        .add("scope", "ids_connector")
                        .build();

        OkHttpClient client =
                new OkHttpClient.Builder()
                        .sslSocketFactory(sslSocketFactory, trustManager)
                        .connectTimeout(15, TimeUnit.SECONDS)
                        .writeTimeout(15, TimeUnit.SECONDS)
                        .readTimeout(15, TimeUnit.SECONDS)
                        .build();

        Request request =
                new Request.Builder()
                        .url(dapsUrl.concat("/token"))
                        .post(formBody)
                        .build();

        try {
            //get http response from DAPS
            if (LOG.isDebugEnabled()) {
                LOG.debug("Acquire DAT from {}", dapsUrl);
            }
            Response response = client.newCall(request).execute();

            //check for valid response
            if (!response.isSuccessful()) {
                if (LOG.isWarnEnabled()) {
                    LOG.warn("Get unsuccessful http response: {}", response.toString());
                }
                return invalidToken.getBytes();
            }

            if (response.body() == null) {
                if (LOG.isWarnEnabled()) {
                    LOG.warn("Get empty DAPS response");
                }
                return invalidToken.getBytes();
            }

            JSONObject json = new JSONObject(response.body().string());
            if (json.has("access_token")) {
                token = json.getString("access_token");
                LOG.info("Get access_token from DAPS: {}", token);
            } else if (json.has("error")) {
                if (LOG.isWarnEnabled()) {
                    LOG.warn("Get DAPS error response: {}", json.getString("error"));
                }
                return invalidToken.getBytes();
            } else {
                if (LOG.isWarnEnabled()) {
                    LOG.warn("Get unknown DAPS response format: {}", json.toString());
                }
                return invalidToken.getBytes();
            }

            //verify token once without security attr validation before providing it
            if (verifyToken(token.getBytes(), null) > 0) {
                LOG.info("DAT is valid");
                return token.getBytes();
            } else {
                if (LOG.isWarnEnabled()) {
                    LOG.warn("DAT validation failed");
                }
                return invalidToken.getBytes();
            }
        } catch (IOException e) {
            LOG.error("Cannot acquire DAT from DAPS: ", e);
            return invalidToken.getBytes();
        }
    }

    /*
     * Verify a given dynamic attribute token
     *
     * If the security requirements is not null and an instance of the SecurityRequirements class
     * the method will also check the provided security attributes of the connector that belongs
     * to the provided DAT
     *
     * Return the number of seconds, des DAT is valid, or -1 if validation failed
     */
    @Override
    public long verifyToken(byte[] dat, Object securityRequirements) {

        LOG.info("Verify dynamic attribute token ...");

        // Get JsonWebKey JWK from JsonWebKeyStore JWKS using DAPS JWKS endpoint
        HttpsJwks httpsJwks = new HttpsJwks(dapsUrl.concat("/.well-known/jwks.json"));
        Get getInstance = new Get();
        getInstance.setSslSocketFactory(sslSocketFactory);
        httpsJwks.setSimpleHttpGet(getInstance);

        // create new jwks key resolver, selects jwk based on key ID in jwt header
        HttpsJwksVerificationKeyResolver jwksKeyResolver
                = new HttpsJwksVerificationKeyResolver(httpsJwks);

        //create validation requirements
        JwtConsumer jwtConsumer =
                new JwtConsumerBuilder()
                        .setRequireExpirationTime()         // has expiration time
                        .setAllowedClockSkewInSeconds(30)   // leeway in validation time
                        .setRequireSubject()                // has subject
                        .setExpectedAudience(targetAudience)
                        .setExpectedIssuer(dapsUrl)         // e.g. https://daps.aisec.fraunhofer.de
                        .setVerificationKeyResolver(jwksKeyResolver) //get decryption key from jwks
                        .setJweAlgorithmConstraints(
                                new AlgorithmConstraints(
                                        ConstraintType.WHITELIST,
                                        AlgorithmIdentifiers.RSA_USING_SHA256
                                )
                        )
                        .build();

        //verify dat
        JwtClaims claims;
        NumericDate expTime;

        if (LOG.isDebugEnabled()) {
            LOG.debug("Request JWKS from DAPS for validating DAT");
        }

        try {
            claims = jwtConsumer.processToClaims(new String(dat));
            expTime = claims.getExpirationTime();
        } catch (InvalidJwtException e) {
            if (LOG.isWarnEnabled()) {
                LOG.warn("DAPS response is not a valid DAT format", e);
            }
            return -1;
        } catch (MalformedClaimException e) {
            if (LOG.isWarnEnabled()) {
                LOG.warn("DAT does not contain expiration time", e);
            }
            return -1;
        }
        long validityTime = expTime.getValue() - NumericDate.now().getValue();

        //check security requirements
        if (securityRequirements != null) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Validate security attributes");
            }

            if (securityRequirements instanceof SecurityRequirements) {
                SecurityRequirements secRequirements = (SecurityRequirements) securityRequirements;
                SecurityRequirements providedSecurityProfile =
                        parseSecurityRequirements(claims.toJson());

                if (providedSecurityProfile == null) {
                    return -1;
                }

                //toDo add further security attribute validation

                
                if(secRequirements.getRequiredSecurityLevel().equals("idsc:BASE_CONNECTOR_SECURITY_PROFILE")) {
                    if (providedSecurityProfile.getRequiredSecurityLevel().equals("idsc:BASE_CONNECTOR_SECURITY_PROFILE") ||
                        providedSecurityProfile.getRequiredSecurityLevel().equals("idsc:TRUSTED_CONNECTOR_SECURITY_PROFILE") ||
                        providedSecurityProfile.getRequiredSecurityLevel().equals("idsc:TRUSTED_CONNECTOR_PLUS_SECURITY_PROFILE")) {
                        LOG.info("DAT is valid and secure");
                        return validityTime;
                    } else {
                        if (LOG.isWarnEnabled()) {
                            LOG.warn("DAT does not fulfill the security requirements");
                        }
                        return -1;
                    }
                } else if(secRequirements.getRequiredSecurityLevel().equals("idsc:TRUSTED_CONNECTOR_SECURITY_PROFILE")) {
                    if (providedSecurityProfile.getRequiredSecurityLevel().equals("idsc:TRUSTED_CONNECTOR_SECURITY_PROFILE") ||
                        providedSecurityProfile.getRequiredSecurityLevel().equals("idsc:TRUSTED_CONNECTOR_PLUS_SECURITY_PROFILE")) {
                        LOG.info("DAT is valid and secure");
                        return validityTime;
                    } else {
                        if (LOG.isWarnEnabled()) {
                            LOG.warn("DAT does not fulfill the security requirements, TRUST LEVEL not reached");
                        }
                        return -1;
                    }
                } else if(secRequirements.getRequiredSecurityLevel().equals("idsc:TRUSTED_CONNECTOR_PLUS_SECURITY_PROFILE")) {
                    if (providedSecurityProfile.getRequiredSecurityLevel().equals("idsc:TRUSTED_CONNECTOR_PLUS_SECURITY_PROFILE")) {
                        LOG.info("DAT is valid and secure");
                        return validityTime;
                    } else {
                        if (LOG.isWarnEnabled()) {
                            LOG.warn("DAT does not fulfill the security requirements, TRUST+ LEVEL not reached");
                        }
                        return -1;
                    }
                } else {
                    if (LOG.isWarnEnabled()) {
                        LOG.warn("DAT does not fulfill the security requirements, not supported trust level");
                    }
                    return -1;
                }

            } else {
                //invalid security requirements format
                if (LOG.isWarnEnabled()) {
                    LOG.warn("Invalid security requirements format. Expected SecurityRequirements.class");
                }
                return -1;
            }
        } else {
            LOG.info("DAT is valid");
            return validityTime;
        }
    } //returns number of seconds dat is valid

    private SecurityRequirements parseSecurityRequirements(String dynamicAttrToken) {
        JSONObject asJson = new JSONObject(dynamicAttrToken);

        if (!asJson.has("securityProfile")) {
            if (LOG.isWarnEnabled()) {
                LOG.warn("DAT does not contain securityProfile");
            }
            return null;
        }
        //toDo parse further security attributes
        //FIXME: Does this make sense? How are security requirements mapped?
        return new SecurityRequirements.Builder()
                .setRequiredSecurityLevel(asJson.getString("securityProfile"))
                .build();
    }

    /***
     * Split string ever len chars and return string array
     * @param src
     * @param len
     * @return
     */
    public static String[] split(String src, int len) {
        String[] result = new String[(int)Math.ceil((double)src.length()/(double)len)];
        for (int i=0; i<result.length; i++)
            result[i] = src.substring(i*len, Math.min(src.length(), (i+1)*len));
        return result;
    }

    /***
     * Beautyfies Hex strings and will generate a result later used to create the client id (XX:YY:ZZ)
     * @param hexString HexString to be beautified
     * @return beautifiedHex result
     */
    private String beatifyHex(String hexString) {
        String[] splitString = split(hexString, 2);
        StringBuffer sb = new StringBuffer();
        for(int i =0; i < splitString.length; i++) {
            sb.append(splitString[i]);
            sb.append(":");
        }
        return sb.toString();
    }

    /**
     * Convert byte array to hex without any dependencies to libraries.
     * @param num
     * @return
     */
    private String byteToHex(byte num) {
        char[] hexDigits = new char[2];
        hexDigits[0] = Character.forDigit((num >> 4) & 0xF, 16);
        hexDigits[1] = Character.forDigit((num & 0xF), 16);
        return new String(hexDigits);
    }

    /**
     * Encode a byte array to an hex string
     * @param byteArray
     * @return
     */
    private String encodeHexString(byte[] byteArray) {
        StringBuffer hexStringBuffer = new StringBuffer();
        for (int i = 0; i < byteArray.length; i++) {
            hexStringBuffer.append(byteToHex(byteArray[i]));
        }
        return hexStringBuffer.toString();
    }
}
