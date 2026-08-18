package com.seth.identityservice.security;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.seth.identityservice.model.User;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.text.ParseException;
import java.time.Instant;
import java.util.Date;
import java.util.UUID;

@Service
public class JwtService {

    private final RSAKey rsaKey;
    private final String issuer;
    private final long accessTokenTtlSeconds;
    private final long refreshTokenTtlSeconds;

    public JwtService(RSAKey rsaKey,
                       @Value("${identity.jwt.issuer}") String issuer,
                       @Value("${identity.jwt.access-token-ttl-seconds}") long accessTokenTtlSeconds,
                       @Value("${identity.jwt.refresh-token-ttl-seconds}") long refreshTokenTtlSeconds) {
        this.rsaKey = rsaKey;
        this.issuer = issuer;
        this.accessTokenTtlSeconds = accessTokenTtlSeconds;
        this.refreshTokenTtlSeconds = refreshTokenTtlSeconds;
    }

    public String generateAccessToken(User user) {
        return generateToken(user, "access", accessTokenTtlSeconds);
    }

    public String generateRefreshToken(User user) {
        return generateToken(user, "refresh", refreshTokenTtlSeconds);
    }

    public long getAccessTokenTtlSeconds() {
        return accessTokenTtlSeconds;
    }

    private String generateToken(User user, String type, long ttlSeconds) {
        try {
            Instant now = Instant.now();
            JWTClaimsSet claims = new JWTClaimsSet.Builder()
                    .subject(user.getId().toString())
                    .issuer(issuer)
                    .claim("email", user.getEmail())
                    .claim("type", type)
                    .jwtID(UUID.randomUUID().toString())
                    .issueTime(Date.from(now))
                    .expirationTime(Date.from(now.plusSeconds(ttlSeconds)))
                    .build();

            JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.RS256)
                    .keyID(rsaKey.getKeyID())
                    .type(JOSEObjectType.JWT)
                    .build();

            SignedJWT signedJWT = new SignedJWT(header, claims);
            signedJWT.sign(new RSASSASigner(rsaKey));
            return signedJWT.serialize();
        } catch (JOSEException e) {
            throw new IllegalStateException("Failed to sign JWT", e);
        }
    }

    /**
     * Verifies signature and expiry only. Callers must separately check the
     * "type" claim matches what they expect (access vs refresh) -- this
     * method proves authenticity, not intent.
     */
    public JWTClaimsSet verifyAndParse(String token) {
        try {
            SignedJWT signedJWT = SignedJWT.parse(token);
            RSASSAVerifier verifier = new RSASSAVerifier(rsaKey.toRSAPublicKey());

            if (!signedJWT.verify(verifier)) {
                throw new IllegalArgumentException("Invalid token signature");
            }

            JWTClaimsSet claims = signedJWT.getJWTClaimsSet();
            if (claims.getExpirationTime() == null || claims.getExpirationTime().before(new Date())) {
                throw new IllegalArgumentException("Token expired");
            }

            return claims;
        } catch (ParseException | JOSEException e) {
            throw new IllegalArgumentException("Malformed token", e);
        }
    }
}
