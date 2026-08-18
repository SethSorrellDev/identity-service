package com.seth.identityservice.config;

import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.text.ParseException;
import java.util.UUID;

/**
 * Generates (once) or loads the RSA signing key used for JWT issuance.
 *
 * The full JWK -- including private key material -- is persisted to a local,
 * gitignored file on first run so restarts don't invalidate every previously
 * issued token. In production this file's contents should come from a secret
 * store / env var instead of disk, but local-file bootstrap is fine for dev
 * and matches Phase 0 scope (scaffold + keypair only, no deployment yet).
 */
@Configuration
public class RsaKeyConfig {

    @Value("${identity.keys.path}")
    private String keysPath;

    @Bean
    public RSAKey rsaKey() throws IOException, ParseException, java.security.NoSuchAlgorithmException, com.nimbusds.jose.JOSEException {
        Path path = Path.of(keysPath);

        if (Files.exists(path)) {
            String json = Files.readString(path);
            return RSAKey.parse(json);
        }

        RSAKey generated = new RSAKeyGenerator(2048)
                .keyID(UUID.randomUUID().toString())
                .generate();

        Files.createDirectories(path.getParent() == null ? Path.of(".") : path.getParent());
        Files.writeString(path, generated.toJSONString());

        return generated;
    }
}
