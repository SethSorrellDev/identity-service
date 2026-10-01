package com.seth.identityservice.config;

import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.UUID;

/**
 * Resolves the RSA signing key, in priority order:
 *   1. IDENTITY_SIGNING_KEY env var (full JWK JSON) -- production. Render's
 *      filesystem is ephemeral, so a file-based key would regenerate on every
 *      deploy and silently invalidate every issued token.
 *   2. Local gitignored file -- dev. Generated on first run, reused after.
 */
@Configuration
public class RsaKeyConfig {

    @Value("${identity.keys.path}")
    private String keysPath;

    @Value("${identity.keys.json:}")
    private String keyJson;

    @Bean
    public RSAKey rsaKey() throws Exception {
        if (keyJson != null && !keyJson.isBlank()) {
            RSAKey key = RSAKey.parse(keyJson);
            if (!key.isPrivate()) {
                throw new IllegalStateException(
                        "IDENTITY_SIGNING_KEY must include private key material (d, p, q)");
            }
            return key;
        }

        Path path = Path.of(keysPath);
        if (Files.exists(path)) {
            return RSAKey.parse(Files.readString(path));
        }

        RSAKey generated = new RSAKeyGenerator(2048)
                .keyID(UUID.randomUUID().toString())
                .generate();

        Path parent = path.getParent();
        if (parent != null) {
            Files.createDirectories(parent);
        }
        Files.writeString(path, generated.toJSONString());
        return generated;
    }
}
