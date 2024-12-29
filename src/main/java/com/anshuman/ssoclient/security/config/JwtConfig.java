package com.anshuman.ssoclient.security.config;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;

@Configuration
@Slf4j
public class JwtConfig {

    @Value("${spring.security.oauth2.resourceserver.jwt.jwk-set-uri}")
    private String jwkSetUri;

    @Bean
    public JwtDecoder jwtDecoder() {

        JwtDecoder jwtDecoder = NimbusJwtDecoder.withJwkSetUri(jwkSetUri).build();

        return token -> {
            log.debug("Validating token: {}", token);
            Jwt jwt = jwtDecoder.decode(token);
            log.debug("Decoded JWT token with subject: {}, headers: {}, claims: {}, audience: {}, id: {}, issuer: {}, expires: {}",
                    jwt.getSubject(), jwt.getHeaders(), jwt.getClaims(), jwt.getAudience(), jwt.getId(), jwt.getIssuer(), jwt.getExpiresAt());
            return jwt;
        };
    }
}
