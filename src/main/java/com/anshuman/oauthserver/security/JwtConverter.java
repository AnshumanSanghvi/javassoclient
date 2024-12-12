package com.anshuman.oauthserver.security;

import jakarta.annotation.Nonnull;
import lombok.extern.slf4j.Slf4j;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtClaimNames;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;
import org.springframework.stereotype.Component;

import java.util.Collection;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

@Slf4j
@Component
public class JwtConverter  implements Converter<Jwt, AbstractAuthenticationToken> {

    private final JwtGrantedAuthoritiesConverter jwtGrantedAuthoritiesConverter = new JwtGrantedAuthoritiesConverter();

    private final JwtConverterProperties properties;

    public JwtConverter(JwtConverterProperties properties) {
        this.properties = properties;
    }

    /**
     * Convert the Jwt token to an AbstractAuthenticationToken
     * @param jwt the jwt token
     * @return the AbstractAuthenticationToken
     */
    @Override
    public AbstractAuthenticationToken convert(@Nonnull Jwt jwt) {
        log.debug("Received JWT token with subject: {}, headers: {}, claims: {}, audience: {}, id: {}, issuer: {}, expires: {}",
                jwt.getSubject(), jwt.getHeaders(), jwt.getClaims(), jwt.getAudience(), jwt.getId(), jwt.getIssuer(), jwt.getExpiresAt());

        Stream<GrantedAuthority> grantedAuthorityStream = jwtGrantedAuthoritiesConverter.convert(jwt).stream();
        Stream<? extends GrantedAuthority> resourceRolesStream = extractResourceRoles(jwt).stream();
        Collection<GrantedAuthority> authorities = Stream.concat(grantedAuthorityStream, resourceRolesStream).collect(Collectors.toSet());
        String principalClaim = getPrincipalClaimName(jwt);
        return new JwtAuthenticationToken(jwt, authorities, principalClaim);
    }

    /**
     * Get the principal claim name from the jwt token
     * @param jwt the jwt token
     * @return the principal claim name
     */
    private String getPrincipalClaimName(Jwt jwt) {
        String claimName = JwtClaimNames.SUB;
        if (properties.getPrincipalAttribute() != null) {
            claimName = properties.getPrincipalAttribute();
        }
        return jwt.getClaim(claimName);
    }

    /**
     * Extract the resource roles from the jwt token
     * @param jwt  the jwt token
     * @return the collection of granted authorities
     */
    @SuppressWarnings("unchecked")
    private Collection<? extends GrantedAuthority> extractResourceRoles(Jwt jwt) {
        Map<String, Object> resourceAccess = jwt.getClaim("resource_access");
        Map<String, Object> resource;
        Collection<String> resourceRoles;

        if (resourceAccess == null
                || (resource = (Map<String, Object>) resourceAccess.get(properties.getResourceId())) == null
                || (resourceRoles = (Collection<String>) resource.get("roles")) == null) {
            return Set.of();
        }
        return resourceRoles.stream()
                .map(role -> new SimpleGrantedAuthority("ROLE_" + role))
                .collect(Collectors.toSet());
    }

}
