package com.anshuman.ssoclient.security;

import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.stereotype.Component;

import java.io.Serial;
import java.io.Serializable;
import java.time.Instant;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

/**
 * JWT Utility class. It generates jwt token, extracts it, checks whether token
 * is valid or not. It uses SHA256 algorithm for encryption and decryption.
 * 
 */
@Slf4j
@Component
public class JwtUtil implements Serializable {

	private final JwtDecoder jwtDecoder;

	@Serial
	private static final long serialVersionUID = -2550185165626007488L;

	private final Set<String> blacklistedTokens = new HashSet<>();

    public JwtUtil(JwtDecoder jwtDecoder) {
        this.jwtDecoder = jwtDecoder;
    }

    public Jwt convertToJwt(String token) throws JwtException {
		try {
			return jwtDecoder.decode(token);
		} catch (JwtException e) {
			log.error("Error decoding JWT: {}", e.getMessage());
			return null;
		}
	}
	
	public void blacklistToken(Jwt jwt) {
	    blacklistedTokens.add(jwt.getSubject());
	}

	// Check if a token is blacklisted
	public Boolean isTokenBlacklisted(Jwt jwt) {
	    return blacklistedTokens.contains(jwt.getSubject());
	}

	public String extractUsername(Jwt jwt) {
		return jwt.getClaim("preferred_username");
	}

	public Instant extractExpiration(Jwt jwt) {
		return jwt.getExpiresAt();
	}

	public String extractClaim(Jwt jwt , String claimName) {
		return jwt.getClaim(claimName);
	}

	public Map<String, Object> extractAllClaims(Jwt jwt) {
		return jwt.getClaims();
	}

	public Boolean isTokenExpired(Jwt jwt) {
		return extractExpiration(jwt).isBefore(Instant.now());
	}

	public Boolean validateToken(Jwt jwt, UserDetails userDetails) {
		boolean isTokenBlacklisted = isTokenBlacklisted(jwt);
		boolean doesUserNameMatch = extractUsername(jwt).equals(userDetails.getUsername());
		boolean isTokenExpired = isTokenExpired(jwt);
		return !isTokenBlacklisted && doesUserNameMatch && !isTokenExpired;
	}
}