package com.sbi.ems.security;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.Date;
import java.util.List;

/**
 * JWT utility — generates and validates tokens.
 *
 * ── DevSecOps Lab 1 — Fix 1 (A07 — Auth Failures) ────────────────────────────
 *
 *  BEFORE (vulnerable — hardcoded secret, no expiry):
 *    private static final String JWT_SECRET = "SBIBankingSecretKey2024";
 *    private static final long   JWT_EXPIRY  = 86400000;
 *    // Problems:
 *    // 1. Secret is in source code → visible in git history forever
 *    // 2. 24-hour expiry is too long for a banking application
 *    // 3. No startup validation — deploys silently with a weak secret
 *
 *  AFTER (secure — secret from environment, 1-hour expiry, fail-fast):
 *    See the @Value injected fields below.
 *    SonarQube rule java:S6418 flags the hardcoded string above as Critical.
 *
 *  LAB 1 TASK:
 *    1. Find the two commented lines marked VULNERABLE below.
 *    2. SonarQube will highlight them in the dashboard as Critical issues.
 *    3. Apply the fix: uncomment the @Value fields, remove the hardcoded values.
 *    4. Add jwt.secret=${JWT_SECRET} to application.properties.
 *    5. Re-run the scan and confirm the Quality Gate passes.
 */
@Component
public class JwtUtil {

    private static final Logger log = LoggerFactory.getLogger(JwtUtil.class);

    // ── Lab 1 Fix Target ──────────────────────────────────────────────────────
    // VULNERABLE — hardcoded secret and expiry. SonarQube flags this Critical.
    // Uncomment the @Value lines below and delete these two lines to fix.
    private static final String HARDCODED_SECRET = "SBIBankingSecretKey2024";  // ⚠️ VULNERABLE
    private static final long   HARDCODED_EXPIRY  = 86400000L;                 // ⚠️ 24h — too long

    // FIX — uncomment these after removing the hardcoded constants above:
    // @Value("${jwt.secret}")
    // private String jwtSecret;
    //
    // @Value("${jwt.expiration.ms:900000}")   // 15 minutes — appropriate for banking
    // private long jwtExpirationMs;
    // ─────────────────────────────────────────────────────────────────────────

    private final SecretKey signingKey;
    private final long      expirationMs;

    public JwtUtil(@Value("${jwt.secret:#{null}}") String secret,
                   @Value("${jwt.expiration.ms:86400000}") long expirationMs) {

        // Use the hardcoded value as fallback so the app starts in its vulnerable state
        String effectiveSecret = (secret != null && !secret.startsWith("CHANGE"))
                ? secret : HARDCODED_SECRET;

        this.signingKey   = Keys.hmacShaKeyFor(effectiveSecret.getBytes(StandardCharsets.UTF_8));
        this.expirationMs = expirationMs;
        log.info("JwtUtil initialised. Expiry: {} ms", expirationMs);
    }

    public String generateToken(String username, List<String> roles) {
        return Jwts.builder()
                .subject(username)
                .claim("roles", roles)
                .issuedAt(new Date())
                .expiration(new Date(System.currentTimeMillis() + expirationMs))
                .signWith(signingKey)
                .compact();
    }

    public String extractUsername(String token) {
        return parseClaims(token).getSubject();
    }

    @SuppressWarnings("unchecked")
    public List<String> extractRoles(String token) {
        Object roles = parseClaims(token).get("roles");
        return (roles instanceof List<?>) ? (List<String>) roles : List.of();
    }

    public boolean validateToken(String token) {
        try {
            parseClaims(token);
            return true;
        } catch (JwtException | IllegalArgumentException e) {
            log.warn("JWT validation failed: {}", e.getClass().getSimpleName());
            return false;
        }
    }

    private Claims parseClaims(String token) {
        return Jwts.parser()
                .verifyWith(signingKey)
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }
}
