package com.sbi.ems.dto.auth;

import io.swagger.v3.oas.annotations.media.Schema;

/**
 * Response body for a successful login.
 *
 * DevSecOps: Returns structured JSON instead of a raw string token.
 * Includes token type and expiry so clients can schedule refresh.
 */
@Schema(description = "JWT token response")
public class TokenResponse {

    @Schema(description = "JWT bearer token", example = "eyJhbGci...")
    private final String token;

    @Schema(description = "Token type", example = "Bearer")
    private final String tokenType = "Bearer";

    @Schema(description = "Token expiry in milliseconds", example = "3600000")
    private final long expiresIn;

    @Schema(description = "Authenticated username", example = "hr.admin")
    private final String username;

    public TokenResponse(String token, long expiresIn, String username) {
        this.token     = token;
        this.expiresIn = expiresIn;
        this.username  = username;
    }

    public String getToken()     { return token; }
    public String getTokenType() { return tokenType; }
    public long   getExpiresIn() { return expiresIn; }
    public String getUsername()  { return username; }
}
