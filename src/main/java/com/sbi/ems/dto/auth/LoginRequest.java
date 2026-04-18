package com.sbi.ems.dto.auth;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

/**
 * Request body for POST /api/v1/auth/login.
 *
 * DevSecOps (A07 — Auth Failures):
 *   BEFORE: Credentials sent as @RequestParam — they appear in the URL,
 *           in server access logs, browser history, and proxy logs.
 *
 *   AFTER: Credentials sent as JSON request body over HTTPS.
 *          @NotBlank prevents empty credential attacks.
 *          @Size limits brute-force payload size.
 */
@Schema(description = "Login credentials")
public class LoginRequest {

    @Schema(description = "Username", example = "hr.admin", requiredMode = Schema.RequiredMode.REQUIRED)
    @NotBlank(message = "Username is required")
    @Size(min = 3, max = 50, message = "Username must be 3–50 characters")
    private String username;

    @Schema(description = "Password", example = "Admin@SBI123", requiredMode = Schema.RequiredMode.REQUIRED)
    @NotBlank(message = "Password is required")
    @Size(min = 8, max = 100, message = "Password must be 8–100 characters")
    private String password;

    public String getUsername() { return username; }
    public void setUsername(String username) { this.username = username; }
    public String getPassword() { return password; }
    public void setPassword(String password) { this.password = password; }
}
