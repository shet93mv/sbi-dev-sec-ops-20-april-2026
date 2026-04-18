package com.sbi.ems.controller;

import com.sbi.ems.dto.auth.LoginRequest;
import com.sbi.ems.dto.auth.TokenResponse;
import com.sbi.ems.security.JwtUtil;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
//import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

/**
 * Authentication endpoint.
 *
 * DevSecOps fixes (A07 — Auth Failures):
 *
 * BEFORE (vulnerable): @PostMapping("/login") public String login(@RequestParam
 * String username, @RequestParam String password) // PROBLEM 1: Credentials
 * appear in the URL: /login?username=hr.admin&password=Admin123 // PROBLEM 2:
 * URL parameters are logged by web servers, proxies, browser history // PROBLEM
 * 3: Returns raw token string — no metadata // PROBLEM 4: No input validation
 *
 * AFTER (secure): - Credentials sent as JSON body (never in URL or query
 * params) - @Valid enforces @NotBlank and @Size constraints - Returns
 * structured TokenResponse with token type and expiry - Roles extracted from
 * Authentication and embedded in JWT - Endpoint mapped under /api/v1/auth/login
 * (consistent versioned prefix)
 */
@RestController
@RequestMapping("/api/v1/auth")
@Tag(name = "Authentication", description = "Login and obtain JWT token")
//@CrossOrigin(origins = "*")
public class AuthController {

	private final AuthenticationManager authenticationManager;
	private final JwtUtil jwtUtil;
	private final long expirationMs;

	public AuthController(AuthenticationManager authenticationManager, JwtUtil jwtUtil,
			@Value("${jwt.expiration.ms:3600000}") long expirationMs) {
		this.authenticationManager = authenticationManager;
		this.jwtUtil = jwtUtil;
		this.expirationMs = expirationMs;
	}

	@PostMapping("/login")
	@Operation(summary = "Authenticate and receive a JWT token", description = "Send username and password as JSON body. Returns a Bearer token.")
	public ResponseEntity<TokenResponse> login(@Valid @RequestBody LoginRequest request) {

		// Spring Security verifies credentials against UserDetailsService
		Authentication authentication = authenticationManager
				.authenticate(new UsernamePasswordAuthenticationToken(request.getUsername(), request.getPassword()));

		// Extract granted roles to embed in JWT
		List<String> roles = authentication.getAuthorities().stream().map(GrantedAuthority::getAuthority).toList();

		String token = jwtUtil.generateToken(authentication.getName(), roles);

		return ResponseEntity.ok(new TokenResponse(token, expirationMs, authentication.getName()));
	}
}
