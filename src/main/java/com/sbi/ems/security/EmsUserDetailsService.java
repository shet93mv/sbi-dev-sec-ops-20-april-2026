package com.sbi.ems.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.beans.factory.annotation.Value;
/**
 * In-memory user store for training purposes.
 *
 * Provides two accounts demonstrating RBAC:
 *   - hr.admin  / Admin@SBI123  → ROLE_ADMIN  (can see salary, manage all)
 *   - emp.user  / User@SBI123   → ROLE_USER   (limited access, salary masked)
 *
 * ── DevSecOps Fixes (A07 — Auth Failures, A02 — Cryptographic Failures) ─────
 *
 *  BEFORE (vulnerable):
 *    .username("sonu").password(encoder.encode("sonu")).roles("USER")
 *    // Weak credentials, single role, no ADMIN user
 *
 *  AFTER (secure):
 *    - Strong passwords following complexity rules
 *    - Separate ADMIN and USER roles enabling RBAC on salary endpoint
 *    - BCrypt encoding (cost 12) — work factor makes brute-force expensive
 *    - In production: replace with DB-backed UserDetailsService
 *
 * ── Training Note ─────────────────────────────────────────────────────────────
 *  In production, use a database-backed UserDetailsService with employee
 *  records. The InMemoryUserDetailsManager is acceptable only for training.
 */
@Configuration
public class EmsUserDetailsService {

	@Value("${app.security.admin.username}")
	private String adminUsername;

	@Value("${app.security.admin.password}")
	private String adminPassword;

	@Value("${app.security.user.username}")
	private String username;

	@Value("${app.security.user.password}")
	private String userPassword;
	@Bean
    public UserDetailsService userDetailsService(PasswordEncoder encoder) {

        // ADMIN — HR team: full access including salary fields
        UserDetails admin = User.builder()
                .username(adminUsername)
                .password(encoder.encode(adminPassword))
                .roles("ADMIN", "USER")
                .build();

        // USER — Regular employee: limited access, salary masked
        UserDetails user = User.builder()
                .username(username)
                .password(encoder.encode(userPassword))
                .roles("USER")
                .build();

        return new InMemoryUserDetailsManager(admin, user);
    }
}
