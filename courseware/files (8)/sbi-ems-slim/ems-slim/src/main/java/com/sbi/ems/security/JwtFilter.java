package com.sbi.ems.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.List;

/**
 * JWT authentication filter — runs once per request.
 *
 * ── DevSecOps Fixes (A01 — Broken Access Control, A07 — Auth Failures) ──────
 *
 *  BEFORE (vulnerable):
 *    // Always assigned ROLE_USER — admin users had no special privileges
 *    List.of(new SimpleGrantedAuthority("ROLE_USER"))
 *
 *  AFTER (secure):
 *    - Roles are extracted from the JWT 'roles' claim (set at login)
 *    - Authorities correctly reflect ROLE_ADMIN vs ROLE_USER
 *    - @PreAuthorize("hasRole('ADMIN')") on salary endpoints now works
 *    - Uses constructor injection (not @Autowired field injection)
 */
@Component
public class JwtFilter extends OncePerRequestFilter {

    private final JwtUtil jwtUtil;

    public JwtFilter(JwtUtil jwtUtil) {
        this.jwtUtil = jwtUtil;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain)
            throws ServletException, IOException {

        String authHeader = request.getHeader("Authorization");

        if (authHeader != null && authHeader.startsWith("Bearer ")) {

            String token = authHeader.substring(7);

            if (jwtUtil.validateToken(token)) {

                String username = jwtUtil.extractUsername(token);

                // Extract roles from JWT claims — enables RBAC
                List<SimpleGrantedAuthority> authorities = jwtUtil.extractRoles(token)
                        .stream()
                        .map(SimpleGrantedAuthority::new)
                        .toList();

                UsernamePasswordAuthenticationToken authentication =
                        new UsernamePasswordAuthenticationToken(username, null, authorities);

                SecurityContextHolder.getContext().setAuthentication(authentication);
            }
        }

        filterChain.doFilter(request, response);
    }
}
