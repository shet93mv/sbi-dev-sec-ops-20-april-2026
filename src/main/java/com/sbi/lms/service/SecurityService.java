package com.sbi.lms.service;

import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Service;

@Service
public class SecurityService {

    public boolean isManager(Authentication auth) {
        return auth != null && auth.getAuthorities().stream()
                .anyMatch(a -> a.getAuthority().equals("ROLE_MANAGER"));
    }

    /**
     * DevSecOps: PAN masking — shows only last 4 characters.
     * Example: ABCPK1234E → ******1234E
     * Comment
     * Satisfies A01 Broken Access Control for OFFICER role responses.
     */
    public String maskPan(String pan) {
        if (pan == null || pan.length() < 4) return "****";
        return "*".repeat(pan.length() - 4) + pan.substring(pan.length() - 4);
    }
}
