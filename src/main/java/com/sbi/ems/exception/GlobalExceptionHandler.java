package com.sbi.ems.exception;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.ConstraintViolationException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.method.annotation.MethodArgumentTypeMismatchException;

import java.time.LocalDateTime;
import java.util.stream.Collectors;

/**
 * Centralised exception handler for the EMS REST API.
 *
 * DevSecOps (A05 — Security Misconfiguration):
 *
 *   BEFORE (vulnerable):
 *     // Fallback handler returned ex.getMessage() directly — could expose
 *     // SQL error messages, internal class names, stack frame details.
 *     ApiError error = new ApiError(..., ex.getMessage(), ...);
 *
 *   AFTER (secure):
 *     - 404 / 400 / 409 handlers return domain-specific, safe messages.
 *     - 403 / 401 handlers return generic security messages.
 *     - Fallback 500 handler returns ONLY "An unexpected error occurred."
 *     - Internal exception details are logged server-side only.
 *     - Stack traces NEVER reach the HTTP response body.
 */
@RestControllerAdvice
public class GlobalExceptionHandler {

    private static final Logger log = LoggerFactory.getLogger(GlobalExceptionHandler.class);

    // ── 404 — Resource not found ──────────────────────────────────────────────
    @ExceptionHandler(ResourceNotFoundException.class)
    public ResponseEntity<ApiError> handleNotFound(ResourceNotFoundException ex,
                                                   HttpServletRequest request) {
        log.warn("Resource not found: {}", ex.getMessage());
        return build(HttpStatus.NOT_FOUND, "Not Found", ex.getMessage(), request);
    }

    // ── 409 — Conflict / Duplicate ────────────────────────────────────────────
    @ExceptionHandler(ConflictException.class)
    public ResponseEntity<ApiError> handleConflict(ConflictException ex,
                                                   HttpServletRequest request) {
        log.warn("Conflict: {}", ex.getMessage());
        return build(HttpStatus.CONFLICT, "Conflict", ex.getMessage(), request);
    }

    // ── 400 — Bad request ─────────────────────────────────────────────────────
    @ExceptionHandler(BadRequestException.class)
    public ResponseEntity<ApiError> handleBadRequest(BadRequestException ex,
                                                     HttpServletRequest request) {
        log.warn("Bad request: {}", ex.getMessage());
        return build(HttpStatus.BAD_REQUEST, "Bad Request", ex.getMessage(), request);
    }

    // ── 422 — Invalid state transition ───────────────────────────────────────
    @ExceptionHandler(InvalidStateTransitionException.class)
    public ResponseEntity<ApiError> handleStateTransition(InvalidStateTransitionException ex,
                                                          HttpServletRequest request) {
        log.warn("Invalid state transition: {}", ex.getMessage());
        return build(HttpStatus.UNPROCESSABLE_ENTITY, "Invalid State Transition",
                     ex.getMessage(), request);
    }

    // ── 400 — Bean Validation (@Valid) ────────────────────────────────────────
    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<ApiError> handleValidation(MethodArgumentNotValidException ex,
                                                     HttpServletRequest request) {
        String message = ex.getBindingResult().getFieldErrors().stream()
                .map(fe -> fe.getField() + ": " + fe.getDefaultMessage())
                .collect(Collectors.joining("; "));
        log.warn("Validation failed: {}", message);
        return build(HttpStatus.BAD_REQUEST, "Validation Failed", message, request);
    }

    // ── 400 — Constraint violations (path/query params) ───────────────────────
    @ExceptionHandler(ConstraintViolationException.class)
    public ResponseEntity<ApiError> handleConstraint(ConstraintViolationException ex,
                                                     HttpServletRequest request) {
        log.warn("Constraint violation: {}", ex.getMessage());
        return build(HttpStatus.BAD_REQUEST, "Constraint Violation",
                     ex.getMessage(), request);
    }

    // ── 400 — Type mismatch in path/query params ──────────────────────────────
    @ExceptionHandler(MethodArgumentTypeMismatchException.class)
    public ResponseEntity<ApiError> handleTypeMismatch(MethodArgumentTypeMismatchException ex,
                                                       HttpServletRequest request) {
        String message = String.format("Parameter '%s' has invalid value", ex.getName());
        return build(HttpStatus.BAD_REQUEST, "Bad Request", message, request);
    }

    // ── 401 — Unauthenticated ─────────────────────────────────────────────────
    @ExceptionHandler(AuthenticationException.class)
    public ResponseEntity<ApiError> handleAuth(AuthenticationException ex,
                                               HttpServletRequest request) {
        // DevSecOps: Generic message — do not reveal WHY authentication failed
        return build(HttpStatus.UNAUTHORIZED, "Unauthorized",
                     "Authentication required", request);
    }

    // ── 403 — Forbidden ───────────────────────────────────────────────────────
    @ExceptionHandler(AccessDeniedException.class)
    public ResponseEntity<ApiError> handleForbidden(AccessDeniedException ex,
                                                    HttpServletRequest request) {
        // DevSecOps: Generic message — do not reveal internal role structure
        return build(HttpStatus.FORBIDDEN, "Forbidden",
                     "You do not have permission to perform this action", request);
    }

    // ── 500 — Catch-all ───────────────────────────────────────────────────────
    @ExceptionHandler(Exception.class)
    public ResponseEntity<ApiError> handleGeneral(Exception ex,
                                                  HttpServletRequest request) {
        // DevSecOps: Log full exception server-side; return ONLY generic message
        // to the client. NEVER return ex.getMessage() here — it may contain
        // SQL errors, internal class paths, or sensitive data.
        log.error("Unhandled exception at {}: {}", request.getRequestURI(), ex.getMessage(), ex);
        return build(HttpStatus.INTERNAL_SERVER_ERROR, "Internal Server Error",
                     "An unexpected error occurred. Please contact support.", request);
    }

    // ── Helper ────────────────────────────────────────────────────────────────
    private ResponseEntity<ApiError> build(HttpStatus status, String error,
                                           String message, HttpServletRequest request) {
        ApiError body = new ApiError(LocalDateTime.now(), status.value(),
                                     error, message, request.getRequestURI());
        return new ResponseEntity<>(body, status);
    }
}
