package com.sbi.ems.exception;

/**
 * Thrown when a project status transition violates the business state machine.
 *
 * DevSecOps (A04 — Insecure Design):
 *   Enforcing the PLANNED → ACTIVE → COMPLETED lifecycle at the service layer
 *   prevents invalid state transitions regardless of which client calls the API.
 *   This is a design-level security control, not just a validation rule.
 */
public class InvalidStateTransitionException extends RuntimeException {
    private static final long serialVersionUID = 1L;
    public InvalidStateTransitionException(String message) { super(message); }
}
