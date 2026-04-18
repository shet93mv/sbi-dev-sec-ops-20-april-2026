package com.sbi.ems.exception;

public class ResourceNotFoundException extends RuntimeException {
    private static final long serialVersionUID = 1L;
    public ResourceNotFoundException(String resource, String field, Object value) {
        super(String.format("%s not found with %s = '%s'", resource, field, value));
    }
    public ResourceNotFoundException(String message) { super(message); }
}
