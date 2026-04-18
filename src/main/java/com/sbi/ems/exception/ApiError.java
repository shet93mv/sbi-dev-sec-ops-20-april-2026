package com.sbi.ems.exception;

import java.time.LocalDateTime;

/**
 * Standard API error response body.
 *
 * DevSecOps (A05 — Security Misconfiguration):
 *   Never include stack traces, SQL queries, or internal class names in
 *   error responses. The 'message' field carries a safe, human-readable
 *   description; internal details stay in server logs only.
 */
public class ApiError {

    private final LocalDateTime timestamp;
    private final int           status;
    private final String        error;
    private final String        message;
    private final String        path;

    public ApiError(LocalDateTime timestamp, int status,
                    String error, String message, String path) {
        this.timestamp = timestamp;
        this.status    = status;
        this.error     = error;
        this.message   = message;
        this.path      = path;
    }

    public LocalDateTime getTimestamp() { return timestamp; }
    public int           getStatus()    { return status; }
    public String        getError()     { return error; }
    public String        getMessage()   { return message; }
    public String        getPath()      { return path; }
}
