package com.sbi.ems.aop;

import org.aspectj.lang.ProceedingJoinPoint;
import org.aspectj.lang.annotation.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

/**
 * Cross-cutting audit and performance logging via AOP.
 *
 * DevSecOps fixes (A02 — Cryptographic Failures / PII Protection):
 *
 *   BEFORE (vulnerable):
 *     Object[] args = joinPoint.getArgs();
 *     logger.info("API CALL: {} | args={}", methodName, Arrays.toString(args));
 *     // PROBLEM: Logs the full object including salary, email, phone as plain text.
 *     //          Any log aggregator (ELK, Splunk) now holds PII.
 *
 *   AFTER (secure):
 *     - Method arguments are NEVER logged — only method name and timing
 *     - Return values are NEVER logged
 *     - Exception message is logged for 5xx; full stack trace for DEBUG only
 *     - PII fields (salary, email, phone) never appear in any log entry
 *
 *   RBI Compliance:
 *     Audit logging records WHO called WHAT and WHEN — without logging the
 *     sensitive payload. The structured log entries can be ingested into a
 *     SIEM for real-time anomaly detection (e.g. unusual salary access patterns).
 */
@Aspect
@Component
public class AuditAspect {

    private static final Logger log = LoggerFactory.getLogger(AuditAspect.class);

    // Pointcut: all public methods in controllers
    @Pointcut("execution(public * com.sbi.ems.controller..*(..))")
    public void controllerMethods() {}

    // Pointcut: all public methods in services
    @Pointcut("execution(public * com.sbi.ems.service..*(..))")
    public void serviceMethods() {}

    /**
     * Log controller method entry/exit with timing.
     * DevSecOps: Arguments and return values are NOT logged.
     */
    @Around("controllerMethods()")
    public Object logController(ProceedingJoinPoint pjp) throws Throwable {
        long start      = System.currentTimeMillis();
        String method   = pjp.getSignature().toShortString();

        log.info("[API] → {}", method);

        Object result = pjp.proceed();

        long elapsed = System.currentTimeMillis() - start;
        log.info("[API] ← {} completed in {}ms", method, elapsed);

        return result;
    }

    /**
     * Log service method timing.
     * Useful for identifying slow queries and N+1 problems.
     */
    @Around("serviceMethods()")
    public Object logService(ProceedingJoinPoint pjp) throws Throwable {
        long start    = System.currentTimeMillis();
        Object result = pjp.proceed();
        long elapsed  = System.currentTimeMillis() - start;

        if (elapsed > 500) {
            // Warn on slow service calls — may indicate missing DB indexes
            log.warn("[SERVICE] SLOW ({} ms): {}", elapsed, pjp.getSignature().toShortString());
        } else {
            log.debug("[SERVICE] {} in {}ms", pjp.getSignature().toShortString(), elapsed);
        }
        return result;
    }

    /**
     * Log exceptions from controllers and services.
     * DevSecOps: Only logs exception TYPE and message — never the request payload.
     * Full stack trace available at DEBUG level for developer troubleshooting.
     */
    @AfterThrowing(pointcut = "controllerMethods() || serviceMethods()", throwing = "ex")
    public void logException(Exception ex) {
        // Log message at WARN — stack trace at DEBUG to avoid noisy prod logs
        log.warn("[EXCEPTION] {}: {}", ex.getClass().getSimpleName(), ex.getMessage());
        log.debug("[EXCEPTION] Full stack trace:", ex);
    }
}
