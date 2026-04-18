# DevSecOps — Intermediate | Participant Courseware
## DAY 1
**Secure Coding · SAST · DAST · Secrets Management · CI/CD Integration**

*Project: SBI Employee Management System (EMS) — Spring Boot REST API*
*State Bank of India — Technology Training Programme*

---

## Day 1 Schedule

| Time | Session | Topics |
|---|---|---|
| 10:30 – 11:30 | **Secure Coding Practices** | OWASP Top 10, injection, broken auth, code-level controls on EMS |
| 11:30 – 12:15 | **SAST Concepts + Tools** | Static analysis, SonarQube, taint analysis, EMS scan walkthrough |
| 12:15 – 12:30 | Break | — |
| 12:30 – 1:30 | **Lab 1: SAST Scan + Fix** | SonarQube scan of EMS, triage two Critical issues, re-scan |
| 1:30 – 2:15 | **DAST Concepts + Tools** | Dynamic testing, OWASP ZAP, scanning running apps |
| 2:15 – 3:00 | Lunch | — |
| 3:00 – 4:00 | **Lab 2: DAST Scan** | ZAP active scan of EMS, vulnerability analysis |
| 4:00 – 4:45 | **Secrets Management** | HashiCorp Vault, detect-secrets, best practices |
| 4:45 – 5:15 | **CI/CD Integration** | Pipeline gates, SAST+DAST in GitHub Actions |
| 5:15 – 5:30 | Wrap-up + Q&A | Open questions, action items |

---

## The EMS Project — Quick Reference

EMS is a Spring Boot REST API with three entities and two controllers. Keep this in mind as you work through today's labs.

| Entity | Fields | Security relevance |
|---|---|---|
| `Employee` | id, firstName, lastName, email, **salary**, status, departmentId | `salary` is PII — the A01 access-control lab target |
| `Department` | id, name | FK on Employee; target of the capstone SQL injection demo |
| `Project` | id, name, **status** | `status` state machine — the A04 insecure design demo |

**Two controllers, two labs:**

| Controller | Endpoints | Lab |
|---|---|---|
| `EmployeeController` | GET/POST/PUT/DELETE `/api/v1/employees` | Lab 1 (SAST) + Lab 2 (DAST) |
| `ProjectController` | GET `/api/v1/projects`, PUT `/api/v1/projects/{id}/status` | Day 2 — A04 demo |

---

# Module 1: Secure Coding Practices
`10:30 – 11:30` · OWASP Top 10 · Input Validation · Authentication · Error Handling

Secure coding is the practice of writing software that is resilient to attack from the moment it is written — not as an afterthought. For a banking application like EMS, a single exploitable flaw in a REST endpoint can expose salary data, enable unauthorized access to employee records, or allow an attacker to pivot deeper into the bank's network.

## 1.1 Why Secure Coding Matters in Banking

Banks are among the most targeted organisations in the world. RBI's IT Framework for Banks (updated 2023) and CERT-In directives mandate that development teams follow secure coding standards. The cost of a post-deployment fix is 6–100x higher than catching the same issue at code review. EMS uses the same patterns, frameworks, and data types (PII: salary, email) found in real banking systems.

## 1.2 The OWASP Top 10 — Banking Context

---

### A01:2021 — Broken Access Control

Broken Access Control is the #1 risk. It occurs when the application does not properly enforce what authenticated users are allowed to do.

**EMS Example** — The `salary` field is PII. Only the employee themselves and HR Admins should see it. A broken access control vulnerability returns salary to **any** authenticated caller:

```
GET /api/v1/employees/1  →  returns { salary: 55000 } to ANY authenticated user
```

**In `EmployeeController.java` (Lab 1 fix target):**

```java
// VULNERABLE — salary always included regardless of who is calling
@GetMapping("/{id}")
public ResponseEntity<EmployeeResponse> getEmployeeById(
        @PathVariable Long id, Authentication auth) {
    boolean includeSalary = true;  // ⚠️ VULNERABLE — fix this in Lab 1
    return ResponseEntity.ok(employeeService.getEmployeeById(id, includeSalary));
}

// FIXED — salary only for ADMIN or the employee themselves
@GetMapping("/{id}")
public ResponseEntity<EmployeeResponse> getEmployeeById(
        @PathVariable Long id, Authentication auth) {
    boolean includeSalary = isAdminOrSelf(auth, id);   // ← fix
    return ResponseEntity.ok(employeeService.getEmployeeById(id, includeSalary));
}
```

The salary masking happens in `EmployeeResponse.from()`:

```java
// EmployeeResponse.java — single point of salary inclusion logic
public static EmployeeResponse from(Employee e, boolean includeSalary) {
    EmployeeResponse r = new EmployeeResponse();
    r.salary = includeSalary ? e.getSalary() : null;  // PII gate
    // ... other fields
    return r;
}
```

`@JsonInclude(NON_NULL)` on the class means a `null` salary is **omitted from the JSON entirely** — not returned as `null`, not visible at all.

> **Key Principle:** Always enforce authorization at the SERVICE layer too, not just at the controller. Defence in depth means every layer checks permissions independently.

---

### A02:2021 — Cryptographic Failures

Sensitive data transmitted or stored without adequate encryption.

- Always use HTTPS (TLS 1.2+).
- Never log sensitive fields. The `Employee.toString()` in EMS explicitly redacts salary and email:

```java
// Employee.java — DevSecOps A02: PII never in logs
@Override
public String toString() {
    return "Employee{id=" + id + ", name=" + firstName + " " + lastName
           + ", email=[REDACTED], salary=[REDACTED], status=" + status + "}";
}
```

- Store passwords using BCrypt — never MD5, SHA-1, or plain text:

```java
// SecurityConfig.java
@Bean
public PasswordEncoder passwordEncoder() {
    return new BCryptPasswordEncoder(12); // cost factor 12
}
```

---

### A03:2021 — Injection

SQL injection remains devastatingly common in banking applications.

EMS uses Spring Data JPA which generates parameterized queries by default. However, the `EmployeeRepository` contains an intentionally vulnerable query for the Capstone Lab:

```java
// EmployeeRepository.java — ⚠️ VULNERABLE (Capstone Lab target)
@Query(value = "SELECT * FROM employees e JOIN departments d " +
               "ON e.department_id = d.id " +
               "WHERE d.name = ':deptName'", nativeQuery = true)
List<Employee> findByDepartmentNameUnsafe(@Param("deptName") String deptName);
// BUG: single quotes around :deptName mean the parameter is never substituted.
// Fix: remove the quotes → WHERE d.name = :deptName

// SAFE — Spring Data derived query (no SQL string at all)
List<Employee> findByFirstNameContainingIgnoreCaseOrLastNameContainingIgnoreCase(
        String firstName, String lastName);
```

> **Banking-Specific Risk:** SQL injection on an employee search endpoint could extract ALL employee salary records with `?name=' OR '1'='1` — mass PII exposure triggering RBI data breach notification requirements.

---

### A04:2021 — Insecure Design

Design-level flaws that cannot be fixed by implementation alone.

**EMS Example — Project State Machine** (`ProjectController.java`):

The rule "a project cannot move directly from PLANNED to COMPLETED" is enforced via a state machine. If this rule were not enforced at the API layer, a single bad request could corrupt project lifecycle data.

```java
// ProjectController.java — ALLOWED_TRANSITIONS map
private static final Map<ProjectStatus, Set<ProjectStatus>> ALLOWED_TRANSITIONS = Map.of(
    ProjectStatus.PLANNED,   Set.of(ProjectStatus.ACTIVE, ProjectStatus.CANCELLED),
    ProjectStatus.ACTIVE,    Set.of(ProjectStatus.ON_HOLD, ProjectStatus.COMPLETED, ProjectStatus.CANCELLED),
    ProjectStatus.ON_HOLD,   Set.of(ProjectStatus.ACTIVE, ProjectStatus.CANCELLED),
    ProjectStatus.COMPLETED, Set.of(),   // terminal — no further transitions
    ProjectStatus.CANCELLED, Set.of()    // terminal — no further transitions
);

// In the update endpoint — invalid transition returns 422
Set<ProjectStatus> allowed = ALLOWED_TRANSITIONS.get(project.getStatus());
if (!allowed.contains(newStatus)) {
    throw new InvalidStateTransitionException(
        "Invalid transition: " + project.getStatus() + " → " + newStatus);
}
```

**Also A04 — Soft Delete in `EmployeeServiceImpl.java`:**

```java
// Physical deletion is PROHIBITED — RBI requires audit trail retention
public void deleteEmployee(Long id) {
    Employee emp = findEntityById(id);
    emp.setStatus(EmployeeStatus.TERMINATED);  // soft delete only
    employeeRepository.save(emp);
    // employeeRepository.delete(emp) would be a design violation
}
```

---

### A05:2021 — Security Misconfiguration

Common in Spring Boot applications where auto-configuration exposes sensitive endpoints by default.

**EMS `application.properties`:**

```properties
# Actuator restricted — only health and info exposed
# Never expose: env, heapdump, beans, mappings
management.endpoints.web.exposure.include=health,info

# Swagger enabled in training — disable in production:
# springdoc.api-docs.enabled=false
# springdoc.swagger-ui.enabled=false
```

**EMS `SecurityConfig.java`** — configured with security headers and explicit CORS:

```java
.headers(headers -> headers
    .frameOptions(frame -> frame.deny())          // prevent clickjacking
    .contentTypeOptions(cto -> {})                // prevent MIME sniffing
    .httpStrictTransportSecurity(hsts -> hsts     // force HTTPS
        .maxAgeInSeconds(31536000)
        .includeSubDomains(true))
    .contentSecurityPolicy(csp -> csp
        .policyDirectives("default-src 'self'; script-src 'self' 'unsafe-inline'"))
)
```

> **Lab 2 target:** ZAP will find medium-severity alerts for missing or misconfigured headers. You will fix them in `SecurityConfig.java` and re-scan.

---

### A06:2021 — Vulnerable and Outdated Components

```bash
# Scan EMS Maven dependencies for known CVEs
mvn dependency-check:check

# Show available updates
mvn versions:display-dependency-updates
```

---

### A07:2021 — Identification and Authentication Failures

**EMS `JwtUtil.java`** — the Lab 1 Fix 1 target:

```java
// VULNERABLE — hardcoded secret in source code (Lab 1 SAST target)
private static final String HARDCODED_SECRET = "SBIBankingSecretKey2024";  // ⚠️
private static final long   HARDCODED_EXPIRY  = 86400000L;                 // ⚠️ 24h

// FIXED — inject from environment variable
@Value("${jwt.secret}")
private String jwtSecret;

@Value("${jwt.expiration.ms:900000}")  // 15 minutes for banking
private long jwtExpirationMs;
```

---

### A08:2021 — Software and Data Integrity Failures

- Pin dependency versions in `pom.xml` — never use `LATEST` or `RELEASE`.
- Use `./mvnw` (the wrapper) so the Maven version is pinned and reproducible in CI.
- Restrict write access to `.github/workflows/` — pipeline files are attack surface.

---

### A09:2021 — Security Logging and Monitoring Failures

**EMS `AuditAspect.java`** logs every controller and service method with timing — without logging arguments or return values (which would expose PII):

```java
// AuditAspect.java — method name and timing logged; arguments NEVER logged
@Around("controllerMethods()")
public Object logController(ProceedingJoinPoint pjp) throws Throwable {
    long start = System.currentTimeMillis();
    log.info("[API] → {}", pjp.getSignature().toShortString());   // no args

    Object result = pjp.proceed();

    log.info("[API] ← {} in {}ms",
        pjp.getSignature().toShortString(),
        System.currentTimeMillis() - start);                        // no return value
    return result;
}
```

---

### A10:2021 — Server-Side Request Forgery (SSRF)

- Validate and whitelist any URL parameter your application fetches.
- Never allow user-controlled input to directly form an outbound request URL.
- In banking cloud deployments, `169.254.169.254` (AWS metadata endpoint) is the primary SSRF target.

---

## 1.3 Input Validation — The First Line of Defence

`EmployeeRequest.java` uses Bean Validation on every user-supplied field:

```java
public class EmployeeRequest {

    @NotBlank(message = "First name is required")
    @Size(min = 2, max = 50, message = "First name must be 2-50 characters")
    @Pattern(regexp = "^[a-zA-Z\\s-]+$",
             message = "First name must contain only letters, spaces, or hyphens")
    private String firstName;

    @NotBlank
    @Email(message = "Must be a valid email address")
    private String email;

    @NotNull
    @Positive(message = "Salary must be a positive value")
    @DecimalMax(value = "9999999.99", message = "Salary exceeds maximum allowed value")
    private BigDecimal salary;

    @NotNull
    private EmployeeStatus status;

    @NotNull
    private Long departmentId;
}

// Controller — activate validation with @Valid
@PostMapping
@PreAuthorize("hasRole('ADMIN')")
public ResponseEntity<EmployeeResponse> createEmployee(
        @Valid @RequestBody EmployeeRequest request) {
    return ResponseEntity.status(201).body(employeeService.createEmployee(request));
}
```

## 1.4 Secure Error Handling

`GlobalExceptionHandler.java` returns safe messages to the client and logs full detail internally:

```java
// Validation failure — safe to return field-level detail
@ExceptionHandler(MethodArgumentNotValidException.class)
public ResponseEntity<ApiError> handleValidation(MethodArgumentNotValidException ex,
                                                  HttpServletRequest request) {
    String message = ex.getBindingResult().getFieldErrors().stream()
            .map(fe -> fe.getField() + ": " + fe.getDefaultMessage())
            .collect(Collectors.joining("; "));
    return build(HttpStatus.BAD_REQUEST, "Validation Failed", message, request);
}

// Unexpected error — NEVER expose internals to the client
@ExceptionHandler(Exception.class)
public ResponseEntity<ApiError> handleGeneral(Exception ex, HttpServletRequest request) {
    log.error("Unhandled exception at {}: {}", request.getRequestURI(), ex.getMessage(), ex);
    return build(HttpStatus.INTERNAL_SERVER_ERROR, "Internal Server Error",
                 "An unexpected error occurred. Please contact support.", request);
}
```

> **RBI Compliance Note:** RBI IT Framework §3.2 requires that error messages do not disclose system internals. Stack traces and SQL errors must never appear in HTTP responses.

---

# Module 2: Static Application Security Testing (SAST)
`11:30 – 12:15` · SonarQube · Semgrep · Taint Analysis · CI Integration

Static Application Security Testing analyses source code for security vulnerabilities **without executing the application**. It is the shift-left cornerstone of DevSecOps — finding defects early when they are cheapest to fix.

## 2.1 How SAST Works

| Technique | What it detects |
|---|---|
| Pattern matching | Deprecated APIs, hardcoded strings, obvious injection patterns |
| Taint analysis | Tracks user-controlled data from sources to unsafe sinks. Finds injection, XSS, SSRF. |
| Data flow analysis | Null-pointer dereferences, resource leaks |
| Control flow analysis | Unreachable code, improper error propagation |

## 2.2 SAST in the DevSecOps Pipeline

```
Developer writes code
    │
    ▼
SonarLint (VS Code extension) ──► highlights issues in real-time
    │
    ▼
git push / pull request
    │
    ▼
CI Pipeline: mvn sonar:sonar ──► SonarQube server analysis
    │                             reports to PR / breaks build
    ▼
Quality Gate PASS / FAIL
```

## 2.3 SonarQube — Key Concepts

- **Rules:** SonarQube ships 600+ Java rules; security-relevant ones are tagged `owasp-top10`.
- **Issues:** Bug, Vulnerability, Security Hotspot, or Code Smell.
- **Quality Gate:** Pass/fail condition (e.g. 'no new Critical vulnerabilities').
- **Security Hotspot:** Potential vulnerability requiring human review.

| Severity | Meaning | EMS Example |
|---|---|---|
| Blocker | Must fix before deploy | SQL string concatenation |
| Critical | Fix in current sprint | Hardcoded JWT secret (`HARDCODED_SECRET` in JwtUtil.java) |
| Major | Fix before next release | Missing `@Valid` on a controller method |
| Minor | Fix opportunistically | Unused import |
| Info | Informational | Missing Javadoc on public API |

## 2.4 Configuring SonarQube for EMS

```xml
<!-- pom.xml — SonarQube config (already present) -->
<properties>
    <sonar.host.url>http://SONAR_SERVER_IP:9000</sonar.host.url>
    <sonar.projectKey>sbi-ems</sonar.projectKey>
    <sonar.projectName>SBI Employee Management System</sonar.projectName>
    <sonar.java.source>17</sonar.java.source>
    <sonar.exclusions>**/test/**,**/generated/**</sonar.exclusions>
</properties>
```

```bash
# Run analysis — trainer provides SONAR_IP and TOKEN
mvn clean verify sonar:sonar -Dsonar.token=YOUR_TOKEN
```

## 2.5 Reading a SonarQube Report

- **Rule ID + description** — what was found and why it matters.
- **File + line number** — click to open the problematic line in-browser.
- **Data flow diagram** — for taint analysis findings, shows the complete path from user input (source) to unsafe operation (sink). This is the most valuable feature for understanding injection vulnerabilities.

> **Lab 1 Preview:** You will find two Critical issues in EMS: a hardcoded JWT secret in `JwtUtil.java` and a missing authorization check in `EmployeeController.java`. You will fix both and re-scan to confirm the Quality Gate passes.

## 2.6 Semgrep — Lightweight Rule-Based Scanning

```bash
# Scan EMS with OWASP Top 10 rules
semgrep --config=p/owasp-top-ten ./src

# Scan for Java-specific security issues
semgrep --config=p/java ./src
```

```yaml
# Custom rule — detect hardcoded secrets in EMS
# rules/no-hardcoded-secrets.yaml
rules:
  - id: no-hardcoded-jwt-secret
    pattern: |
      private static final String $SECRET = "..."
    message: Hardcoded secret detected — use @Value or Vault
    severity: ERROR
    languages: [java]
```

---

# Lab 1: SAST Scan + Fix
`12:30 – 1:30` · SonarQube scan of EMS · Triage two Critical issues · Re-scan

> **Lab Objective:** Run SonarQube on EMS, identify two Critical issues (hardcoded JWT secret + salary exposed to all callers), fix both, re-scan, confirm Quality Gate passes.

## Step 1 — Open the Project

1. Open VS Code.
2. **File > Open Folder** → select the `ems/` folder on your Desktop.
3. Open a Terminal inside VS Code (`Ctrl + `` `).

## Step 2 — Build EMS

```bash
mvn clean package -DskipTests
```

Wait for `BUILD SUCCESS`.

## Step 3 — Run the SonarQube Scan

Your trainer will provide `SONAR_IP` and `TOKEN`:

```bash
mvn sonar:sonar \
  -Dsonar.host.url=http://SONAR_IP:9000 \
  -Dsonar.token=YOUR_TOKEN
```

The console prints: `ANALYSIS SUCCESSFUL, you can find the results at: http://SONAR_IP:9000/dashboard?id=sbi-ems`

## Step 4 — Explore the Dashboard

1. Open the URL in Chrome.
2. Note the Quality Gate status (likely **FAILED** on first scan).
3. Click **Vulnerabilities** in the left panel.
4. Click the first Critical issue — read the rule, the file, and the data flow diagram.
5. Answer: what is the user-controlled source, and what is the unsafe sink?

## Step 5 — Fix Issue 1: Hardcoded JWT Secret

Open `src/main/java/com/sbi/ems/security/JwtUtil.java`.

Find the two vulnerable lines near the top:

```java
// ⚠️ VULNERABLE — SonarQube rule: java:S6418
private static final String HARDCODED_SECRET = "SBIBankingSecretKey2024";
private static final long   HARDCODED_EXPIRY  = 86400000L;
```

**Delete those two lines.** Then uncomment the fix block directly below them:

```java
// ✅ FIXED — uncomment these:
@Value("${jwt.secret}")
private String jwtSecret;

@Value("${jwt.expiration.ms:900000}")   // 15 minutes for banking
private long jwtExpirationMs;
```

Update the constructor to use the injected fields instead of the constants:

```java
public JwtUtil(@Value("${jwt.secret}") String secret,
               @Value("${jwt.expiration.ms:900000}") long expirationMs) {

    if (secret == null || secret.isBlank() || secret.startsWith("CHANGE")) {
        throw new IllegalStateException(
            "[SECURITY] JWT_SECRET env variable is not set. " +
            "Generate with: openssl rand -hex 32");
    }
    this.signingKey   = Keys.hmacShaKeyFor(secret.getBytes(StandardCharsets.UTF_8));
    this.expirationMs = expirationMs;
}
```

Confirm `application.properties` already has:

```properties
jwt.secret=${JWT_SECRET:CHANGE_THIS_IN_PRODUCTION}
jwt.expiration.ms=${JWT_EXPIRATION_MS:900000}
```

Set the environment variable for your local run (use the `.env` file):

```
JWT_SECRET=<generate with: openssl rand -hex 32>
```

## Step 6 — Fix Issue 2: Salary Exposed to All Callers

Open `src/main/java/com/sbi/ems/controller/EmployeeController.java`.

Find the `getEmployeeById` method:

```java
// ⚠️ VULNERABLE — salary always returned regardless of caller
boolean includeSalary = true;
```

Replace with:

```java
// ✅ FIXED — salary only for ADMIN or the employee themselves
boolean includeSalary = isAdminOrSelf(auth, id);
```

The `isAdminOrSelf` helper is already in the controller. It currently only checks for ADMIN. Extend it to also allow an employee to see their own record:

```java
private boolean isAdminOrSelf(Authentication auth, Long employeeId) {
    if (isAdmin(auth)) return true;
    // Self-access: JWT subject (username) matches the employee's email
    Employee emp = employeeService.findEntityById(employeeId);
    return auth.getName().equals(emp.getEmail());
}
```

## Step 7 — Re-run the Scan

```bash
mvn clean package -DskipTests sonar:sonar \
  -Dsonar.host.url=http://SONAR_IP:9000 \
  -Dsonar.token=YOUR_TOKEN
```

Refresh the dashboard. Confirm both Critical issues are resolved and the Quality Gate shows **PASSED**.

> **Verify:** Call `GET /api/v1/employees/1` as `emp.user` — salary should be absent from the response. Call it as `hr.admin` — salary should appear.

---

# Module 3: Dynamic Application Security Testing (DAST)
`1:30 – 2:15` · OWASP ZAP · Active Scanning · API Fuzzing · Vulnerability Analysis

Where SAST analyses code without running it, DAST tests the **live, running application** from the outside — exactly as an attacker would.

## 3.1 SAST vs DAST — Complementary, Not Competing

| SAST | DAST |
|---|---|
| Analyses source code | Analyses the running application via HTTP |
| No application needed to run | Application must be running |
| Finds issues early (pre-deployment) | Finds runtime issues SAST cannot see |
| Good for: injection, hardcoded secrets | Good for: missing headers, CORS, auth bypass |

> **DevSecOps Practice:** Run SAST on every commit. Run DAST on every deployment to staging. Both are required — a misconfigured CORS header set via an environment variable will be invisible to SAST but caught immediately by DAST.

## 3.2 OWASP ZAP — Architecture and Modes

- **Spider:** Crawls the application, discovers endpoints.
- **Active Scan:** Sends attack payloads to each parameter. This is the DAST scan proper.
- **Passive Scan:** Analyses traffic without sending extra requests. Safe for production.
- **Fuzzer:** Sends a wordlist to a specific parameter — targeted injection testing.

## 3.3 Understanding ZAP Alerts

| Risk Level | CVSS Range | Examples |
|---|---|---|
| High | 7.0 – 10.0 | SQL injection, RCE, authentication bypass |
| Medium | 4.0 – 6.9 | Missing security headers, CORS misconfiguration |
| Low | 0.1 – 3.9 | Information disclosure, verbose error messages |
| Informational | N/A | Server version in headers |

## 3.4 Scanning EMS with ZAP

ZAP uses the OpenAPI spec at `/v3/api-docs` to discover all endpoints automatically — no manual crawling needed.

```bash
# Step 1 — Start EMS
docker compose up -d

# Step 2 — Confirm API is running
curl http://localhost:8080/actuator/health

# Step 3 — Confirm OpenAPI spec is available
curl http://localhost:8080/v3/api-docs | python -m json.tool | head -20

# Step 4 — Get a JWT token for authenticated scanning
curl -s -X POST http://localhost:8080/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"hr.admin","password":"Admin@SBI123"}'

# Step 5 — In ZAP GUI: Import > Import an OpenAPI definition from a URL
# URL: http://localhost:8080/v3/api-docs
# Then: right-click EMS context > Attack > Active Scan
```

## 3.5 Expected DAST Findings for EMS

| Finding | Endpoint | Remediation in EMS |
|---|---|---|
| Missing Content-Security-Policy | All | Already in `SecurityConfig.java` — verify ZAP sees it |
| X-Content-Type-Options not set | All | `contentTypeOptions()` in SecurityConfig |
| CORS misconfiguration | All | `corsConfigurationSource()` — check allowed origins |
| Verbose error in 500 response | Any | `GlobalExceptionHandler` — confirm stack traces are suppressed |
| JWT token in URL parameter | Auth | Always send in `Authorization: Bearer` header, never in URL |

## 3.6 Adding / Verifying Security Headers in EMS

Open `SecurityConfig.java` and confirm the `headers()` block is present:

```java
.headers(headers -> headers
    .frameOptions(frame -> frame.deny())
    .contentTypeOptions(cto -> {})
    .httpStrictTransportSecurity(hsts -> hsts
        .maxAgeInSeconds(31536000)
        .includeSubDomains(true))
    .contentSecurityPolicy(csp -> csp
        .policyDirectives("default-src 'self'; script-src 'self' 'unsafe-inline'"))
)
```

If any header is missing, add it here, rebuild, and re-scan.

---

# Lab 2: DAST Scan + Vulnerability Analysis
`3:00 – 4:00` · ZAP active scan of EMS · Analyse alerts · Verify security headers

> **Lab Objective:** Start EMS, import its OpenAPI spec into ZAP, run an active scan, analyse all High and Medium alerts, confirm security headers are present.

## Step 1 — Start EMS

```bash
docker compose up -d
curl -s http://localhost:8080/actuator/health
```

Expected: `{"status":"UP"}`

## Step 2 — Open OWASP ZAP

1. Launch ZAP from your Desktop.
2. Select **"No, I do not want to persist this session"**.

## Step 3 — Import the OpenAPI Spec

1. In ZAP: **Import > Import an OpenAPI definition from a URL**.
2. Enter: `http://localhost:8080/v3/api-docs`
3. Click Import. ZAP discovers all EMS endpoints automatically — you will see `/api/v1/employees`, `/api/v1/projects`, `/api/v1/auth/login` in the Sites panel.

## Step 4 — Authenticate ZAP

```bash
curl -s -X POST http://localhost:8080/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"hr.admin","password":"Admin@SBI123"}'
```

Copy the `token` value. In ZAP: **Tools > Options > Replace in Request** (or HTTP Sender script) — add `Authorization: Bearer <token>` to all requests.

## Step 5 — Run Active Scan

1. Right-click `http://localhost:8080` in the Sites panel → **Attack > Active Scan**.
2. Scan takes 5–10 minutes. Watch the **Alerts** tab.

## Step 6 — Analyse Alerts

Sort by Risk (High → Medium → Low). For each High/Medium alert:

```
Alert Name:      ___________________________________
Risk Level:      High / Medium / Low
Affected URL:    ___________________________________
What it means:   ___________________________________
Fix applied in:  ___________________________________  (SecurityConfig / Controller / etc.)
```

## Step 7 — Verify Headers

```bash
# Check response headers directly
curl -v http://localhost:8080/api/v1/employees 2>&1 | grep -i "x-content\|x-frame\|strict\|csp"
```

Expected output should include:
- `X-Content-Type-Options: nosniff`
- `X-Frame-Options: DENY`
- `Strict-Transport-Security: max-age=31536000; includeSubDomains`
- `Content-Security-Policy: default-src 'self'...`

> **Expected Result:** After confirming headers, Medium-severity ZAP alerts for missing headers should not appear (or should appear as low-confidence). Discuss any remaining High alerts with the trainer.

---

# Module 4: Secrets Management
`4:00 – 4:45` · detect-secrets · Environment Variables · HashiCorp Vault · Best Practices

A **secret** is any sensitive configuration value that, if exposed, could lead to unauthorised access.

## 4.1 The Secret Sprawl Problem

```java
// Pattern 1 — Hardcoded in source (in git history FOREVER)
// JwtUtil.java — before the Lab 1 fix:
private static final String HARDCODED_SECRET = "SBIBankingSecretKey2024";
```

```properties
# Pattern 2 — Literal value in application.properties committed to git
# jwt.secret=SBIBankingSecretKey2024
```

```yaml
# Pattern 3 — In Docker Compose committed to git
environment:
  DB_PASSWORD: SBI_EMS_DB_2024!
```

> **Real Incident Pattern:** A bank developer accidentally committed an AWS access key to a public GitHub repository. Within 4 minutes, automated scanners had found it and used it to spin up crypto-mining instances. Incident response cost: $12,000 in cloud bills + regulatory notification. The key had been in the repository for 3 years before discovery.

## 4.2 Secret Detection — detect-secrets

```bash
# Scan the EMS repository for existing secrets
detect-secrets scan . > .secrets.baseline
detect-secrets audit .secrets.baseline

# Install as a pre-commit hook — blocks commits containing secrets
cat > .git/hooks/pre-commit << 'EOF'
#!/bin/sh
detect-secrets-hook --baseline .secrets.baseline
EOF
chmod +x .git/hooks/pre-commit

# Test it — try to commit a file with a fake password
echo "password=SuperSecret123" > test.txt
git add test.txt && git commit -m "test"
# Expected: BLOCKED by pre-commit hook
```

## 4.3 Environment Variables — The Right Approach

`application.properties` references env vars — never literal values:

```properties
jwt.secret=${JWT_SECRET:CHANGE_THIS_IN_PRODUCTION}
jwt.expiration.ms=${JWT_EXPIRATION_MS:900000}

app.security.admin.password=${ADMIN_PASSWORD:Admin@SBI123}
```

`.env` file (gitignored):

```
JWT_SECRET=<generate with: openssl rand -hex 32>
ADMIN_PASSWORD=Admin@SBI123
```

```yaml
# docker-compose.yml uses the .env file — never commits secrets
services:
  ems:
    env_file: .env    # .env is in .gitignore
```

## 4.4 HashiCorp Vault — Enterprise Secrets Management

- **Dynamic secrets:** Vault generates short-lived database credentials — no static password to steal.
- **Audit log:** Every secret access is logged — who accessed what, when (RBI compliance).
- **Access policies:** Each application only accesses the secrets it needs (least privilege).
- **Secret leases:** Secrets expire automatically — limits blast radius of a compromise.

```bash
# Start Vault in dev mode (lab only)
docker run --rm -d --name vault \
  -p 8200:8200 \
  -e VAULT_DEV_ROOT_TOKEN_ID=root \
  hashicorp/vault:latest

export VAULT_ADDR=http://localhost:8200
export VAULT_TOKEN=root

# Store EMS secrets
vault kv put secret/ems \
  jwt_secret=$(openssl rand -hex 32)

# Retrieve
vault kv get -field=jwt_secret secret/ems
```

## 4.5 Spring Boot + Vault Integration

```xml
<!-- pom.xml — add to use Vault as config source -->
<dependency>
    <groupId>org.springframework.cloud</groupId>
    <artifactId>spring-cloud-starter-vault-config</artifactId>
</dependency>
```

```properties
# bootstrap.properties
spring.cloud.vault.uri=http://localhost:8200
spring.cloud.vault.token=${VAULT_TOKEN}
spring.cloud.vault.kv.enabled=true
spring.cloud.vault.kv.backend=secret
spring.cloud.vault.kv.application-name=ems

# application.properties — Vault-sourced value
jwt.secret=${jwt_secret}
```

> **Banking Best Practices:**
> 1. Never commit secrets to git — use pre-commit hooks.
> 2. Rotate secrets regularly — Vault automates this for databases.
> 3. Use separate secrets per environment (dev / staging / prod).
> 4. Audit who accesses secrets — Vault provides this log.
> 5. Use short-lived tokens — limits blast radius of credential theft.

---

# Module 5: CI/CD Security Integration
`4:45 – 5:15` · Pipeline Gates · SAST in CI · DAST in CD · GitHub Actions

Embedding security tools into the CI/CD pipeline transforms security from a periodic audit into a continuous, automated process.

## 5.1 The Secure Pipeline Model

| Stage | Gate | Tool |
|---|---|---|
| Pre-commit | Block secrets before they reach git | detect-secrets hook |
| Build (CI) | Block Critical vulnerabilities in code | SonarQube Quality Gate |
| Deploy (CD) | Block High-risk vulnerabilities at runtime | OWASP ZAP DAST |

## 5.2 GitHub Actions Pipeline for EMS

```yaml
# .github/workflows/devsecops.yml
name: EMS DevSecOps Pipeline

on:
  push:
    branches: [ main, develop ]
  pull_request:
    branches: [ main ]

jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
    - name: Checkout code
      uses: actions/checkout@v3
      with:
        fetch-depth: 0    # full history for SonarQube blame data

    - name: Set up Java 17
      uses: actions/setup-java@v3
      with:
        java-version: '17'
        distribution: 'temurin'

    - name: Detect secrets
      run: |
        pip install detect-secrets
        detect-secrets scan . > /tmp/secrets-baseline.json

    - name: SAST — SonarQube scan
      env:
        SONAR_TOKEN: ${{ secrets.SONAR_TOKEN }}
        SONAR_HOST_URL: ${{ secrets.SONAR_HOST_URL }}
      run: |
        mvn clean verify sonar:sonar \
          -Dsonar.qualitygate.wait=true \
          -Dsonar.qualitygate.timeout=300

    - name: Build Docker image
      run: docker build -t ems:${{ github.sha }} .

    - name: Container scan with Trivy
      run: |
        trivy image --severity HIGH,CRITICAL \
          --exit-code 1 \
          ems:${{ github.sha }}

    - name: Start EMS for DAST
      run: |
        docker run -d --name ems-test \
          -p 8080:8080 \
          -e JWT_SECRET=${{ secrets.JWT_SECRET }} \
          ems:${{ github.sha }}
        sleep 20

    - name: DAST — ZAP API scan
      run: |
        docker run --network=host \
          ghcr.io/zaproxy/zaproxy:stable \
          zap-api-scan.py \
          -t http://localhost:8080/v3/api-docs \
          -f openapi \
          -r zap-report.html

    - name: Upload ZAP report
      uses: actions/upload-artifact@v3
      with:
        name: zap-report
        path: zap-report.html
```

## 5.3 Quality Gate Configuration

| Condition | Threshold |
|---|---|
| New Blocker Issues | = 0 |
| New Critical Issues | = 0 |
| New Coverage on New Code | >= 70% |
| Security Hotspots Reviewed | = 100% |

## 5.4 Day 1 Summary

| Module | Key Takeaway | Where in EMS |
|---|---|---|
| Secure Coding | OWASP Top 10; input validation; safe error handling | `EmployeeRequest.java`, `GlobalExceptionHandler.java` |
| SAST | SonarQube finds hardcoded secrets + missing auth | Fixed `JwtUtil.java` + `EmployeeController.java` |
| DAST | ZAP finds runtime issues SAST cannot see | Verified headers in `SecurityConfig.java` |
| Secrets | Secrets in git = secrets forever; use env vars + Vault | `.env`, `application.properties`, Vault demo |
| CI/CD | Automate all gates — a manual gate gets skipped | `.github/workflows/devsecops.yml` |

> **Day 2 Preview:** Tomorrow — Container Security (Trivy scan of the EMS Docker image), IaC Security (Checkov on the EMS Terraform config), and a Capstone Lab where you introduce a SQL injection vulnerability and drive it through the full pipeline until all gates pass.

---

*Confidential — For Training Purposes Only*
*DevSecOps Intermediate · State Bank of India · Technology Training Programme*
