# SBI Employee Management System (EMS)

> **DevSecOps Training Project — State Bank of India**  
> Spring Boot 3 · JWT · Spring Security · H2 · Swagger · Maven

---

## Quick Start

```bash
# 1. Copy env template and fill in JWT_SECRET
cp .env.example .env
# Generate a strong secret:
# openssl rand -hex 32

# 2. Build and run
./mvnw clean package -DskipTests
./mvnw spring-boot:run

# Or with Docker:
docker compose up -d
```

- **API base:**    http://localhost:8080/api/v1
- **Swagger UI:**  http://localhost:8080/swagger-ui.html  (ZAP imports from here)
- **Health:**      http://localhost:8080/actuator/health

---

## Default Credentials (training only)

| Username   | Password       | Role  | Salary visible? |
|------------|----------------|-------|-----------------|
| hr.admin   | Admin@SBI123   | ADMIN | Yes             |
| emp.user   | User@SBI123    | USER  | No — masked     |

---

## API Endpoints

### Authentication
| Method | Path | Description |
|--------|------|-------------|
| POST | `/api/v1/auth/login` | Get JWT token |

### Employees
| Method | Path | Description |
|--------|------|-------------|
| GET    | `/api/v1/employees`              | List all (salary masked for USER) |
| GET    | `/api/v1/employees/{id}`         | Get by ID (**Lab 1 fix target**) |
| GET    | `/api/v1/employees/department/{id}` | Filter by department |
| GET    | `/api/v1/employees/search?name=` | Safe derived query (A03 demo) |
| POST   | `/api/v1/employees`              | Create — ADMIN only |
| PUT    | `/api/v1/employees/{id}`         | Update — ADMIN only |
| DELETE | `/api/v1/employees/{id}`         | Soft delete — ADMIN only |

### Projects
| Method | Path | Description |
|--------|------|-------------|
| GET    | `/api/v1/projects`               | List all (filter by ?status=) |
| PUT    | `/api/v1/projects/{id}/status`   | Update status — **A04 state machine** |

---

## Lab Reference

### Lab 1 — SAST Fix Targets

```bash
./mvnw clean verify sonar:sonar \
  -Dsonar.host.url=http://SONAR_IP:9000 \
  -Dsonar.token=YOUR_TOKEN
```

**Fix 1** — `JwtUtil.java`: remove `HARDCODED_SECRET`, inject via `@Value("${jwt.secret}")`  
**Fix 2** — `EmployeeController.java`: replace `includeSalary = true` with `isAdminOrSelf(auth, id)`

### Lab 2 — DAST

```bash
docker compose up -d
# ZAP → Import OpenAPI → http://localhost:8080/v3/api-docs
# Login: POST /api/v1/auth/login  →  copy token  →  set Authorization header in ZAP
```

### Lab 3 — Container Scan

```bash
docker build -t ems:insecure .
trivy image --severity HIGH,CRITICAL ems:insecure

docker build -f Dockerfile.secure -t ems:secure .
trivy image --severity HIGH,CRITICAL ems:secure

docker images | grep ems
```

### Lab 4 — IaC Scan

```bash
cd terraform/ems
checkov -d . --compact
# Fix misconfigs, then:
checkov -d . --external-checks-dir ../custom_policies --compact
```

### Capstone — SQL Injection (introduce → SAST catches → fix)

Add to `EmployeeController.java`:

```java
// ⚠️  VULNERABLE — add for Capstone only
@GetMapping("/search-by-dept")
public ResponseEntity<?> searchByDept(@RequestParam String dept) {
    List<Employee> result = employeeRepository.findByDepartmentNameUnsafe(dept);
    return ResponseEntity.ok(result);
}
```

SonarQube will flag this Critical. ZAP confirms via active scan.  
Fix: switch to `employeeRepository.findByDepartmentId(deptId)` with validated input.

---

*Confidential — For Training Purposes Only*  
*DevSecOps Intermediate · State Bank of India*
