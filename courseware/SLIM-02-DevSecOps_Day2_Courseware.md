# DevSecOps — Intermediate | Participant Courseware
## DAY 2
**Container Security · IaC Security · Integrated DevSecOps Pipeline · Banking Case Studies**

*Project: SBI Employee Management System (EMS) — Spring Boot REST API*
*State Bank of India — Technology Training Programme*

---

## Day 2 Schedule

| Time | Session | Topics |
|---|---|---|
| 10:30 – 11:30 | **Container Security** | Docker hardening, image scanning, runtime security |
| 11:30 – 12:15 | **Lab 3: Container Scan** | Trivy scan of EMS image, Dockerfile fix, hardened rebuild |
| 12:15 – 12:30 | Break | — |
| 12:30 – 1:30 | **IaC Security** | Terraform misconfigs, Checkov policy scanning |
| 1:30 – 2:15 | **Lab 4: IaC Scan** | Checkov scan of EMS Terraform, fix misconfigs, custom policy |
| 2:15 – 3:00 | Lunch | — |
| 3:00 – 4:00 | **Integrated DevSecOps Pipeline** | End-to-end pipeline, all gates, metrics |
| 4:00 – 5:00 | **Capstone Lab** | Introduce SQL injection → full pipeline → fix → all gates pass |
| 5:00 – 5:30 | **Case Studies + Q&A** | Real banking incidents, RBI compliance mapping |

---

# Module 6: Container Security
`10:30 – 11:30` · Docker Hardening · Image Scanning · Trivy · Runtime Security

Containers have become the standard deployment unit for modern banking applications. The EMS application is packaged as a Docker container. While containers provide consistency and portability, they also introduce a new attack surface that requires dedicated security controls at every layer.

## 6.1 The Container Attack Surface

| Layer | Risk | EMS Example |
|---|---|---|
| Base image | Outdated OS packages with known CVEs; running as root | `openjdk:17-jdk` — 600MB+, includes compilers, many CVEs |
| App dependencies | Maven/Spring libraries with known CVEs | Spring Boot 3.x transitive dependencies — scanned by Trivy |
| Container runtime | Excessive capabilities; privileged mode | EMS needs no Linux capabilities — drop all by default |
| Orchestration | Overly permissive RBAC | EMS pod should run with a restricted ServiceAccount |

## 6.2 Writing a Secure Dockerfile for EMS

The project ships **two Dockerfiles**:

- `Dockerfile` — intentionally insecure, used as Lab 3 starting point
- `Dockerfile.secure` — hardened reference solution

### Insecure `Dockerfile` (find the 5 problems in Lab 3)

```dockerfile
# ⚠️  INSECURE — FOR TRAINING PURPOSES ONLY
FROM openjdk:17-jdk
WORKDIR /app
COPY target/*.jar app.jar
EXPOSE 8080
ENTRYPOINT ["java", "-jar", "app.jar"]
```

**Hint — there are 5 security problems. Identify them before running Trivy.**

### Hardened `Dockerfile.secure`

```dockerfile
# Stage 1 — Build (JDK + Maven — discarded after this stage)
FROM eclipse-temurin:17-jdk-alpine AS build
WORKDIR /workspace
COPY pom.xml .
COPY src ./src
RUN ./mvnw dependency:go-offline -q
RUN ./mvnw clean package -DskipTests

# Stage 2 — Runtime (JRE only — much smaller attack surface)
FROM eclipse-temurin:17-jre-alpine

# Non-root user — NEVER run as root
RUN addgroup -S emsgroup && adduser -S emsuser -G emsgroup

WORKDIR /app
COPY --from=build /workspace/target/ems-*.jar app.jar
RUN chown emsuser:emsgroup app.jar

USER emsuser
EXPOSE 8080

# Health check — Kubernetes uses this for readiness probes
HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=3 \
  CMD wget -qO- http://localhost:8080/actuator/health || exit 1

ENTRYPOINT ["java", \
  "-XX:+UseContainerSupport", \
  "-XX:MaxRAMPercentage=75.0", \
  "-Djava.security.egd=file:/dev/./urandom", \
  "-jar", "app.jar"]
```

> **Why Non-Root Matters:** If an attacker exploits a vulnerability in EMS, running as root gives them root on the host — they can read `/etc/shadow`, escape the container, and access other workloads. Running as a non-root user (uid 1000+) limits the blast radius to the container's own files.

## 6.3 Multi-Stage Builds and Image Minimization

| Image | Size |
|---|---|
| `openjdk:17-jdk` (base) | ~600 MB — full JDK, compilers, debuggers |
| `eclipse-temurin:17-jre-alpine` (base) | ~160 MB — JRE only, Alpine Linux |
| EMS single-stage build | ~680 MB |
| EMS multi-stage build | ~210 MB |

## 6.4 Trivy — Container Vulnerability Scanning

```bash
# Basic scan
trivy image ems:insecure

# Only HIGH and CRITICAL
trivy image --severity HIGH,CRITICAL ems:insecure

# Exit code 1 on CRITICAL — use in CI to block deployment
trivy image --severity CRITICAL --exit-code 1 ems:secure

# Scan the Dockerfile itself for misconfigurations
trivy config ./Dockerfile

# Scan Maven dependencies for CVEs (without building the image)
trivy fs --security-checks vuln .
```

## 6.5 Understanding Trivy Output

```
ems:insecure (debian 11.7)
==========================
Total: 5 (HIGH: 3, CRITICAL: 2)

Library     Vulnerability  Severity  Installed  Fixed     Title
----------- -------------- --------- ---------- --------- ----
libssl1.1   CVE-2023-0215  CRITICAL  1.1.1n-0   1.1.1t-0  OpenSSL buffer overflow
...

Java (pom.xml)
==============
Total: 1 (HIGH: 1)

Library     Vulnerability  Severity  Version  Fixed   Title
----------- -------------- --------- -------- ------- ----
spring-web  CVE-2024-xxxx  HIGH      6.0.12   6.1.2   Spring MVC path traversal
```

The vulnerability count drops after switching to `Dockerfile.secure` — not because CVEs were patched, but because the full `openjdk:17-jdk` base (hundreds of OS packages) was replaced with the minimal `eclipse-temurin:17-jre-alpine`. **Reducing attack surface is as important as patching.**

## 6.6 Docker Runtime Security

```yaml
# docker-compose.yml — security constraints added to the EMS service
services:
  ems:
    image: ems:secure
    ports:
      - "8080:8080"
    env_file: .env
    security_opt:
      - no-new-privileges:true   # prevents privilege escalation
    read_only: true              # root filesystem is read-only
    tmpfs:
      - /tmp
    cap_drop:
      - ALL                      # drop ALL Linux capabilities
    mem_limit: 512m
    user: "1000:1000"
    healthcheck:
      test: ["CMD", "wget", "-qO-", "http://localhost:8080/actuator/health"]
      interval: 30s
      timeout: 10s
      retries: 3
```

---

# Lab 3: Container Security Scan
`11:30 – 12:15` · Build EMS image · Trivy scan · Fix Dockerfile · Rebuild · Re-scan

> **Lab Objective:** Build the insecure EMS Docker image, scan with Trivy, identify the security problems in the Dockerfile, apply the hardened version, rebuild, and confirm the CVE count drops.

## Step 1 — Build the Project First

```bash
mvn clean package -DskipTests
```

## Step 2 — Build and Scan the Insecure Image

```bash
docker build -t ems:insecure .
trivy image --severity HIGH,CRITICAL ems:insecure
```

Note the total HIGH + CRITICAL count: `_______`

## Step 3 — Inspect the Dockerfile

Open `Dockerfile` in VS Code. List all 5 security problems you identified earlier:

```
1. _________________________________________________
2. _________________________________________________
3. _________________________________________________
4. _________________________________________________
5. _________________________________________________
```

## Step 4 — Build and Scan the Hardened Image

```bash
docker build -f Dockerfile.secure -t ems:secure .
trivy image --severity HIGH,CRITICAL ems:secure
```

New total: `_______` (should be significantly lower)

Compare sizes:

```bash
docker images | grep ems
```

## Step 5 — Scan the Dockerfile for Misconfigs

```bash
trivy config ./Dockerfile.secure
```

Any remaining misconfigurations flagged? Note them.

## Step 6 — Scan Maven Dependencies

```bash
trivy fs --security-checks vuln .
```

Are any Spring Boot dependencies flagged? Note the CVE ID and fixed version.

> **Discussion:** Why did the count drop so dramatically? The `openjdk:17-jdk` base image contains ~400 OS packages including compilers, debuggers, and curl — none of which EMS needs at runtime. Every unnecessary package is potential attack surface with its own CVE history.

---

# Module 7: Infrastructure as Code Security
`12:30 – 1:30` · Terraform Misconfigurations · Checkov · Policy-as-Code

Infrastructure as Code means defining servers, networks, databases, and security controls in code files rather than through manual console clicks. A misconfigured Terraform file can create an open S3 bucket, a publicly accessible database, or a VM with no firewall — at the speed of automation.

## 7.1 Why IaC Security is Critical in Banking

The Capital One breach of 2019 exposed 100 million customer records. Root cause: a misconfigured AWS WAF created through manual console clicks — not IaC. Had Checkov been running against IaC, the misconfiguration would have been caught before deployment. Key principles:

- **Immutable infrastructure:** never modify running infrastructure manually — all changes through IaC and code review.
- Policy scanning (Checkov) runs on every IaC change before `terraform apply`.
- **Drift detection:** alert when actual infrastructure diverges from the IaC definition.

## 7.2 EMS Terraform — Common Misconfigurations

`terraform/ems/main.tf` in the project contains **8 intentional misconfigurations** for Lab 4. The three most critical patterns:

### Misconfiguration 1: Database Publicly Accessible

```hcl
# INSECURE
resource "aws_db_instance" "ems_mysql" {
  publicly_accessible = true     # ⚠️ database reachable from internet
  storage_encrypted   = false    # ⚠️ data not encrypted at rest
  deletion_protection = false    # ⚠️ accidental deletion possible
  password            = "SBI_EMS_DB_2024!"  # ⚠️ hardcoded!
}

# SECURE
resource "aws_db_instance" "ems_mysql" {
  publicly_accessible    = false
  storage_encrypted      = true
  deletion_protection    = true
  skip_final_snapshot    = false
  password               = var.db_password
  db_subnet_group_name   = aws_db_subnet_group.private.name
  vpc_security_group_ids = [aws_security_group.rds_sg.id]
}
```

### Misconfiguration 2: S3 Bucket Publicly Accessible

```hcl
# INSECURE — all employee reports visible to internet
resource "aws_s3_bucket_acl" "ems_reports_acl" {
  acl = "public-read"
}

# SECURE
resource "aws_s3_bucket_public_access_block" "ems_reports" {
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}
resource "aws_s3_bucket_server_side_encryption_configuration" "ems_enc" {
  rule {
    apply_server_side_encryption_by_default { sse_algorithm = "aws:kms" }
  }
}
```

### Misconfiguration 3: Open Security Group

```hcl
# INSECURE — all inbound traffic from internet
ingress {
  from_port   = 0; to_port = 65535; protocol = "-1"
  cidr_blocks = ["0.0.0.0/0"]
}

# SECURE — only port 443 from internet; app port from load balancer only
ingress {
  from_port   = 443; to_port = 443; protocol = "tcp"
  cidr_blocks = ["0.0.0.0/0"]
}
ingress {
  from_port       = 8080; to_port = 8080; protocol = "tcp"
  security_groups = [aws_security_group.alb_sg.id]  # not from internet
}
```

## 7.3 Checkov — Policy Scanning for IaC

```bash
# Scan the EMS Terraform directory
checkov -d ./terraform/ems

# Compact output — only show failures
checkov -d ./terraform/ems --compact

# JUnit XML for CI pipeline
checkov -d ./terraform/ems --output junitxml > checkov-results.xml
```

## 7.4 Understanding Checkov Output

```
Passed checks: 26, Failed checks: 8, Skipped checks: 0

Check: CKV_AWS_17: "Ensure RDS instance is not publicly accessible"
  FAILED for resource: aws_db_instance.ems_mysql
  File: /terraform/ems/main.tf:45-65

  Code:
    45 | resource "aws_db_instance" "ems_mysql" {
    ...
    52 |   publicly_accessible = true   <-- this line causes the failure
```

## 7.5 Policy-as-Code — Custom SBI Policy

```python
# custom_policies/CKV_SBI_001.py
# RBI BCM requirement: RDS must use Multi-AZ
from checkov.common.models.enums import CheckResult, CheckCategories
from checkov.terraform.checks.resource.base_resource_check import BaseResourceCheck

class DBMultiAZCheck(BaseResourceCheck):
    def __init__(self):
        super().__init__(
            name="Ensure RDS uses Multi-AZ (RBI BCM requirement)",
            id="CKV_SBI_001",
            categories=[CheckCategories.BACKUP_AND_RECOVERY],
            supported_resources=["aws_db_instance"])

    def scan_resource_conf(self, conf):
        multi_az = conf.get("multi_az", [False])[0]
        return CheckResult.PASSED if multi_az else CheckResult.FAILED

check = DBMultiAZCheck()
```

```bash
checkov -d ./terraform/ems --external-checks-dir ./custom_policies --compact
```

---

# Lab 4: IaC Security with Checkov
`1:30 – 2:15` · Checkov scan of EMS Terraform · Fix misconfigs · Custom policy

> **Lab Objective:** Run Checkov on the EMS Terraform, identify and fix the 8 misconfigurations, write the custom RBI Multi-AZ policy.

## Step 1 — Read the Terraform First

Open `terraform/ems/main.tf` in VS Code. Without running any tool — can you spot the misconfigurations? The file has comment annotations to help you find them.

## Step 2 — Run Checkov

```bash
cd terraform/ems
checkov -d . --compact
```

FAILED count: `_______`

List the failed check IDs:

```
1. ___________________________________
2. ___________________________________
3. ___________________________________
4. ___________________________________
```

## Step 3 — Apply Fixes

Using the patterns from Module 7, fix `main.tf`:

- `publicly_accessible = false`
- `storage_encrypted = true`
- `deletion_protection = true`
- `skip_final_snapshot = false`
- Add `aws_s3_bucket_public_access_block` (all four options `true`)
- Add `aws_s3_bucket_server_side_encryption_configuration` (SSE-KMS)
- Restrict security group ingress to specific ports only
- Remove hardcoded password — use `var.db_password`

## Step 4 — Re-scan

```bash
checkov -d . --compact
```

New FAILED count: `_______` (should be 0)

## Step 5 — Write and Run the Custom Policy

Create `custom_policies/CKV_SBI_001.py` using the code from Module 7.

```bash
checkov -d . --external-checks-dir ../custom_policies --compact
```

Does the EMS RDS pass or fail `CKV_SBI_001`? Add `multi_az = true` if it fails.

> **Real-world relevance:** RBI's BCM guidelines (Annex 7, Master Direction on IT) require critical banking applications to have multi-AZ or equivalent HA. The policy you just wrote enforces this automatically on every infrastructure change.

---

# Module 8: The Integrated DevSecOps Pipeline
`3:00 – 4:00` · End-to-End · All Gates · Metrics · Maturity Model

## 8.1 The EMS Complete Security Pipeline

| Stage | Tool | Pass Condition |
|---|---|---|
| 1. Pre-commit | detect-secrets | No secrets in staged files |
| 2. Build (CI) | SonarQube SAST | Quality Gate: 0 Critical/Blocker |
| 3. Container build | Trivy | 0 CRITICAL CVEs |
| 4. IaC change | Checkov | 0 FAILED checks |
| 5. Staging deploy | OWASP ZAP DAST | 0 High alerts |
| 6. Production deploy | Manual approval | Security team sign-off |

## 8.2 Complete Pipeline YAML

```yaml
# .github/workflows/devsecops-full.yml
name: EMS Full DevSecOps Pipeline

on:
  push:
    branches: [main, develop]
  pull_request:
    branches: [main]

env:
  IMAGE_NAME: sbi-ems
  IMAGE_TAG: ${{ github.sha }}

jobs:
  sast:
    name: SAST — Code Analysis
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
        with: { fetch-depth: 0 }
      - uses: actions/setup-java@v3
        with: { java-version: "17", distribution: "temurin" }
      - name: Detect secrets
        run: pip install detect-secrets && detect-secrets scan --all-files .
      - name: SonarQube Quality Gate
        env:
          SONAR_TOKEN: ${{ secrets.SONAR_TOKEN }}
          SONAR_HOST_URL: ${{ secrets.SONAR_HOST_URL }}
        run: mvn clean verify sonar:sonar -Dsonar.qualitygate.wait=true

  iac-scan:
    name: IaC — Checkov
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - run: |
          pip install checkov
          checkov -d terraform/ems --external-checks-dir custom_policies \
            --output junitxml > checkov-results.xml

  build-and-scan:
    name: Build + Trivy Container Scan
    needs: [sast, iac-scan]
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - uses: actions/setup-java@v3
        with: { java-version: "17", distribution: "temurin" }
      - run: mvn clean package -DskipTests
      - run: docker build -f Dockerfile.secure -t $IMAGE_NAME:$IMAGE_TAG .
      - run: |
          trivy image --severity HIGH,CRITICAL \
            --exit-code 1 --format sarif \
            --output trivy-results.sarif $IMAGE_NAME:$IMAGE_TAG

  dast:
    name: DAST — ZAP API Scan
    needs: build-and-scan
    runs-on: ubuntu-latest
    if: github.ref == 'refs/heads/main'
    steps:
      - uses: actions/checkout@v3
      - run: |
          docker run -d --name ems-staging -p 8080:8080 \
            -e JWT_SECRET=${{ secrets.JWT_SECRET }} \
            -e SPRING_PROFILES_ACTIVE=dev \
            $IMAGE_NAME:$IMAGE_TAG
          sleep 30
      - run: |
          docker run --network=host ghcr.io/zaproxy/zaproxy:stable \
            zap-api-scan.py \
            -t http://localhost:8080/v3/api-docs \
            -f openapi -r zap-report.html -l WARN
      - uses: actions/upload-artifact@v3
        with: { name: zap-report, path: zap-report.html }
```

## 8.3 DevSecOps Maturity Model

| Level | Characteristics | EMS Target |
|---|---|---|
| Level 1 — Ad hoc | Manual security reviews; no pipeline tooling | Starting point for most legacy banking apps |
| Level 2 — Defined | SAST tool integrated; developers aware | SonarQube + Quality Gate enforced |
| Level 3 — Consistent | SAST + DAST automated; secrets managed | Days 1+2 lab state — all tools in pipeline |
| Level 4 — Quantified | Security metrics tracked; SLAs on remediation | MTTR tracked in Jira |
| Level 5 — Optimizing | Threat modelling; chaos engineering; red team | Target for banking security programmes |

## 8.4 Security Metrics That Matter

| Metric | What it measures |
|---|---|
| MTTR — Critical vulnerabilities | How quickly critical findings are fixed |
| Vulnerability escape rate | % found in production vs caught in pipeline |
| Quality Gate pass rate | % of builds passing — signals developer adoption |
| Container base image age | Days since last update — older = more CVEs |
| Secrets detected pre-commit | Count caught by hooks — should trend to zero |

---

# Capstone Lab: End-to-End DevSecOps on EMS
`4:00 – 5:00` · Introduce SQL injection → SAST catches it → DAST confirms → Fix → All gates pass

> **Lab Objective:** Simulate a real developer workflow — make a code change that introduces a Critical vulnerability, watch the pipeline catch it, fix it, and confirm all gates pass. This ties together every tool from both days.

## Scenario

A developer adds an endpoint to search employees by department name using a raw SQL query with string concatenation. Your job:

1. Add the vulnerable endpoint to `EmployeeController.java`.
2. Run SonarQube — observe the Critical injection finding.
3. Confirm exploitability with ZAP.
4. Fix the code.
5. Re-run all pipeline stages and confirm clean results.

## Step 1 — Introduce the Vulnerability

Add this method to `EmployeeController.java`:

```java
// ⚠️  VULNERABLE — add this for the Capstone Lab only
// SonarQube will flag this as Critical (taint: dept → raw SQL)
@GetMapping("/search-by-dept")
public ResponseEntity<?> searchByDept(@RequestParam String dept) {
    // VULNERABLE — uses findByDepartmentNameUnsafe() which has a raw JPQL query
    List<Employee> result = employeeRepository.findByDepartmentNameUnsafe(dept);
    return ResponseEntity.ok(result);
}
```

You will also need to inject `EmployeeRepository` into the controller:

```java
private final EmployeeRepository employeeRepository;

public EmployeeController(EmployeeService employeeService,
                           EmployeeRepository employeeRepository) {
    this.employeeService      = employeeService;
    this.employeeRepository   = employeeRepository;
}
```

Commit:

```bash
git add . && git commit -m "feat: add department search endpoint"
```

## Step 2 — Run SAST

```bash
mvn clean package -DskipTests sonar:sonar \
  -Dsonar.host.url=http://SONAR_IP:9000 \
  -Dsonar.token=YOUR_TOKEN
```

Open the SonarQube dashboard. Find the new Critical issue on `search-by-dept`. Read the taint flow — where does `dept` enter? Where is the raw SQL built?

## Step 3 — Confirm with DAST

1. Start EMS: `docker compose up -d`
2. In ZAP, Spider and Active Scan.
3. Find the SQL injection alert on `/api/v1/employees/search-by-dept`.
4. Right-click the request → **Fuzz** → payload: `' OR '1'='1`

## Step 4 — Fix the Vulnerability

Replace the vulnerable method in `EmployeeController.java`:

```java
// FIXED — uses safe derived query
@GetMapping("/search-by-dept")
public ResponseEntity<?> searchByDept(
        @RequestParam
        @NotBlank(message = "Department name is required")
        @Size(max = 100) String dept) {
    // Safe: findByDepartmentName uses Spring Data parameterized query
    List<Employee> result = employeeRepository.findByDepartmentId(
        departmentRepository.findByName(dept)
            .orElseThrow(() -> new ResourceNotFoundException("Department","name",dept))
            .getId()
    );
    return ResponseEntity.ok(result.stream()
        .map(e -> EmployeeResponse.from(e, false))
        .toList());
}
```

Or simpler — use the existing safe search:

```java
// Even simpler — delegate to the existing safe service method
@GetMapping("/search-by-dept")
public ResponseEntity<?> searchByDept(
        @RequestParam @NotBlank @Size(max = 100) String name,
        Authentication auth) {
    return ResponseEntity.ok(employeeService.searchEmployees(name, isAdmin(auth)));
}
```

Commit the fix.

## Step 5 — Re-run SAST

```bash
mvn clean package -DskipTests sonar:sonar \
  -Dsonar.host.url=http://SONAR_IP:9000 \
  -Dsonar.token=YOUR_TOKEN
```

Confirm: Quality Gate **PASSED**.

## Step 6 — Rebuild Container and Re-scan

```bash
mvn clean package -DskipTests
docker build -f Dockerfile.secure -t ems:capstone .
trivy image --severity HIGH,CRITICAL --exit-code 1 ems:capstone
```

Confirm: Trivy exits with code 0.

## Step 7 — IaC Scan

```bash
checkov -d terraform/ems --external-checks-dir custom_policies --compact
```

Confirm: 0 FAILED checks.

## Step 8 — Final DAST Verification

```bash
docker compose up -d
```

Re-run ZAP Active Scan. Confirm: the SQL injection alert on `/search-by-dept` is gone.

> **Congratulations.** You have completed a full DevSecOps cycle:
> - Introduced a vulnerability → SAST caught it (Critical, Quality Gate FAILED)
> - Confirmed exploitability → DAST confirmed it (High ZAP alert)
> - Fixed the code → SAST passed, DAST passed, Trivy passed, Checkov passed
> - **SAST ✓  Container ✓  IaC ✓  DAST ✓**

---

# Module 9: Banking Case Studies + Q&A
`5:00 – 5:30` · Real Incidents · Lessons Learned · RBI Compliance Mapping

## Case Study 1 — SWIFT Banking Fraud (Bangladesh Bank, 2016)

- **What happened:** Attackers gained access to the Bangladesh Bank's SWIFT terminal and transferred $81 million to fraudulent accounts.
- **Root DevSecOps cause:** Hardcoded credentials in legacy systems; no container isolation; no anomaly detection on outbound transactions.
- **How tools from this training would have helped:**

```
SAST:              Detected hardcoded SWIFT credentials at code review
Secrets mgmt:      Vault rotating credentials automatically
Container:         Isolating the SWIFT terminal in a hardened container
Monitoring (A09):  Anomaly detection on transaction amounts/patterns
```

## Case Study 2 — Spring4Shell CVE-2022-22965

- **What happened:** Critical RCE vulnerability in Spring MVC (CVSS 9.8). Banks using Spring Boot were vulnerable for weeks.
- **Root DevSecOps cause:** No container/dependency scanning.

```bash
# How Trivy would have caught this within 24 hours of CVE disclosure:
trivy image ems:spring4shell-era

# Output:
# CVE-2022-22965  CRITICAL  spring-webmvc  5.3.17  Fixed: 5.3.18
# --exit-code 1 blocks deployment automatically
```

## Case Study 3 — Exposed S3 Bucket (Indian NBFC, 2023)

- **What happened:** KYC bucket accidentally set to `public-read`. 2.3 lakh customer documents (Aadhaar, PAN, bank statements) exposed.
- **Root DevSecOps cause:** Manual console configuration; no IaC scanning.

```
Checkov would have caught it:
  Check: CKV_AWS_53: "Ensure S3 bucket has block public ACLS enabled"
    FAILED for resource: aws_s3_bucket.kyc_documents
  → Pipeline blocks deployment before the bucket goes live
```

## RBI Compliance Mapping

| RBI Requirement | Section | DevSecOps Control in EMS |
|---|---|---|
| Secure SDLC | 6.3 | SAST (SonarQube), DAST (ZAP), code review |
| Vulnerability management | 6.4 | Trivy CVE scanning, OWASP Dependency-Check |
| Secrets and credential management | 6.5 | detect-secrets hook, `.env` pattern, Vault |
| Audit logging for PII access | 7.2 | `AuditAspect.java` — method-level audit trail |
| Change management + security review | 8.1 | CI/CD pipeline gates; security sign-off |
| Business continuity (Multi-AZ) | Annex 7 | Custom Checkov policy `CKV_SBI_001` |
| Infrastructure security baseline | 6.6 | Checkov CIS benchmark checks |

## Key Takeaways — Both Days

| Day | Module | The One Thing to Remember |
|---|---|---|
| Day 1 | Secure Coding | Write security in from line 1 — `@Valid`, `@PreAuthorize`, BCrypt, safe error handler |
| Day 1 | SAST | SonarQube finds what you cannot see — run it on every commit; fix Critical before merging |
| Day 1 | DAST | The running app is the ground truth — ZAP finds what SAST cannot (headers, CORS, runtime config) |
| Day 1 | Secrets | A secret in git is a secret forever — use detect-secrets hooks and Vault |
| Day 1 | CI/CD | Automate the gates — a gate only you manually run is a gate that gets skipped |
| Day 2 | Containers | Non-root + JRE-only base + Trivy scan = 90% of container security |
| Day 2 | IaC | Every infra change through Terraform; every Terraform through Checkov |
| Day 2 | Pipeline | DevSecOps is a culture before it is a toolchain — fast feedback, shared ownership |

## Next Steps for Your Team

1. Set up SonarQube in your internal CI/CD this week.
2. Add detect-secrets pre-commit hooks to all active repositories.
3. Add Trivy to your container build pipeline.
4. Run Checkov on your existing Terraform — treat it as a security audit.
5. Schedule a quarterly DAST scan on all externally-facing applications.
6. Present the RBI compliance mapping to your CISO.

---

*Confidential — For Training Purposes Only*
*DevSecOps Intermediate · State Bank of India · Technology Training Programme*
