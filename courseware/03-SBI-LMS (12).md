# Loan Management System (LMS)
### Project Abstract — Spring Boot REST API Training Project
**Prepared for:** DevSecOps Training — SBI
**Tech Stack:** Java 17 · Spring Boot 3.x · Spring Data JPA · MySQL · Spring Security · JWT · Lombok · Bean Validation · SpringDoc OpenAPI · Spring Actuator

---

## 1. Project Overview

The **Loan Management System (LMS)** is a lightweight RESTful web service built with Spring Boot that manages loan applications at a bank branch. It covers three simple entities — a loan application, the branch it belongs to, and the loan product it is filed under.

LMS is deliberately kept small. The goal is not to simulate a production banking system — it is to give trainees a familiar, meaningful domain on which to practise every DevSecOps concept: secure coding, containerisation, CI/CD pipelines, secret management, vulnerability scanning, and monitoring. Participants should spend their energy on DevSecOps, not on understanding the project.

### Scope

- **LoanApplication** — the central entity; applicant details and lifecycle status
- **Branch** — the branch where the application is submitted
- **LoanProduct** — the type of loan applied for (e.g. Home Loan, Personal Loan)

---

## 2. Business Context

A bank officer at a branch receives a customer's loan request. They log the application in the system, attach it to their branch and the relevant loan product, and move it through a simple review lifecycle — from submission, through review, to approval or rejection.

That is the entire business story. Everything else in the training is about how to build, secure, ship, and operate this service safely.

### 2.1 Business Problems Being Solved

| Problem | How LMS Solves It |
|---|---|
| No central application log | REST API stores validated loan applications in MySQL |
| No branch-wise visibility | Applications are linked to a branch and queryable by branch |
| Sensitive data unprotected | JWT + role-based access controls income and CIBIL fields |
| No lifecycle tracking | Status field with server-enforced transition rules |
| No audit trail | `createdAt` / `updatedAt` on every record; no hard deletes |

---

## 3. Entities and Data Model

### 3.1 LoanApplication

The core entity. Kept intentionally lean — enough fields to make validation, security, and lifecycle lessons meaningful.

| Field | Type | Constraint | Description |
|---|---|---|---|
| `id` | Long | PK, Auto | Unique system identifier |
| `applicantName` | String | NOT NULL | Full name of the applicant (2–100 chars) |
| `email` | String | NOT NULL, Unique | Applicant's email address |
| `panNumber` | String | NOT NULL, Unique | PAN card number; PII — masked in list responses |
| `monthlyIncome` | BigDecimal | NOT NULL | Gross monthly income; PII — restricted access |
| `loanAmountRequested` | BigDecimal | NOT NULL | Amount the applicant is requesting |
| `cibilScore` | Integer | NOT NULL, 300–900 | Applicant's credit score; PII — restricted access |
| `status` | Enum | NOT NULL | `SUBMITTED` \| `UNDER_REVIEW` \| `APPROVED` \| `REJECTED` |
| `branch` | Branch | FK, NOT NULL | Branch where the application was submitted |
| `loanProduct` | LoanProduct | FK, NOT NULL | The loan product being applied for |
| `createdAt` | LocalDateTime | Auto, Immutable | Audit timestamp — record creation |
| `updatedAt` | LocalDateTime | Auto | Audit timestamp — last update |

### 3.2 Branch

A simple lookup entity. Exists to give applications an organisational anchor and to practise One-to-Many relationships.

| Field | Type | Constraint | Description |
|---|---|---|---|
| `id` | Long | PK, Auto | Unique system identifier |
| `ifscCode` | String | NOT NULL, Unique | RBI-format IFSC code (e.g. `SBIN0001234`) |
| `name` | String | NOT NULL | Branch name |
| `city` | String | NOT NULL | City of the branch |

### 3.3 LoanProduct

Another simple lookup entity. Provides amount bounds used in validation exercises.

| Field | Type | Constraint | Description |
|---|---|---|---|
| `id` | Long | PK, Auto | Unique system identifier |
| `productCode` | String | NOT NULL, Unique | e.g. `HOME_LOAN`, `PERSONAL_LOAN`, `GOLD_LOAN` |
| `name` | String | NOT NULL | Human-readable product name |
| `minAmount` | BigDecimal | NOT NULL | Minimum loan amount for this product |
| `maxAmount` | BigDecimal | NOT NULL | Maximum loan amount for this product |
| `interestRate` | BigDecimal | NOT NULL | Annual interest rate as a percentage |

### 3.4 Relationships Summary

| From | Cardinality | To | Notes |
|---|---|---|---|
| LoanApplication | Many → One | Branch | Many applications belong to one branch |
| LoanApplication | Many → One | LoanProduct | Many applications are of one product type |

> **Note:** There is no Many-to-Many relationship in this project. That complexity is intentionally excluded to keep the codebase small and the focus on DevSecOps.

---

## 4. Use Cases

### 4.1 Branch Manager

- **UC-01** — Submit a new loan application for a customer
- **UC-02** — Update an application's details before review begins
- **UC-03** — Approve or reject an application after review
- **UC-04** — View all applications at their branch, filtered by status

### 4.2 Loan Officer

- **UC-05** — View all applications in `SUBMITTED` status
- **UC-06** — Move an application to `UNDER_REVIEW`
- **UC-07** — View applicant details including income and CIBIL score

### 4.3 Applicant (Self-Service)

- **UC-08** — View the current status of their own application

---

## 5. User Stories

### 5.1 Branch Manager Stories

| Story ID | As a... | I want to... | So that... | Priority |
|---|---|---|---|---|
| US-01 | Branch Manager | submit a new loan application with applicant details | the application is formally registered in the system | High |
| US-02 | Branch Manager | approve or reject an application | the decision is recorded and the applicant can be informed | High |
| US-03 | Branch Manager | view all applications at my branch filtered by status | I can monitor the pipeline at my branch | High |
| US-04 | Branch Manager | manage loan products and branches | the reference data is always current | Medium |

### 5.2 Loan Officer Stories

| Story ID | As a... | I want to... | So that... | Priority |
|---|---|---|---|---|
| US-05 | Loan Officer | view all newly submitted applications | I can pick up cases that need review | High |
| US-06 | Loan Officer | move an application to UNDER_REVIEW | it is clear that processing has started | High |
| US-07 | Loan Officer | view CIBIL score and income on an application | I have the data I need to conduct my review | High |

### 5.3 Applicant Stories

| Story ID | As a... | I want to... | So that... | Priority |
|---|---|---|---|---|
| US-08 | Applicant | view the status of my loan application | I know where my application stands | High |

---

## 6. API Endpoint Overview

All endpoints are prefixed with `/api/v1`. Swagger UI is available at `/swagger-ui.html`.

### 6.1 LoanApplication Endpoints

| Method | Endpoint | Description | Auth Required |
|---|---|---|---|
| `GET` | `/api/v1/applications` | Get all applications (paginated; filter by status optional) | Yes |
| `GET` | `/api/v1/applications/{id}` | Get application by ID | Yes |
| `GET` | `/api/v1/applications/branch/{branchId}` | Get all applications at a branch | Yes |
| `POST` | `/api/v1/applications` | Submit a new loan application | Yes |
| `PUT` | `/api/v1/applications/{id}` | Update application details | Yes |
| `PATCH` | `/api/v1/applications/{id}/status` | Update application status | Yes |

### 6.2 Branch Endpoints

| Method | Endpoint | Description | Auth Required |
|---|---|---|---|
| `GET` | `/api/v1/branches` | Get all branches | Yes |
| `GET` | `/api/v1/branches/{id}` | Get branch by ID | Yes |
| `POST` | `/api/v1/branches` | Create a new branch | Yes |
| `PUT` | `/api/v1/branches/{id}` | Update branch details | Yes |
| `DELETE` | `/api/v1/branches/{id}` | Delete a branch | Yes |

### 6.3 LoanProduct Endpoints

| Method | Endpoint | Description | Auth Required |
|---|---|---|---|
| `GET` | `/api/v1/products` | Get all loan products | Yes |
| `GET` | `/api/v1/products/{id}` | Get product by ID | Yes |
| `POST` | `/api/v1/products` | Create a new loan product | Yes |
| `PUT` | `/api/v1/products/{id}` | Update product details | Yes |
| `DELETE` | `/api/v1/products/{id}` | Delete a loan product | Yes |

---

## 7. Key Business Rules

### 7.1 LoanApplication Rules

- Every application must be linked to exactly one branch and one loan product
- `email` and `panNumber` must be unique across the system
- `loanAmountRequested` must fall within the `minAmount` and `maxAmount` of the selected `LoanProduct`
- `cibilScore` must be between 300 and 900
- `monthlyIncome` and `cibilScore` are PII — visible only to `ROLE_MANAGER` and `ROLE_OFFICER`; hidden from applicant's own view
- `panNumber` is masked to last 4 characters in all list responses; full value returned only on single-record fetch for authorised roles
- Applications are never deleted — `REJECTED` is the terminal negative state; records are preserved for audit

### 7.2 Status Lifecycle Rules

The only valid status transitions are:

```
SUBMITTED → UNDER_REVIEW → APPROVED
                          ↘ REJECTED
```

- A `ROLE_OFFICER` may only transition status from `SUBMITTED` to `UNDER_REVIEW`
- Only a `ROLE_MANAGER` may transition status to `APPROVED` or `REJECTED`
- No backwards transitions are permitted once a status has advanced
- `APPROVED` and `REJECTED` are terminal states

### 7.3 Branch and LoanProduct Rules

- IFSC code must be unique and follow RBI format: 4 letters + `0` + 6 alphanumeric characters
- A branch cannot be deleted if it has applications associated with it
- `productCode` must be unique; `maxAmount` must be greater than `minAmount`
- A loan product cannot be deleted if there are active applications linked to it

---

## 8. Security Roles

Two roles cover all access control exercises in the training.

| Role | Maps To | Key Permissions |
|---|---|---|
| `ROLE_MANAGER` | Branch Manager | Full access to all endpoints; can approve/reject; sees all PII fields in full |
| `ROLE_OFFICER` | Loan Officer | Can view applications and move status to `UNDER_REVIEW`; sees PII on individual record fetch only |

> **Training note:** The sharp distinction between these two roles drives the `@PreAuthorize` lesson, field-level masking, and the JWT claims structure — cleanly and without ambiguity.

---

## 9. Glossary

| Term | Definition |
|---|---|
| **LoanApplication** | A customer's formal request to borrow a specified amount under a chosen loan product |
| **Branch** | A bank office identified by an IFSC code; the organisational unit that owns applications |
| **LoanProduct** | A loan category (e.g. Home Loan) with defined interest rate and amount bounds |
| **CIBIL Score** | A credit score (300–900) reflecting an applicant's creditworthiness; PII — restricted |
| **PAN** | Permanent Account Number — a unique identifier issued by the Income Tax Department; PII |
| **IFSC Code** | Indian Financial System Code — RBI's unique identifier for a bank branch |
| **Status Lifecycle** | The permitted sequence of states: `SUBMITTED → UNDER_REVIEW → APPROVED / REJECTED` |
| **PII** | Personally Identifiable Information — fields requiring role-based access control |
| **Soft Delete** | Retaining records instead of physically removing them; preserves the audit trail |
| **JWT** | JSON Web Token — used for stateless authentication in the Spring Security layer |
| **REST** | Representational State Transfer — the architectural style for the HTTP API |

---

*Confidential — For Training Purposes Only*
