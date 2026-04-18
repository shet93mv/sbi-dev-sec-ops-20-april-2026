package com.sbi.ems.controller;

import com.sbi.ems.dto.employee.EmployeeRequest;
import com.sbi.ems.dto.employee.EmployeeResponse;
import com.sbi.ems.service.EmployeeService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

import java.util.List;

/**
 * Employee REST controller.
 *
 * ── DevSecOps Lab targets in this file ────────────────────────────────────────
 *
 *  LAB 1 — SAST Fix 2 (A01 — Broken Access Control):
 *    The getEmployeeById() endpoint currently returns salary to ANY caller.
 *    SonarQube will flag the missing @PreAuthorize and the unconditional
 *    salary exposure.
 *    Fix: add @PreAuthorize or isAdminOrSelf() check — see Module 1 in courseware.
 *
 *  CAPSTONE LAB — A03 SQL Injection (introduce then fix):
 *    The searchByDept() endpoint uses a raw JPQL query with string concatenation.
 *    SonarQube flags it Critical. ZAP confirms it via active scan.
 *    Fix: switch to Spring Data derived query (findByDepartmentName).
 *
 *  LAB 2 — DAST:
 *    Run ZAP against the running app to find:
 *      - Missing security headers (fixed in SecurityConfig)
 *      - CORS wildcard (fixed in SecurityConfig)
 */
@RestController
@RequestMapping("/api/v1/employees")
@Tag(name = "Employees", description = "Employee management endpoints")
@SecurityRequirement(name = "bearerAuth")
public class EmployeeController {

    private final EmployeeService employeeService;

    public EmployeeController(EmployeeService employeeService) {
        this.employeeService = employeeService;
    }

    // ── GET ALL ───────────────────────────────────────────────────────────────
    @GetMapping
    @Operation(summary = "Get all employees — salary shown to ADMIN only")
    public ResponseEntity<List<EmployeeResponse>> getAllEmployees(Authentication auth) {
        return ResponseEntity.ok(employeeService.getAllEmployees(isAdmin(auth)));
    }

    // ── GET BY ID ─────────────────────────────────────────────────────────────
    /**
     * DevSecOps Lab 1 — Fix 2 (A01 — Broken Access Control):
     *
     * BEFORE (vulnerable — salary returned to ANY authenticated caller):
     *   public ResponseEntity<EmployeeResponse> getEmployeeById(@PathVariable Long id) {
     *       return ResponseEntity.ok(employeeService.getEmployeeById(id, true));
     *   }
     *
     * AFTER (secure — salary only for ADMIN or the employee themselves):
     *   See the fix in Step 6 of Lab 1 in the courseware.
     *   Implement isAdminOrSelf() below and pass the boolean to the service.
     */
    @GetMapping("/{id}")
    @Operation(summary = "Get employee by ID — salary visible to ADMIN or self only")
    public ResponseEntity<EmployeeResponse> getEmployeeById(
            @PathVariable Long id, Authentication auth) {
        // ⚠️  LAB 1 FIX TARGET: replace 'true' with isAdminOrSelf(auth, id)
        boolean includeSalary = true;  // VULNERABLE — always includes salary
        return ResponseEntity.ok(employeeService.getEmployeeById(id, includeSalary));
    }

    // ── GET BY DEPARTMENT ─────────────────────────────────────────────────────
    @GetMapping("/department/{deptId}")
    @Operation(summary = "Get all employees in a department")
    public ResponseEntity<List<EmployeeResponse>> getByDepartment(
            @PathVariable Long deptId, Authentication auth) {
        return ResponseEntity.ok(
                employeeService.getEmployeesByDepartment(deptId, isAdmin(auth)));
    }

    // ── SEARCH BY NAME ────────────────────────────────────────────────────────
    @GetMapping("/search")
    @Operation(summary = "Search employees by name — safe parameterized query")
    public ResponseEntity<List<EmployeeResponse>> search(
            @RequestParam
            @NotBlank(message = "Search term is required")
            @Size(max = 100, message = "Search term must not exceed 100 characters")
            String name,
            Authentication auth) {
        return ResponseEntity.ok(employeeService.searchEmployees(name, isAdmin(auth)));
    }

    // ── CREATE ────────────────────────────────────────────────────────────────
    @PostMapping
    @PreAuthorize("hasRole('ADMIN')")
    @Operation(summary = "Onboard a new employee — ADMIN only")
    public ResponseEntity<EmployeeResponse> createEmployee(
            @Valid @RequestBody EmployeeRequest request) {
        return ResponseEntity
                .status(HttpStatus.CREATED)
                .body(employeeService.createEmployee(request));
    }

    // ── UPDATE ────────────────────────────────────────────────────────────────
    @PutMapping("/{id}")
    @PreAuthorize("hasRole('ADMIN')")
    @Operation(summary = "Update employee details — ADMIN only")
    public ResponseEntity<EmployeeResponse> updateEmployee(
            @PathVariable Long id,
            @Valid @RequestBody EmployeeRequest request) {
        return ResponseEntity.ok(employeeService.updateEmployee(id, request));
    }

    // ── SOFT DELETE ───────────────────────────────────────────────────────────
    @DeleteMapping("/{id}")
    @PreAuthorize("hasRole('ADMIN')")
    @Operation(summary = "Terminate employee — sets status=TERMINATED (soft delete, ADMIN only)")
    public ResponseEntity<Void> deleteEmployee(@PathVariable Long id) {
        employeeService.deleteEmployee(id);
        return ResponseEntity.noContent().build();
    }

    // ── Security helpers ──────────────────────────────────────────────────────

    private boolean isAdmin(Authentication auth) {
        if (auth == null) return false;
        return auth.getAuthorities().stream()
                .anyMatch(a -> a.getAuthority().equals("ROLE_ADMIN"));
    }

    /**
     * DevSecOps Lab 1 — implement this method as part of Fix 2.
     * Returns true if the caller is ADMIN OR is the employee themselves.
     * In production: compare auth.getName() (JWT subject = email) to employee.getEmail().
     */
    private boolean isAdminOrSelf(Authentication auth, Long employeeId) {
        // TODO Lab 1: implement self-check using auth.getName() vs employee email
        return isAdmin(auth);
    }
}
