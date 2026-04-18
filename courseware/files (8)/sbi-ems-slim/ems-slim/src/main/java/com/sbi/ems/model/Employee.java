package com.sbi.ems.model;

import jakarta.persistence.*;
import jakarta.validation.constraints.*;

import java.math.BigDecimal;

/**
 * Central entity representing an employee.
 *
 * Fields kept to the minimum required by the training labs:
 *   - id, firstName, lastName, email  — identity
 *   - salary                          — PII field: A01 access-control demo
 *   - status                          — soft-delete demo (A04)
 *   - department                      — FK for the capstone SQL injection demo (A03)
 *
 * Removed to keep participants focused:
 *   phone, hireDate, createdAt, updatedAt, role (Role entity removed),
 *   employeeProjects (EmployeeProject join entity removed).
 */
@Entity
@Table(name = "employees",
       uniqueConstraints = @UniqueConstraint(name = "uk_employee_email", columnNames = "email"))
public class Employee {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @NotBlank(message = "First name is required")
    @Size(min = 2, max = 50)
    @Column(name = "first_name", nullable = false, length = 50)
    private String firstName;

    @NotBlank(message = "Last name is required")
    @Size(min = 2, max = 50)
    @Column(name = "last_name", nullable = false, length = 50)
    private String lastName;

    @NotBlank(message = "Email is required")
    @Email(message = "Email must be a valid email address")
    @Column(nullable = false, length = 100, unique = true)
    private String email;

    /**
     * PII field — DevSecOps A01 / A02 training anchor.
     * Never use float/double for money — BigDecimal preserves precision.
     * Masked in responses unless caller is ADMIN or the employee themselves.
     */
    @NotNull(message = "Salary is required")
    @DecimalMin(value = "0.0", inclusive = false, message = "Salary must be greater than 0")
    @Digits(integer = 10, fraction = 2)
    @Column(nullable = false, precision = 12, scale = 2)
    private BigDecimal salary;

    /**
     * A04 training anchor — soft-delete sets status to TERMINATED,
     * physical deletion is never performed (RBI audit trail).
     */
    @NotNull
    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 20)
    private EmployeeStatus status = EmployeeStatus.ACTIVE;

    /**
     * Many employees → one department.
     * Used in the A03 SQL injection demo (search by department name).
     */
    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "department_id", nullable = false)
    private Department department;

    public enum EmployeeStatus { ACTIVE, INACTIVE, ON_LEAVE, TERMINATED }

    public Employee() {}

    // ── Getters / setters ────────────────────────────────────────────────────

    public Long getId()                        { return id; }
    public void setId(Long id)                 { this.id = id; }

    public String getFirstName()               { return firstName; }
    public void setFirstName(String v)         { this.firstName = v; }

    public String getLastName()                { return lastName; }
    public void setLastName(String v)          { this.lastName = v; }

    public String getEmail()                   { return email; }
    public void setEmail(String v)             { this.email = v; }

    public BigDecimal getSalary()              { return salary; }
    public void setSalary(BigDecimal v)        { this.salary = v; }

    public EmployeeStatus getStatus()          { return status; }
    public void setStatus(EmployeeStatus v)    { this.status = v; }

    public Department getDepartment()          { return department; }
    public void setDepartment(Department v)    { this.department = v; }

    @Override
    public String toString() {
        // DevSecOps A02: salary and email are NEVER included in toString/logs
        return "Employee{id=" + id + ", name=" + firstName + " " + lastName
               + ", email=[REDACTED], salary=[REDACTED], status=" + status + "}";
    }
}
