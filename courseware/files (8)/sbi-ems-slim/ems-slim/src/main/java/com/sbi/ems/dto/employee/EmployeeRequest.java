package com.sbi.ems.dto.employee;

import com.sbi.ems.model.Employee.EmployeeStatus;
import jakarta.validation.constraints.*;
import java.math.BigDecimal;

/**
 * Request DTO for creating / updating an employee.
 *
 * DevSecOps A03 training anchor:
 *   Every user-supplied field is validated before reaching the service layer.
 *   @NotBlank, @Email, @Positive, @DecimalMax prevent injection-friendly inputs.
 */
public class EmployeeRequest {

    @NotBlank(message = "First name is required")
    @Size(min = 2, max = 50, message = "First name must be 2-50 characters")
    @Pattern(regexp = "^[a-zA-Z\\s-]+$",
             message = "First name must contain only letters, spaces, or hyphens")
    private String firstName;

    @NotBlank(message = "Last name is required")
    @Size(min = 2, max = 50)
    private String lastName;

    @NotBlank(message = "Email is required")
    @Email(message = "Must be a valid email address")
    private String email;

    /**
     * Salary — PII field. A01 / A02 training anchor.
     * BigDecimal preserves monetary precision (never float/double for money).
     */
    @NotNull(message = "Salary is required")
    @Positive(message = "Salary must be a positive value")
    @DecimalMax(value = "9999999.99", message = "Salary exceeds maximum allowed value")
    private BigDecimal salary;

    @NotNull(message = "Status is required")
    private EmployeeStatus status;

    @NotNull(message = "Department is required")
    private Long departmentId;

    // ── Getters / setters ────────────────────────────────────────────────────

    public String getFirstName()             { return firstName; }
    public void setFirstName(String v)       { this.firstName = v; }
    public String getLastName()              { return lastName; }
    public void setLastName(String v)        { this.lastName = v; }
    public String getEmail()                 { return email; }
    public void setEmail(String v)           { this.email = v; }
    public BigDecimal getSalary()            { return salary; }
    public void setSalary(BigDecimal v)      { this.salary = v; }
    public EmployeeStatus getStatus()        { return status; }
    public void setStatus(EmployeeStatus v)  { this.status = v; }
    public Long getDepartmentId()            { return departmentId; }
    public void setDepartmentId(Long v)      { this.departmentId = v; }
}
