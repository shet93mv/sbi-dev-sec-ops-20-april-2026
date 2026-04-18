package com.sbi.ems.dto.employee;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.sbi.ems.model.Employee;
import com.sbi.ems.model.Employee.EmployeeStatus;

import java.math.BigDecimal;

/**
 * Safe response DTO for Employee.
 *
 * DevSecOps A01 training anchor:
 *   The 'salary' field is annotated @JsonInclude(NON_NULL).
 *   When includeSalary=false, salary is left null and is omitted from
 *   the JSON response entirely — not returned as null, not visible at all.
 *
 *   The static factory method from(Employee, boolean) is the single place
 *   where the salary inclusion decision is applied.
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public class EmployeeResponse {

    private Long id;
    private String firstName;
    private String lastName;
    private String email;
    private EmployeeStatus status;
    private String departmentName;

    /**
     * Salary is PII — only populated when the caller is authorised.
     * @JsonInclude(NON_NULL) means a null salary is omitted from JSON output.
     */
    private BigDecimal salary;

    /**
     * Factory method — single point of salary inclusion logic.
     *
     * @param e             the employee entity
     * @param includeSalary true if the caller is ADMIN or the employee themselves
     */
    public static EmployeeResponse from(Employee e, boolean includeSalary) {
        EmployeeResponse r = new EmployeeResponse();
        r.id             = e.getId();
        r.firstName      = e.getFirstName();
        r.lastName       = e.getLastName();
        r.email          = e.getEmail();
        r.status         = e.getStatus();
        r.departmentName = e.getDepartment() != null ? e.getDepartment().getName() : null;
        r.salary         = includeSalary ? e.getSalary() : null;   // PII gate
        return r;
    }

    // ── Getters ──────────────────────────────────────────────────────────────

    public Long getId()               { return id; }
    public String getFirstName()      { return firstName; }
    public String getLastName()       { return lastName; }
    public String getEmail()          { return email; }
    public EmployeeStatus getStatus() { return status; }
    public String getDepartmentName() { return departmentName; }
    public BigDecimal getSalary()     { return salary; }
}
