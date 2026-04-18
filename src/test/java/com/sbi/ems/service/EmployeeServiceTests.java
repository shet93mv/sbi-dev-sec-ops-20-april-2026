package com.sbi.ems.service;

import com.sbi.ems.dto.employee.EmployeeRequest;
import com.sbi.ems.dto.employee.EmployeeResponse;
import com.sbi.ems.exception.ConflictException;
import com.sbi.ems.model.Department;
import com.sbi.ems.model.Employee;
import com.sbi.ems.model.Employee.EmployeeStatus;
import com.sbi.ems.repository.DepartmentRepository;
import com.sbi.ems.repository.EmployeeRepository;
import com.sbi.ems.service.impl.EmployeeServiceImpl;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.math.BigDecimal;
import java.util.List;
import java.util.Optional;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

/**
 * Unit tests for EmployeeServiceImpl.
 *
 * These tests provide coverage for SonarQube in Lab 1
 * and verify key DevSecOps behaviours:
 *   - Salary masking (A01 — Broken Access Control)
 *   - Soft delete / no physical deletion (A04 — Insecure Design)
 *   - Duplicate email prevention (A07 — Auth Failures)
 */
@ExtendWith(MockitoExtension.class)
class EmployeeServiceTests {

    @Mock  EmployeeRepository   employeeRepository;
    @Mock  DepartmentRepository departmentRepository;
    @InjectMocks EmployeeServiceImpl service;

    private Department dept;
    private Employee   emp;

    @BeforeEach
    void setUp() {
        dept = new Department(1L, "Engineering");

        emp = new Employee();
        emp.setId(1L);
        emp.setFirstName("Arjun");
        emp.setLastName("Sharma");
        emp.setEmail("arjun.sharma@sbi.co.in");
        emp.setSalary(new BigDecimal("55000.00"));
        emp.setStatus(EmployeeStatus.ACTIVE);
        emp.setDepartment(dept);
    }

    // ── A01: Salary masking ───────────────────────────────────────────────────

    @Test
    @DisplayName("A01: salary is included when includeSalary=true (ADMIN caller)")
    void salaryIncludedForAdmin() {
        when(employeeRepository.findById(1L)).thenReturn(Optional.of(emp));

        EmployeeResponse response = service.getEmployeeById(1L, true);

        assertThat(response.getSalary()).isNotNull()
            .isEqualByComparingTo("55000.00");
    }

    @Test
    @DisplayName("A01: salary is NULL when includeSalary=false (non-admin caller)")
    void salaryMaskedForNonAdmin() {
        when(employeeRepository.findById(1L)).thenReturn(Optional.of(emp));

        EmployeeResponse response = service.getEmployeeById(1L, false);

        // Salary MUST be null — not zero, not redacted string, but absent
        assertThat(response.getSalary()).isNull();
    }

    // ── A04: Soft delete ──────────────────────────────────────────────────────

    @Test
    @DisplayName("A04: deleteEmployee sets status=TERMINATED, does not call repository.delete()")
    void deleteIsSoftOnly() {
        when(employeeRepository.findById(1L)).thenReturn(Optional.of(emp));
        when(employeeRepository.save(any())).thenReturn(emp);

        service.deleteEmployee(1L);

        // Status changed to TERMINATED
        assertThat(emp.getStatus()).isEqualTo(EmployeeStatus.TERMINATED);

        // Physical delete methods MUST NOT be called
        verify(employeeRepository, never()).delete(any());
        verify(employeeRepository, never()).deleteById(any());

        // Save was called (to persist TERMINATED status)
        verify(employeeRepository).save(emp);
    }

    // ── A07: Duplicate email prevention ───────────────────────────────────────

    @Test
    @DisplayName("A07: createEmployee throws ConflictException for duplicate email")
    void duplicateEmailThrowsConflict() {
        when(employeeRepository.findByEmail("arjun.sharma@sbi.co.in"))
            .thenReturn(Optional.of(emp));

        EmployeeRequest request = new EmployeeRequest();
        request.setFirstName("Arjun");
        request.setLastName("Sharma");
        request.setEmail("arjun.sharma@sbi.co.in");
        request.setSalary(new BigDecimal("55000"));
        request.setStatus(EmployeeStatus.ACTIVE);
        request.setDepartmentId(1L);

        assertThatThrownBy(() -> service.createEmployee(request))
            .isInstanceOf(ConflictException.class)
            .hasMessageContaining("already exists");
    }

    // ── A03: Safe search query ────────────────────────────────────────────────

    @Test
    @DisplayName("A03: searchEmployees delegates to safe derived query method")
    void searchDelegatesToSafeDerivedQuery() {
        when(employeeRepository
            .findByFirstNameContainingIgnoreCaseOrLastNameContainingIgnoreCase("Arjun", "Arjun"))
            .thenReturn(List.of(emp));

        List<EmployeeResponse> results = service.searchEmployees("Arjun", false);

        assertThat(results).hasSize(1);
        assertThat(results.get(0).getFirstName()).isEqualTo("Arjun");

        // Verify the safe repository method was called (not a raw query)
        verify(employeeRepository)
            .findByFirstNameContainingIgnoreCaseOrLastNameContainingIgnoreCase("Arjun", "Arjun");
    }
}
