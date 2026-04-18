package com.sbi.ems.service.impl;

import com.sbi.ems.dto.employee.EmployeeRequest;
import com.sbi.ems.dto.employee.EmployeeResponse;
import com.sbi.ems.exception.ConflictException;
import com.sbi.ems.exception.ResourceNotFoundException;
import com.sbi.ems.model.Department;
import com.sbi.ems.model.Employee;
import com.sbi.ems.model.Employee.EmployeeStatus;
import com.sbi.ems.repository.DepartmentRepository;
import com.sbi.ems.repository.EmployeeRepository;
import com.sbi.ems.service.EmployeeService;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

/**
 * Employee business logic.
 *
 * DevSecOps training anchors in this class:
 *
 *  A01 — Broken Access Control:
 *    The 'includeSalary' flag is decided by the controller based on the
 *    caller's role. The service layer passes it through to EmployeeResponse.from().
 *    Defence in depth: both layers participate in the access control decision.
 *
 *  A03 — Injection:
 *    searchEmployees() uses a Spring Data derived query — no string concatenation.
 *    The vulnerable searchByDepartmentName() in EmployeeRepository is left for
 *    participants to find and fix in Lab 1 (SAST).
 *
 *  A04 — Insecure Design:
 *    deleteEmployee() performs a SOFT DELETE only (sets TERMINATED).
 *    Physical deletion would violate RBI audit-trail requirements.
 */
@Service
@Transactional(readOnly = true)
public class EmployeeServiceImpl implements EmployeeService {

    private final EmployeeRepository   employeeRepository;
    private final DepartmentRepository departmentRepository;

    public EmployeeServiceImpl(EmployeeRepository employeeRepository,
                                DepartmentRepository departmentRepository) {
        this.employeeRepository   = employeeRepository;
        this.departmentRepository = departmentRepository;
    }

    @Override
    public List<EmployeeResponse> getAllEmployees(boolean includeSalary) {
        return employeeRepository.findAll().stream()
                .map(e -> EmployeeResponse.from(e, includeSalary))
                .toList();
    }

    @Override
    public EmployeeResponse getEmployeeById(Long id, boolean includeSalary) {
        return EmployeeResponse.from(findEntityById(id), includeSalary);
    }

    @Override
    public List<EmployeeResponse> getEmployeesByDepartment(Long deptId, boolean includeSalary) {
        departmentRepository.findById(deptId)
                .orElseThrow(() -> new ResourceNotFoundException("Department", "id", deptId));
        return employeeRepository.findByDepartmentId(deptId).stream()
                .map(e -> EmployeeResponse.from(e, includeSalary))
                .toList();
    }

    @Override
    public List<EmployeeResponse> searchEmployees(String name, boolean includeSalary) {
        // DevSecOps A03: Spring Data derived query — no string concatenation in SQL
        return employeeRepository
                .findByFirstNameContainingIgnoreCaseOrLastNameContainingIgnoreCase(name, name)
                .stream()
                .map(e -> EmployeeResponse.from(e, includeSalary))
                .toList();
    }

    @Override
    @Transactional
    public EmployeeResponse createEmployee(EmployeeRequest req) {
        if (employeeRepository.findByEmail(req.getEmail()).isPresent()) {
            throw new ConflictException(
                "An employee already exists with email = '" + req.getEmail() + "'");
        }
        Department dept = departmentRepository.findById(req.getDepartmentId())
                .orElseThrow(() -> new ResourceNotFoundException(
                    "Department", "id", req.getDepartmentId()));

        Employee emp = new Employee();
        emp.setFirstName(req.getFirstName());
        emp.setLastName(req.getLastName());
        emp.setEmail(req.getEmail());
        emp.setSalary(req.getSalary());
        emp.setStatus(req.getStatus());
        emp.setDepartment(dept);

        return EmployeeResponse.from(employeeRepository.save(emp), true);
    }

    @Override
    @Transactional
    public EmployeeResponse updateEmployee(Long id, EmployeeRequest req) {
        Employee existing = findEntityById(id);

        if (!existing.getEmail().equals(req.getEmail())
                && employeeRepository.findByEmail(req.getEmail()).isPresent()) {
            throw new ConflictException(
                "An employee already exists with email = '" + req.getEmail() + "'");
        }

        Department dept = departmentRepository.findById(req.getDepartmentId())
                .orElseThrow(() -> new ResourceNotFoundException(
                    "Department", "id", req.getDepartmentId()));

        existing.setFirstName(req.getFirstName());
        existing.setLastName(req.getLastName());
        existing.setEmail(req.getEmail());
        existing.setSalary(req.getSalary());
        existing.setStatus(req.getStatus());
        existing.setDepartment(dept);

        return EmployeeResponse.from(employeeRepository.save(existing), true);
    }

    @Override
    @Transactional
    public void deleteEmployee(Long id) {
        // DevSecOps A04: SOFT DELETE — record is never physically removed.
        // Setting TERMINATED preserves the audit trail required by RBI guidelines.
        Employee emp = findEntityById(id);
        emp.setStatus(EmployeeStatus.TERMINATED);
        employeeRepository.save(emp);
    }

    @Override
    public Employee findEntityById(Long id) {
        return employeeRepository.findById(id)
                .orElseThrow(() -> new ResourceNotFoundException("Employee", "id", id));
    }
}
