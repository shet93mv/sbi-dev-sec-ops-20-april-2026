package com.sbi.ems.service;

import com.sbi.ems.dto.employee.EmployeeRequest;
import com.sbi.ems.dto.employee.EmployeeResponse;
import com.sbi.ems.model.Employee;

import java.util.List;

public interface EmployeeService {
    List<EmployeeResponse> getAllEmployees(boolean includeSalary);
    EmployeeResponse       getEmployeeById(Long id, boolean includeSalary);
    List<EmployeeResponse> getEmployeesByDepartment(Long deptId, boolean includeSalary);
    List<EmployeeResponse> searchEmployees(String name, boolean includeSalary);
    EmployeeResponse       createEmployee(EmployeeRequest request);
    EmployeeResponse       updateEmployee(Long id, EmployeeRequest request);
    void                   deleteEmployee(Long id);   // soft delete — sets TERMINATED
    Employee               findEntityById(Long id);
}
