package com.sbi.ems.repository;

import com.sbi.ems.model.Employee;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.List;
import java.util.Optional;

public interface EmployeeRepository extends JpaRepository<Employee, Long> {

    Optional<Employee> findByEmail(String email);

    List<Employee> findByDepartmentId(Long departmentId);

    /**
     * Safe derived query for employee name search — A03 training anchor.
     * Spring Data generates a parameterized WHERE clause — NO string concatenation.
     */
    List<Employee> findByFirstNameContainingIgnoreCaseOrLastNameContainingIgnoreCase(
            String firstName, String lastName);

    // ── DevSecOps Lab 1 (SAST) — intentionally vulnerable query ─────────────
    // This method is left here for participants to FIND and FIX during Lab 1.
    // SonarQube will flag it as a Critical SQL injection vulnerability.
    // NEVER use this pattern in production code.
    @Query(value = "SELECT * FROM employees e JOIN departments d ON e.department_id = d.id " +
                   "WHERE d.name = ':deptName'", nativeQuery = true)
    List<Employee> findByDepartmentNameUnsafe(@Param("deptName") String deptName);
    // ^^^ BUG: single quotes around :deptName mean Sequelize treats it as a
    //     literal string — parameter is NOT substituted. Fix in Lab 1:
    //     remove the quotes → WHERE d.name = :deptName
}
