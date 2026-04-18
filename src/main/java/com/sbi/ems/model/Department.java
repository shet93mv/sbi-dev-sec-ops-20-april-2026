package com.sbi.ems.model;

import jakarta.persistence.*;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

/**
 * Organisational department.
 * Kept minimal — only id and name needed for the training labs.
 * Used as a foreign key on Employee and as the target of the
 * SQL injection demo in the Capstone Lab.
 */
@Entity
@Table(name = "departments",
       uniqueConstraints = @UniqueConstraint(name = "uk_dept_name", columnNames = "name"))
public class Department {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @NotBlank(message = "Department name is required")
    @Size(min = 2, max = 100)
    @Column(nullable = false, length = 100)
    private String name;

    public Department() {}

    public Department(Long id, String name) {
        this.id   = id;
        this.name = name;
    }

    public Long getId()          { return id; }
    public void setId(Long id)   { this.id = id; }
    public String getName()      { return name; }
    public void setName(String n){ this.name = n; }
}
