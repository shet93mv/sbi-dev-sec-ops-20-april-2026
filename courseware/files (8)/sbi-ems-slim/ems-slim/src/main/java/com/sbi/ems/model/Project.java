package com.sbi.ems.model;

import jakarta.persistence.*;
import jakarta.validation.constraints.*;

/**
 * Project entity — kept minimal for the training labs.
 *
 * Only id, name, and status are needed.
 * The status field is the A04 (Insecure Design) training anchor:
 *   the state machine enforced in ProjectService prevents PLANNED → COMPLETED.
 *
 * Removed: description, startDate, endDate, createdAt, updatedAt,
 *          employeeProjects (join entity removed entirely).
 */
@Entity
@Table(name = "projects",
       uniqueConstraints = @UniqueConstraint(name = "uk_project_name", columnNames = "name"))
public class Project {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @NotBlank(message = "Project name is required")
    @Size(min = 2, max = 150)
    @Column(nullable = false, length = 150)
    private String name;

    /**
     * DevSecOps A04 training anchor — state machine.
     * PLANNED → ACTIVE → COMPLETED | ON_HOLD | CANCELLED
     * PLANNED → COMPLETED is explicitly blocked.
     */
    @NotNull
    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 20)
    private ProjectStatus status = ProjectStatus.PLANNED;

    public enum ProjectStatus { PLANNED, ACTIVE, ON_HOLD, COMPLETED, CANCELLED }

    public Project() {}

    public Long getId()              { return id; }
    public void setId(Long id)       { this.id = id; }

    public String getName()          { return name; }
    public void setName(String v)    { this.name = v; }

    public ProjectStatus getStatus()         { return status; }
    public void setStatus(ProjectStatus v)   { this.status = v; }
}
