package com.sbi.ems.controller;

import com.sbi.ems.exception.InvalidStateTransitionException;
import com.sbi.ems.exception.ResourceNotFoundException;
import com.sbi.ems.model.Project;
import com.sbi.ems.model.Project.ProjectStatus;
import com.sbi.ems.repository.ProjectRepository;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Project REST controller — minimal version for the DevSecOps training.
 *
 * Only two operations are exposed:
 *   GET  /api/v1/projects       — list all projects (authenticated)
 *   PUT  /api/v1/projects/{id}/status — update project status (ADMIN)
 *
 * The status update endpoint is the A04 (Insecure Design) training anchor.
 * The state machine validation is inline here so participants can read and
 * understand it directly, without navigating to a separate service class.
 *
 * Removed: full CRUD, employee assignment endpoints, ProjectService interface.
 */
@RestController
@RequestMapping("/api/v1/projects")
@Tag(name = "Projects", description = "Project management endpoints")
@SecurityRequirement(name = "bearerAuth")
public class ProjectController {

    // ── State machine — A04 Insecure Design training anchor ───────────────────
    /**
     * DevSecOps A04 — Insecure Design:
     * Valid status transitions. Any transition NOT in this map is rejected.
     *
     * Key rule from the courseware:
     *   PLANNED → COMPLETED is explicitly blocked.
     *   The project must pass through ACTIVE before reaching COMPLETED.
     *   This is a DESIGN-LEVEL security control — cannot be bypassed by the caller.
     */
    private static final Map<ProjectStatus, Set<ProjectStatus>> ALLOWED_TRANSITIONS = Map.of(
        ProjectStatus.PLANNED,   Set.of(ProjectStatus.ACTIVE,   ProjectStatus.CANCELLED),
        ProjectStatus.ACTIVE,    Set.of(ProjectStatus.ON_HOLD,  ProjectStatus.COMPLETED, ProjectStatus.CANCELLED),
        ProjectStatus.ON_HOLD,   Set.of(ProjectStatus.ACTIVE,   ProjectStatus.CANCELLED),
        ProjectStatus.COMPLETED, Set.of(),   // terminal state
        ProjectStatus.CANCELLED, Set.of()    // terminal state
    );

    private final ProjectRepository projectRepository;

    public ProjectController(ProjectRepository projectRepository) {
        this.projectRepository = projectRepository;
    }

    // ── GET ALL ───────────────────────────────────────────────────────────────
    @GetMapping
    @Operation(summary = "Get all projects (filter by status optional)")
    public ResponseEntity<List<Project>> getAllProjects(
            @RequestParam(required = false) ProjectStatus status) {
        List<Project> projects = (status == null)
                ? projectRepository.findAll()
                : projectRepository.findByStatus(status);
        return ResponseEntity.ok(projects);
    }

    // ── UPDATE STATUS ─────────────────────────────────────────────────────────
    /**
     * DevSecOps A04 training endpoint.
     *
     * Participants call this with:
     *   PUT /api/v1/projects/1/status  body: { "status": "COMPLETED" }
     *
     * When the project is PLANNED, this returns 422 with a clear error.
     * After changing to ACTIVE, COMPLETED is allowed.
     *
     * This demonstrates that security controls at the design layer CANNOT
     * be bypassed — even if the controller validation were removed, the
     * ALLOWED_TRANSITIONS map enforces the rule.
     */
    @PutMapping("/{id}/status")
    @PreAuthorize("hasRole('ADMIN')")
    @Operation(summary = "Update project status — ADMIN only. Enforces state machine (A04).")
    public ResponseEntity<Project> updateStatus(
            @PathVariable Long id,
            @RequestBody Map<String, String> body) {

        Project project = projectRepository.findById(id)
                .orElseThrow(() -> new ResourceNotFoundException("Project", "id", id));

        ProjectStatus newStatus = ProjectStatus.valueOf(body.get("status").toUpperCase());

        // ── A04: Enforce state machine ────────────────────────────────────────
        Set<ProjectStatus> allowed = ALLOWED_TRANSITIONS.getOrDefault(project.getStatus(), Set.of());
        if (!allowed.contains(newStatus)) {
            throw new InvalidStateTransitionException(
                String.format("Invalid transition: %s → %s. Allowed from %s: %s",
                    project.getStatus(), newStatus,
                    project.getStatus(),
                    allowed.isEmpty() ? "none (terminal state)" : allowed));
        }

        project.setStatus(newStatus);
        return ResponseEntity.ok(projectRepository.save(project));
    }
}
