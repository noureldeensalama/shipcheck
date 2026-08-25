package com.example.app;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.RestController;

// Fixture: Spring Boot controller. The class-level prefix composes onto each
// mapping; the unguarded /profile MUST fire, the security-annotated billing
// route must not.
@RestController
@RequestMapping("/api/v1")
public class UserController {

    @GetMapping("/profile")
    public Profile getProfile() {
        return null;
    }

    @PreAuthorize("hasRole('ADMIN')")
    @GetMapping("/billing/history")
    public Billing history() {
        return null;
    }
}
