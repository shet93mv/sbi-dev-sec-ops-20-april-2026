package com.sbi.ems;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
 * SBI Employee Management System — Spring Boot entry point.
 *
 * DevSecOps note: This class is intentionally minimal.
 * All security configuration lives in SecurityConfig.
 * Never put secrets, debug flags, or open endpoints here.
 */
@SpringBootApplication
public class App {

    private static final Logger log = LoggerFactory.getLogger(App.class);

    public static void main(String[] args) {
        log.info("Starting SBI Employee Management System...");
        SpringApplication.run(App.class, args);
        log.info("SBI EMS started. Navigate to /swagger-ui.html");
    }
}
