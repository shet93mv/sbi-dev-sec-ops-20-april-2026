package com.sbi.ems;

import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;

@SpringBootTest
@ActiveProfiles("test")
class EmsApplicationTests {

    @Test
    void contextLoads() {
        // Verifies the Spring context starts without errors.
        // This is all that is needed for SonarQube coverage in Lab 1.
    }
}
