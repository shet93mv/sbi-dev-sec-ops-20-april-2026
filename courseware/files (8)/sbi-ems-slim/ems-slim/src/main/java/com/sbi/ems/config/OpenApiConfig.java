package com.sbi.ems.config;

import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.info.Info;
import io.swagger.v3.oas.models.security.SecurityScheme;
import io.swagger.v3.oas.models.security.SecurityScheme.Type;
import io.swagger.v3.oas.models.Components;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * OpenAPI / Swagger configuration.
 * ZAP uses the generated spec at /v3/api-docs to auto-discover endpoints (DAST Lab 2).
 */
@Configuration
public class OpenApiConfig {

    @Bean
    public OpenAPI emsOpenApi() {
        return new OpenAPI()
            .info(new Info()
                .title("SBI Employee Management System API")
                .description("REST API — DevSecOps Training Project (State Bank of India)")
                .version("1.0.0"))
            .components(new Components()
                .addSecuritySchemes("bearerAuth",
                    new SecurityScheme()
                        .type(Type.HTTP)
                        .scheme("bearer")
                        .bearerFormat("JWT")));
    }
}
