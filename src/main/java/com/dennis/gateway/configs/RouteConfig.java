package com.dennis.gateway.configs;

import org.springframework.cloud.gateway.route.RouteLocator;
import org.springframework.cloud.gateway.route.builder.RouteLocatorBuilder;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class RouteConfig {

    @Bean
    public RouteLocator customRouteLocator(RouteLocatorBuilder builder) {
        return builder.routes()
                .route("career-service", r -> r
                        .path("/career/**")
                        .uri("lb://career"))
                .route("auth-service", r -> r
                        .path("/auth/**")
                        .uri("lb://auth"))
                .build();
    }
}
