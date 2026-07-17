package com.dennis.gateway.configs;

import org.springframework.cloud.gateway.route.RouteLocator;
import org.springframework.cloud.gateway.route.builder.RouteLocatorBuilder;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class GatewayRoutesConfig {

        @Bean
        public RouteLocator customRouteLocator(RouteLocatorBuilder builder) {
                return builder.routes()
                                .route("career-service", route -> route
                                                .path("/career/**")
                                                .uri("lb://career"))
                                .route("auth-service", route -> route
                                                .path("/auth/**")
                                                .uri("lb://auth"))
                                .build();
        }
}