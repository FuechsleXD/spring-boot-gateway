package com.dennis.gateway.components;

import java.util.Map;

import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;

import lombok.extern.slf4j.Slf4j;
import lombok.RequiredArgsConstructor;
import reactor.core.publisher.Mono;

@Component
@Slf4j
@RequiredArgsConstructor
public class AuthFilter implements GlobalFilter, Ordered {

    private final JwtUtil jwtUtil;

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        ServerHttpRequest request = exchange.getRequest();

        if (HttpMethod.OPTIONS.equals(request.getMethod())) {
            return chain.filter(exchange);
        }

        // Öffentliche Pfade überspringen
        String path = request.getURI().getPath();
        if (path.startsWith("/auth")) {
            return chain.filter(exchange);
        }

        // Header prüfen
        String authHeader = request.getHeaders().getFirst(HttpHeaders.AUTHORIZATION);
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            exchange.getResponse().getHeaders().set("X-Gateway-Auth-Failure",
                    "missing_or_invalid_authorization_header");
            exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
            return exchange.getResponse().setComplete();
        }

        String token = authHeader.substring(7);

        try {
            Map<String, Object> claims = jwtUtil.parseToken(token);
            String subject = toHeaderValue(claims.get("sub"));
            String role = toHeaderValue(claims.get("role"));

            // Claims als Header weitergeben
            ServerHttpRequest mutated = request.mutate()
                    .header("X-User-Email", subject)
                    .header("X-User-Role", role)
                    .build();

            return chain.filter(exchange.mutate().request(mutated).build());
        } catch (Exception e) {
            log.warn("JWT validation failed for path {}: {} - {}", path, e.getClass().getSimpleName(), e.getMessage());
            exchange.getResponse().getHeaders().set("X-Gateway-Auth-Failure", "jwt_validation_failed");
            exchange.getResponse().getHeaders().set("X-Gateway-Auth-Exception", e.getClass().getSimpleName());
            exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
            return exchange.getResponse().setComplete();
        }
    }

    @Override
    public int getOrder() {
        return -1; // früh ausführen
    }

    private String toHeaderValue(Object value) {
        return value == null ? "" : String.valueOf(value);
    }
}
