package com.example.apigateway.filter;

import com.google.firebase.auth.FirebaseAuth;
import com.google.firebase.auth.FirebaseToken;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

@Component
public class FirebaseAuthFilter extends AbstractGatewayFilterFactory<FirebaseAuthFilter.Config> {

    public FirebaseAuthFilter() {
        super(Config.class);
    }

    @Override
    public GatewayFilter apply(Config config) {
        return (exchange, chain) -> {
            String token = exchange.getRequest().getHeaders().getFirst("Authorization");

            if (token == null || !token.startsWith("Bearer ")) {
                System.out.println("No token provided"); // Log missing token
                return onError(exchange, "No token provided", HttpStatus.UNAUTHORIZED);
            }

            token = token.substring(7); // Remove "Bearer " prefix

            try {
                FirebaseToken decodedToken = FirebaseAuth.getInstance().verifyIdToken(token);
                System.out.println("Token validated for user: " + decodedToken.getUid()); // Log successful validation
                exchange.getAttributes().put("userId", decodedToken.getUid());
                return chain.filter(exchange);
            } catch (Exception e) {
                System.out.println("Invalid token: " + e.getMessage()); // Log token validation error
                return onError(exchange, "Invalid token", HttpStatus.UNAUTHORIZED);
            }
        };
    }

    private Mono<Void> onError(ServerWebExchange exchange, String error, HttpStatus status) {
        exchange.getResponse().setStatusCode(status);
        return exchange.getResponse().setComplete();
    }

    public static class Config {
        // Configuration properties (if needed)
    }
}