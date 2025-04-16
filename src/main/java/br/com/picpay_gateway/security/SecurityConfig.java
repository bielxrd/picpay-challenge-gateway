package br.com.picpay_gateway.security;

import br.com.picpay_gateway.filter.SecurityJwtFilter;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.SecurityWebFiltersOrder;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.web.server.SecurityWebFilterChain;

@Configuration
@EnableWebFluxSecurity
public class SecurityConfig {

    private final SecurityJwtFilter securityJwtFilter;

    public SecurityConfig(SecurityJwtFilter securityJwtFilter) {
        this.securityJwtFilter = securityJwtFilter;
    }

    @Bean
    public SecurityWebFilterChain securityWebFilterChain(ServerHttpSecurity http) {
        return http
                .csrf(csrf -> csrf.disable())
                .authorizeExchange(matchers -> {
                    matchers.pathMatchers("/auth", "/register").permitAll();
                    matchers.pathMatchers("/deposit/**", "/deposit-history", "/transfers-payed").hasRole("USER");

                    matchers.pathMatchers(HttpMethod.POST, "/transfers").hasRole("USER");

                    matchers.pathMatchers(HttpMethod.GET, "/transfers").hasAnyRole("USER", "SHOPKEEPER");

                    matchers.pathMatchers("/profile", "/transfers-received", "/transfers-amount").hasAnyRole("USER", "SHOPKEEPER");
                })
                .addFilterAt(securityJwtFilter, SecurityWebFiltersOrder.AUTHENTICATION)
                .build();
    }
}
