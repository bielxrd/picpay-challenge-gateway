package br.com.picpay_gateway.filter;
import br.com.picpay_gateway.utils.JwtUtils;
import com.auth0.jwt.interfaces.DecodedJWT;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;

import java.util.List;
import java.util.UUID;


@Component
public class SecurityJwtFilter implements WebFilter {


    @Override
    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
        String authorization =  exchange.getRequest().getHeaders().getFirst(HttpHeaders.AUTHORIZATION);

        if (authorization == null || !authorization.startsWith("Bearer ")) {
            return chain.filter(exchange);
        }

        var decodedJWT = JwtUtils.decodeToken(authorization);

        UUID userId = UUID.fromString(decodedJWT.getSubject());

        String role = decodedJWT.getClaim("role").asString();

        List<GrantedAuthority> authorities = List.of((GrantedAuthority) () -> role);

        ServerWebExchange mutatedExchange = exchange.mutate()
                .request(builder -> builder.header("userId", userId.toString()))
                .build();

        var authentication = new UsernamePasswordAuthenticationToken(userId, null, authorities);

        return chain.filter(mutatedExchange)
                .contextWrite(ReactiveSecurityContextHolder.withAuthentication(authentication));
    }
}
