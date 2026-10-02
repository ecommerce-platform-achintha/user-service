package com.achintha.userservice.auth;

import com.achintha.userservice.config.AuthProperties;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

/**
 * Client IP for login throttling. With {@code auth.trust-forwarded-for=true} (behind the api-gateway) it is the last
 * {@code X-Forwarded-For} entry, i.e. the address the trusted proxy saw; entries before it are client-controlled and
 * ignored. Otherwise it is the TCP peer address.
 */
@Component
@RequiredArgsConstructor
public class ClientIpResolver {

    private final AuthProperties properties;

    public String resolve(HttpServletRequest request) {
        if (properties.trustForwardedFor()) {
            String forwarded = request.getHeader("X-Forwarded-For");
            if (forwarded != null && !forwarded.isBlank()) {
                String[] hops = forwarded.split(",");
                String last = hops[hops.length - 1].trim();
                if (!last.isEmpty() && last.length() <= 64) {
                    return last;
                }
            }
        }
        return request.getRemoteAddr();
    }
}
