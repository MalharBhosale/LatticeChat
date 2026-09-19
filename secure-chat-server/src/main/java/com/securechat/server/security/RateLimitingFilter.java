package com.securechat.server.security;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.securechat.common.dto.ApiResponse;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentLinkedDeque;

/**
 * Servlet filter providing sliding-window rate limiting for authentication endpoints.
 * Defends against brute-force credential stuffing and denial-of-service attempts.
 * Returns HTTP 429 Too Many Requests when threshold is exceeded.
 */
@Component
public class RateLimitingFilter extends OncePerRequestFilter {

    private final int maxRequestsPerMinute;
    private final long windowMillis;
    private final ConcurrentHashMap<String, ConcurrentLinkedDeque<Long>> requestLogs = new ConcurrentHashMap<>();
    private final ObjectMapper objectMapper = new ObjectMapper().findAndRegisterModules();

    public RateLimitingFilter() {
        this(15, 60_000L);
    }

    public RateLimitingFilter(int maxRequestsPerMinute, long windowMillis) {
        this.maxRequestsPerMinute = maxRequestsPerMinute;
        this.windowMillis = windowMillis;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {

        String path = request.getRequestURI();
        if (path != null && path.startsWith("/api/v1/auth/")) {
            String clientIp = extractClientIp(request);
            long now = System.currentTimeMillis();

            ConcurrentLinkedDeque<Long> timestamps = requestLogs.computeIfAbsent(clientIp, k -> new ConcurrentLinkedDeque<>());

            synchronized (timestamps) {
                while (!timestamps.isEmpty() && now - timestamps.peekFirst() > windowMillis) {
                    timestamps.pollFirst();
                }

                if (timestamps.size() >= maxRequestsPerMinute) {
                    response.setStatus(HttpStatus.TOO_MANY_REQUESTS.value());
                    response.setContentType(MediaType.APPLICATION_JSON_VALUE);
                    response.setHeader("Retry-After", "60");
                    ApiResponse<Void> apiResponse = ApiResponse.error("Rate limit exceeded: Too many authentication attempts. Please retry later.");
                    response.getWriter().write(objectMapper.writeValueAsString(apiResponse));
                    return;
                }

                timestamps.addLast(now);
            }
        }

        filterChain.doFilter(request, response);
    }

    private String extractClientIp(HttpServletRequest request) {
        String xfHeader = request.getHeader("X-Forwarded-For");
        if (xfHeader != null && !xfHeader.isEmpty()) {
            return xfHeader.split(",")[0].trim();
        }
        return request.getRemoteAddr();
    }

    public void reset() {
        requestLogs.clear();
    }
}
