package com.securechat.server.config;

import com.securechat.server.security.WebSocketAuthInterceptor;
import org.springframework.context.annotation.Configuration;
import org.springframework.messaging.simp.config.ChannelRegistration;
import org.springframework.messaging.simp.config.MessageBrokerRegistry;
import org.springframework.web.socket.config.annotation.EnableWebSocketMessageBroker;
import org.springframework.web.socket.config.annotation.StompEndpointRegistry;
import org.springframework.web.socket.config.annotation.WebSocketMessageBrokerConfigurer;

/**
 * Spring WebSocket & STOMP configuration for real-time messaging,
 * user-targeted push notifications, and presence broadcasting.
 */
@Configuration
@EnableWebSocketMessageBroker
public class WebSocketConfig implements WebSocketMessageBrokerConfigurer {

    private final WebSocketAuthInterceptor webSocketAuthInterceptor;

    public WebSocketConfig(WebSocketAuthInterceptor webSocketAuthInterceptor) {
        this.webSocketAuthInterceptor = webSocketAuthInterceptor;
    }

    @Override
    public void configureMessageBroker(MessageBrokerRegistry config) {
        // In-memory message broker for subscription destinations:
        // /queue -> point-to-point user messages and receipts
        // /topic -> broadcast topics (e.g. presence, room updates)
        config.enableSimpleBroker("/queue", "/topic");

        // Prefix for messages routed to @MessageMapping controller handlers
        config.setApplicationDestinationPrefixes("/app");

        // Prefix for user-targeted queues (e.g. /user/{username}/queue/messages)
        config.setUserDestinationPrefix("/user");
    }

    @Override
    public void registerStompEndpoints(StompEndpointRegistry registry) {
        // Standard WebSocket endpoint
        registry.addEndpoint("/ws")
                .setAllowedOriginPatterns("*");

        // SockJS fallback endpoint for restrictive network environments
        registry.addEndpoint("/ws-sockjs")
                .setAllowedOriginPatterns("*")
                .withSockJS();
    }

    @Override
    public void configureClientInboundChannel(ChannelRegistration registration) {
        // Intercept client STOMP frames to authenticate connections via JWT
        registration.interceptors(webSocketAuthInterceptor);
    }
}
