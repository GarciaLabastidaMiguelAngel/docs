package com.authserver.oidc.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.session.data.redis.config.annotation.web.http.EnableRedisHttpSession;

/**
 * Spring Session with Redis configuration.
 * 
 * This configuration enables distributed session storage using Redis,
 * allowing for horizontal scalability and session persistence across
 * multiple instances of the authorization server.
 * 
 * Features:
 * - Distributed session storage in Redis
 * - Session timeout of 30 minutes (1800 seconds)
 * - Automatic session replication
 * - Spring Security integration (automatically manages JSESSIONID)
 * 
 * Redis connection is auto-configured from application.yml:
 * - spring.redis.host (default: localhost)
 * - spring.redis.port (default: 6379)
 * - spring.redis.password (if required)
 */
@Configuration
@EnableRedisHttpSession(maxInactiveIntervalInSeconds = 1800)
public class SessionConfig {
    
    // No additional bean configuration needed - Spring Boot auto-configures
    // RedisConnectionFactory from application.yml properties

}
