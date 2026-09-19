package com.securechat.server.service;

import com.securechat.common.dto.AuthRequest;
import com.securechat.common.dto.AuthResponse;
import com.securechat.common.dto.RegisterRequest;
import com.securechat.common.dto.UserDto;
import com.securechat.common.exception.AuthenticationException;
import com.securechat.server.entity.AuditEventType;
import com.securechat.server.entity.AuditLogEntity;
import com.securechat.server.entity.UserEntity;
import com.securechat.server.entity.UserKeyBundleEntity;
import com.securechat.server.entity.UserStatus;
import com.securechat.server.repository.AuditLogRepository;
import com.securechat.server.repository.UserKeyBundleRepository;
import com.securechat.server.repository.UserRepository;
import com.securechat.server.security.JwtTokenProvider;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.StringUtils;

/**
 * Service managing user registration, authentication, credential validation,
 * and security audit logging.
 */
@Service
public class AuthService {

    private final UserRepository userRepository;
    private final UserKeyBundleRepository keyBundleRepository;
    private final AuditLogRepository auditLogRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtTokenProvider jwtTokenProvider;

    public AuthService(
            UserRepository userRepository,
            UserKeyBundleRepository keyBundleRepository,
            AuditLogRepository auditLogRepository,
            PasswordEncoder passwordEncoder,
            JwtTokenProvider jwtTokenProvider) {
        this.userRepository = userRepository;
        this.keyBundleRepository = keyBundleRepository;
        this.auditLogRepository = auditLogRepository;
        this.passwordEncoder = passwordEncoder;
        this.jwtTokenProvider = jwtTokenProvider;
    }

    @Transactional
    public AuthResponse register(RegisterRequest request, String clientIp) {
        if (!StringUtils.hasText(request.username()) || request.username().trim().length() < 3) {
            throw new IllegalArgumentException("Username must be at least 3 characters long");
        }
        if (!StringUtils.hasText(request.email()) || !request.email().contains("@")) {
            throw new IllegalArgumentException("A valid email address is required");
        }
        if (!StringUtils.hasText(request.password()) || request.password().length() < 8) {
            throw new IllegalArgumentException("Password must be at least 8 characters long");
        }

        String username = request.username().trim().toLowerCase();
        String email = request.email().trim().toLowerCase();

        if (userRepository.existsByUsername(username)) {
            throw new IllegalArgumentException("Username '" + username + "' is already taken");
        }
        if (userRepository.existsByEmail(email)) {
            throw new IllegalArgumentException("Email '" + email + "' is already registered");
        }

        // Hash password with BCrypt
        String passwordHash = passwordEncoder.encode(request.password());
        UserEntity user = new UserEntity(username, email, passwordHash, username);
        UserEntity savedUser = userRepository.save(user);

        // Optionally publish initial Post-Quantum key bundle if supplied during registration
        if (StringUtils.hasText(request.kemPublicKeyBase64()) && StringUtils.hasText(request.dsaPublicKeyBase64())) {
            UserKeyBundleEntity keyBundle = new UserKeyBundleEntity(
                    savedUser,
                    request.dsaPublicKeyBase64(),
                    "ML-DSA-65",
                    request.kemPublicKeyBase64(),
                    "ML-KEM-768",
                    "REGISTER_SELF_SIGNED",
                    1
            );
            keyBundleRepository.save(keyBundle);

            auditLogRepository.save(new AuditLogEntity(
                    savedUser,
                    AuditEventType.KEY_UPLOAD,
                    clientIp,
                    "Initial ML-DSA-65 and ML-KEM-768 key bundle published during registration"
            ));
        }

        // Security Audit Log
        auditLogRepository.save(new AuditLogEntity(
                savedUser,
                AuditEventType.USER_REGISTER,
                clientIp,
                "Account created successfully for username: " + username
        ));

        // Generate JWT token
        String token = jwtTokenProvider.generateToken(savedUser);
        long expiresInSeconds = jwtTokenProvider.getExpirationMs() / 1000;

        UserDto userDto = new UserDto(savedUser.getId(), savedUser.getUsername(), savedUser.getEmail(), true, savedUser.getCreatedAt());
        return AuthResponse.bearer(token, expiresInSeconds, userDto);
    }

    @Transactional(noRollbackFor = AuthenticationException.class)
    public AuthResponse login(AuthRequest request, String clientIp) {
        if (!StringUtils.hasText(request.username()) || !StringUtils.hasText(request.password())) {
            throw new AuthenticationException("Username and password are required");
        }

        String identifier = request.username().trim().toLowerCase();
        UserEntity user = userRepository.findByUsernameOrEmail(identifier, identifier)
                .orElse(null);

        if (user == null || !passwordEncoder.matches(request.password(), user.getPasswordHash())) {
            auditLogRepository.save(new AuditLogEntity(
                    user,
                    AuditEventType.LOGIN_FAILED,
                    clientIp,
                    "Failed login attempt for identifier: " + identifier
            ));
            throw new AuthenticationException("Invalid username or password");
        }

        if (user.getStatus() != UserStatus.ACTIVE) {
            throw new AuthenticationException("Account is " + user.getStatus().name().toLowerCase());
        }

        // Security Audit Log
        auditLogRepository.save(new AuditLogEntity(
                user,
                AuditEventType.USER_LOGIN,
                clientIp,
                "User successfully logged in"
        ));

        String token = jwtTokenProvider.generateToken(user);
        long expiresInSeconds = jwtTokenProvider.getExpirationMs() / 1000;

        UserDto userDto = new UserDto(user.getId(), user.getUsername(), user.getEmail(), true, user.getUpdatedAt());
        return AuthResponse.bearer(token, expiresInSeconds, userDto);
    }
}
