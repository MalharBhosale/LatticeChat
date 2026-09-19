package com.securechat.server.service;

import com.securechat.common.dto.UserDto;
import com.securechat.common.exception.SecureChatException;
import com.securechat.server.entity.UserEntity;
import com.securechat.server.entity.UserStatus;
import com.securechat.server.repository.UserRepository;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

/**
 * Service providing user profile retrieval and directory search.
 */
@Service
@Transactional(readOnly = true)
public class UserService {

    private final UserRepository userRepository;

    public UserService(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    public UserDto getUserByUsername(String username) {
        UserEntity user = userRepository.findByUsername(username)
                .orElseThrow(() -> new SecureChatException("User '" + username + "' not found"));
        return mapToDto(user);
    }

    public UserDto getUserById(Long id) {
        UserEntity user = userRepository.findById(id)
                .orElseThrow(() -> new SecureChatException("User with ID " + id + " not found"));
        return mapToDto(user);
    }

    public List<UserDto> searchUsers(String query) {
        if (query == null || query.trim().isEmpty()) {
            return userRepository.findByStatus(UserStatus.ACTIVE).stream()
                    .map(this::mapToDto)
                    .toList();
        }

        String search = query.trim().toLowerCase();
        return userRepository.findAll().stream()
                .filter(u -> u.getStatus() == UserStatus.ACTIVE)
                .filter(u -> u.getUsername().toLowerCase().contains(search) ||
                             (u.getDisplayName() != null && u.getDisplayName().toLowerCase().contains(search)))
                .map(this::mapToDto)
                .toList();
    }

    public UserDto mapToDto(UserEntity entity) {
        return new UserDto(
                entity.getId(),
                entity.getUsername(),
                entity.getEmail(),
                entity.getStatus() == UserStatus.ACTIVE,
                entity.getUpdatedAt()
        );
    }
}
