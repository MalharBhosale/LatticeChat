package com.securechat.server.repository;

import com.securechat.server.entity.OneTimePrekeyEntity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;
import java.util.List;
import java.util.Optional;

/**
 * Spring Data JPA repository for pre-published One-Time Prekeys (ML-KEM).
 */
@Repository
public interface OneTimePrekeyRepository extends JpaRepository<OneTimePrekeyEntity, Long> {

    Optional<OneTimePrekeyEntity> findFirstByUserIdAndIsConsumedFalseOrderByIdAsc(Long userId);

    Optional<OneTimePrekeyEntity> findFirstByUserUsernameAndIsConsumedFalseOrderByIdAsc(String username);

    long countByUserIdAndIsConsumedFalse(Long userId);

    List<OneTimePrekeyEntity> findByUserIdAndIsConsumedFalse(Long userId);
}
