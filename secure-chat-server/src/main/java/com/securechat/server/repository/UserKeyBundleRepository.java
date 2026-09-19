package com.securechat.server.repository;

import com.securechat.server.entity.UserKeyBundleEntity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;
import java.util.List;
import java.util.Optional;

/**
 * Spring Data JPA repository for published Post-Quantum Key Bundles.
 */
@Repository
public interface UserKeyBundleRepository extends JpaRepository<UserKeyBundleEntity, Long> {

    Optional<UserKeyBundleEntity> findByUserIdAndIsActiveTrue(Long userId);

    Optional<UserKeyBundleEntity> findByUserUsernameAndIsActiveTrue(String username);

    List<UserKeyBundleEntity> findAllByUserIdOrderByKeyVersionDesc(Long userId);

    @Modifying(clearAutomatically = true)
    @Query("UPDATE UserKeyBundleEntity b SET b.isActive = false WHERE b.user.id = :userId")
    int deactivateAllByUserId(@Param("userId") Long userId);
}
