package com.securechat.server.repository;

import com.securechat.server.entity.AuditEventType;
import com.securechat.server.entity.AuditLogEntity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;
import java.util.List;

/**
 * Spring Data JPA repository for immutable security audit logs.
 */
@Repository
public interface AuditLogRepository extends JpaRepository<AuditLogEntity, Long> {

    List<AuditLogEntity> findByUserIdOrderByCreatedAtDesc(Long userId);

    List<AuditLogEntity> findByEventTypeOrderByCreatedAtDesc(AuditEventType eventType);

    List<AuditLogEntity> findTop50ByOrderByCreatedAtDesc();
}
