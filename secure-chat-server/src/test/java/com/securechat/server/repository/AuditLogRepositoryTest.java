package com.securechat.server.repository;

import com.securechat.server.entity.AuditEventType;
import com.securechat.server.entity.AuditLogEntity;
import com.securechat.server.entity.UserEntity;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.orm.jpa.DataJpaTest;
import org.springframework.test.context.ActiveProfiles;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

@DataJpaTest
@ActiveProfiles("test")
class AuditLogRepositoryTest {

    @Autowired
    private AuditLogRepository auditLogRepository;

    @Autowired
    private UserRepository userRepository;

    @Test
    @DisplayName("Should record and query security audit events")
    void testAuditLogPersistence() {
        UserEntity user = userRepository.save(new UserEntity("audit_user", "audit@latticechat.internal", "pass", "Audit"));

        AuditLogEntity log1 = new AuditLogEntity(user, AuditEventType.USER_LOGIN, "192.168.1.50", "Successful password authentication");
        AuditLogEntity log2 = new AuditLogEntity(user, AuditEventType.KEY_ROTATION, "192.168.1.50", "Rotated ML-KEM-768 prekey bundle to v2");
        AuditLogEntity log3 = new AuditLogEntity(null, AuditEventType.REPLAY_ATTACK_DETECTED, "10.0.0.99", "Duplicate message nonce rejected");

        auditLogRepository.save(log1);
        auditLogRepository.save(log2);
        auditLogRepository.save(log3);

        List<AuditLogEntity> userLogs = auditLogRepository.findByUserIdOrderByCreatedAtDesc(user.getId());
        assertEquals(2, userLogs.size());

        List<AuditLogEntity> replayLogs = auditLogRepository.findByEventTypeOrderByCreatedAtDesc(AuditEventType.REPLAY_ATTACK_DETECTED);
        assertEquals(1, replayLogs.size());
        assertEquals("10.0.0.99", replayLogs.get(0).getIpAddress());

        List<AuditLogEntity> recent = auditLogRepository.findTop50ByOrderByCreatedAtDesc();
        assertTrue(recent.size() >= 3);
        assertNotNull(recent.get(0).getCreatedAt());
    }
}
