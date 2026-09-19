package com.securechat.server.repository;

import com.securechat.server.entity.MessageEntity;
import com.securechat.server.entity.MessageStatus;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;
import java.util.List;
import java.util.Optional;

/**
 * Spring Data JPA repository for zero-knowledge encrypted messages.
 */
@Repository
public interface MessageRepository extends JpaRepository<MessageEntity, Long> {

    Optional<MessageEntity> findByMessageId(String messageId);

    boolean existsByMessageId(String messageId);

    List<MessageEntity> findByRecipientIdAndStatusOrderBySentAtAsc(Long recipientId, MessageStatus status);

    List<MessageEntity> findByRecipientUsernameAndStatusOrderBySentAtAsc(String username, MessageStatus status);

    @Query("SELECT m FROM MessageEntity m WHERE " +
           "(m.sender.id = :user1Id AND m.recipient.id = :user2Id) OR " +
           "(m.sender.id = :user2Id AND m.recipient.id = :user1Id) " +
           "ORDER BY m.sentAt ASC")
    List<MessageEntity> findConversationBetweenUsers(@Param("user1Id") Long user1Id, @Param("user2Id") Long user2Id);

    long countByRecipientIdAndStatus(Long recipientId, MessageStatus status);
}
