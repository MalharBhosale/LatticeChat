package com.securechat.server.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.FetchType;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.PrePersist;
import jakarta.persistence.Table;
import java.time.Instant;
import java.util.Objects;

/**
 * JPA entity representing an End-to-End Encrypted (E2EE) Message.
 * CRITICAL SECURITY PROPERTY: This entity contains NO plaintext content fields.
 * Only ciphertext, nonce, sender digital signature, and transmission metadata are stored.
 */
@Entity
@Table(name = "messages")
public class MessageEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "message_id", nullable = false, unique = true, length = 64)
    private String messageId;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "sender_id", nullable = false)
    private UserEntity sender;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "recipient_id", nullable = false)
    private UserEntity recipient;

    @Column(name = "ciphertext", columnDefinition = "LONGTEXT", nullable = false)
    private String ciphertext;

    @Column(name = "nonce", nullable = false, length = 64)
    private String nonce;

    @Column(name = "auth_tag", length = 64)
    private String authTag;

    @Column(name = "ephemeral_kem_ciphertext", columnDefinition = "TEXT")
    private String ephemeralKemCiphertext;

    @Column(name = "signature", columnDefinition = "TEXT", nullable = false)
    private String signature;

    @Column(name = "sequence_number", nullable = false)
    private Long sequenceNumber = 1L;

    @Enumerated(EnumType.STRING)
    @Column(name = "status", nullable = false, length = 20)
    private MessageStatus status = MessageStatus.SENT;

    @Column(name = "sent_at", nullable = false, updatable = false)
    private Instant sentAt;

    @Column(name = "delivered_at")
    private Instant deliveredAt;

    @Column(name = "read_at")
    private Instant readAt;

    public MessageEntity() {
    }

    public MessageEntity(String messageId, UserEntity sender, UserEntity recipient,
                         String ciphertext, String nonce, String signature, Long sequenceNumber) {
        this.messageId = messageId;
        this.sender = sender;
        this.recipient = recipient;
        this.ciphertext = ciphertext;
        this.nonce = nonce;
        this.signature = signature;
        this.sequenceNumber = sequenceNumber != null ? sequenceNumber : 1L;
        this.status = MessageStatus.SENT;
    }

    @PrePersist
    protected void onCreate() {
        if (this.sentAt == null) {
            this.sentAt = Instant.now();
        }
        if (this.status == null) {
            this.status = MessageStatus.SENT;
        }
        if (this.sequenceNumber == null) {
            this.sequenceNumber = 1L;
        }
    }

    public void markDelivered() {
        this.status = MessageStatus.DELIVERED;
        this.deliveredAt = Instant.now();
    }

    public void markRead() {
        this.status = MessageStatus.READ;
        this.readAt = Instant.now();
    }

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public String getMessageId() {
        return messageId;
    }

    public void setMessageId(String messageId) {
        this.messageId = messageId;
    }

    public UserEntity getSender() {
        return sender;
    }

    public void setSender(UserEntity sender) {
        this.sender = sender;
    }

    public UserEntity getRecipient() {
        return recipient;
    }

    public void setRecipient(UserEntity recipient) {
        this.recipient = recipient;
    }

    public String getCiphertext() {
        return ciphertext;
    }

    public void setCiphertext(String ciphertext) {
        this.ciphertext = ciphertext;
    }

    public String getNonce() {
        return nonce;
    }

    public void setNonce(String nonce) {
        this.nonce = nonce;
    }

    public String getAuthTag() {
        return authTag;
    }

    public void setAuthTag(String authTag) {
        this.authTag = authTag;
    }

    public String getEphemeralKemCiphertext() {
        return ephemeralKemCiphertext;
    }

    public void setEphemeralKemCiphertext(String ephemeralKemCiphertext) {
        this.ephemeralKemCiphertext = ephemeralKemCiphertext;
    }

    public String getSignature() {
        return signature;
    }

    public void setSignature(String signature) {
        this.signature = signature;
    }

    public Long getSequenceNumber() {
        return sequenceNumber;
    }

    public void setSequenceNumber(Long sequenceNumber) {
        this.sequenceNumber = sequenceNumber;
    }

    public MessageStatus getStatus() {
        return status;
    }

    public void setStatus(MessageStatus status) {
        this.status = status;
    }

    public Instant getSentAt() {
        return sentAt;
    }

    public void setSentAt(Instant sentAt) {
        this.sentAt = sentAt;
    }

    public Instant getDeliveredAt() {
        return deliveredAt;
    }

    public void setDeliveredAt(Instant deliveredAt) {
        this.deliveredAt = deliveredAt;
    }

    public Instant getReadAt() {
        return readAt;
    }

    public void setReadAt(Instant readAt) {
        this.readAt = readAt;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        MessageEntity that = (MessageEntity) o;
        return Objects.equals(messageId, that.messageId);
    }

    @Override
    public int hashCode() {
        return Objects.hash(messageId);
    }

    @Override
    public String toString() {
        return "MessageEntity{" +
                "id=" + id +
                ", messageId='" + messageId + '\'' +
                ", senderId=" + (sender != null ? sender.getId() : null) +
                ", recipientId=" + (recipient != null ? recipient.getId() : null) +
                ", sequenceNumber=" + sequenceNumber +
                ", status=" + status +
                ", sentAt=" + sentAt +
                '}';
    }
}
