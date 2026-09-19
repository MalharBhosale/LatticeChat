package com.securechat.server.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
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
 * JPA entity representing a pre-published one-time Post-Quantum prekey (ML-KEM).
 * Used for asynchronous offline messaging in PQ-X3DH style key exchanges.
 */
@Entity
@Table(name = "one_time_prekeys")
public class OneTimePrekeyEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "user_id", nullable = false)
    private UserEntity user;

    @Column(name = "key_id", nullable = false)
    private Integer keyId;

    @Column(name = "public_key", columnDefinition = "TEXT", nullable = false)
    private String publicKey;

    @Column(name = "algorithm", nullable = false, length = 50)
    private String algorithm = "ML-KEM-768";

    @Column(name = "is_consumed", nullable = false)
    private Boolean isConsumed = false;

    @Column(name = "created_at", nullable = false, updatable = false)
    private Instant createdAt;

    @Column(name = "consumed_at")
    private Instant consumedAt;

    public OneTimePrekeyEntity() {
    }

    public OneTimePrekeyEntity(UserEntity user, Integer keyId, String publicKey, String algorithm) {
        this.user = user;
        this.keyId = keyId;
        this.publicKey = publicKey;
        this.algorithm = algorithm != null ? algorithm : "ML-KEM-768";
        this.isConsumed = false;
    }

    @PrePersist
    protected void onCreate() {
        if (this.createdAt == null) {
            this.createdAt = Instant.now();
        }
        if (this.isConsumed == null) {
            this.isConsumed = false;
        }
    }

    public void markConsumed() {
        this.isConsumed = true;
        this.consumedAt = Instant.now();
    }

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public UserEntity getUser() {
        return user;
    }

    public void setUser(UserEntity user) {
        this.user = user;
    }

    public Integer getKeyId() {
        return keyId;
    }

    public void setKeyId(Integer keyId) {
        this.keyId = keyId;
    }

    public String getPublicKey() {
        return publicKey;
    }

    public void setPublicKey(String publicKey) {
        this.publicKey = publicKey;
    }

    public String getAlgorithm() {
        return algorithm;
    }

    public void setAlgorithm(String algorithm) {
        this.algorithm = algorithm;
    }

    public Boolean getIsConsumed() {
        return isConsumed;
    }

    public void setIsConsumed(Boolean consumed) {
        isConsumed = consumed;
    }

    public Instant getCreatedAt() {
        return createdAt;
    }

    public void setCreatedAt(Instant createdAt) {
        this.createdAt = createdAt;
    }

    public Instant getConsumedAt() {
        return consumedAt;
    }

    public void setConsumedAt(Instant consumedAt) {
        this.consumedAt = consumedAt;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        OneTimePrekeyEntity that = (OneTimePrekeyEntity) o;
        return Objects.equals(id, that.id);
    }

    @Override
    public int hashCode() {
        return Objects.hash(id);
    }

    @Override
    public String toString() {
        return "OneTimePrekeyEntity{" +
                "id=" + id +
                ", userId=" + (user != null ? user.getId() : null) +
                ", keyId=" + keyId +
                ", algorithm='" + algorithm + '\'' +
                ", isConsumed=" + isConsumed +
                '}';
    }
}
