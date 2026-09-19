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
 * JPA entity representing a published Post-Quantum Cryptographic Key Bundle.
 * Contains the user's ML-DSA identity public key, ML-KEM prekey, and prekey signature.
 */
@Entity
@Table(name = "user_key_bundles")
public class UserKeyBundleEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "user_id", nullable = false)
    private UserEntity user;

    @Column(name = "identity_key", columnDefinition = "TEXT", nullable = false)
    private String identityKey;

    @Column(name = "identity_algorithm", nullable = false, length = 50)
    private String identityAlgorithm = "ML-DSA-65";

    @Column(name = "prekey", columnDefinition = "TEXT", nullable = false)
    private String prekey;

    @Column(name = "prekey_algorithm", nullable = false, length = 50)
    private String prekeyAlgorithm = "ML-KEM-768";

    @Column(name = "prekey_signature", columnDefinition = "TEXT", nullable = false)
    private String prekeySignature;

    @Column(name = "key_version", nullable = false)
    private Integer keyVersion = 1;

    @Column(name = "is_active", nullable = false)
    private Boolean isActive = true;

    @Column(name = "created_at", nullable = false, updatable = false)
    private Instant createdAt;

    @Column(name = "expires_at")
    private Instant expiresAt;

    public UserKeyBundleEntity() {
    }

    public UserKeyBundleEntity(UserEntity user, String identityKey, String identityAlgorithm,
                               String prekey, String prekeyAlgorithm, String prekeySignature,
                               Integer keyVersion) {
        this.user = user;
        this.identityKey = identityKey;
        this.identityAlgorithm = identityAlgorithm;
        this.prekey = prekey;
        this.prekeyAlgorithm = prekeyAlgorithm;
        this.prekeySignature = prekeySignature;
        this.keyVersion = keyVersion != null ? keyVersion : 1;
        this.isActive = true;
    }

    @PrePersist
    protected void onCreate() {
        if (this.createdAt == null) {
            this.createdAt = Instant.now();
        }
        if (this.isActive == null) {
            this.isActive = true;
        }
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

    public String getIdentityKey() {
        return identityKey;
    }

    public void setIdentityKey(String identityKey) {
        this.identityKey = identityKey;
    }

    public String getIdentityAlgorithm() {
        return identityAlgorithm;
    }

    public void setIdentityAlgorithm(String identityAlgorithm) {
        this.identityAlgorithm = identityAlgorithm;
    }

    public String getPrekey() {
        return prekey;
    }

    public void setPrekey(String prekey) {
        this.prekey = prekey;
    }

    public String getPrekeyAlgorithm() {
        return prekeyAlgorithm;
    }

    public void setPrekeyAlgorithm(String prekeyAlgorithm) {
        this.prekeyAlgorithm = prekeyAlgorithm;
    }

    public String getPrekeySignature() {
        return prekeySignature;
    }

    public void setPrekeySignature(String prekeySignature) {
        this.prekeySignature = prekeySignature;
    }

    public Integer getKeyVersion() {
        return keyVersion;
    }

    public void setKeyVersion(Integer keyVersion) {
        this.keyVersion = keyVersion;
    }

    public Boolean getIsActive() {
        return isActive;
    }

    public void setIsActive(Boolean active) {
        isActive = active;
    }

    public Instant getCreatedAt() {
        return createdAt;
    }

    public void setCreatedAt(Instant createdAt) {
        this.createdAt = createdAt;
    }

    public Instant getExpiresAt() {
        return expiresAt;
    }

    public void setExpiresAt(Instant expiresAt) {
        this.expiresAt = expiresAt;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        UserKeyBundleEntity that = (UserKeyBundleEntity) o;
        return Objects.equals(id, that.id);
    }

    @Override
    public int hashCode() {
        return Objects.hash(id);
    }

    @Override
    public String toString() {
        return "UserKeyBundleEntity{" +
                "id=" + id +
                ", userId=" + (user != null ? user.getId() : null) +
                ", identityAlgorithm='" + identityAlgorithm + '\'' +
                ", prekeyAlgorithm='" + prekeyAlgorithm + '\'' +
                ", keyVersion=" + keyVersion +
                ", isActive=" + isActive +
                '}';
    }
}
