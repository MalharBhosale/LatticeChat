package com.securechat.client.crypto;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.securechat.common.crypto.KeyExchangeService;
import com.securechat.common.crypto.KeyExchangeService.KemKeyPair;
import com.securechat.common.crypto.SignatureService;
import com.securechat.common.crypto.SignatureService.SignatureKeyPair;
import com.securechat.common.crypto.impl.AesGcmEncryptionService;
import com.securechat.common.crypto.impl.MlDsaSignatureService;
import com.securechat.common.crypto.impl.MlKemKeyExchangeService;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.io.File;
import java.io.FileOutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.util.*;

/**
 * Client-side cryptographic keystore managing post-quantum keys:
 * - Identity Key (ML-DSA-65)
 * - Signed Prekey (ML-KEM-768) + signature
 * - One-Time Prekeys (ML-KEM-768)
 *
 * Persisted on disk encrypted with AES-256-GCM using a PBKDF2 password-derived key.
 */
public class ClientKeystore {

    private static final int PBKDF2_ITERATIONS = 65536;
    private static final int SALT_LENGTH_BYTES = 16;
    private static final ObjectMapper MAPPER = new ObjectMapper();

    private SignatureKeyPair identityKey;
    private KemKeyPair signedPrekey;
    private byte[] signedPrekeySignature;
    private final Map<Long, KemKeyPair> oneTimePrekeys = new HashMap<>();

    public ClientKeystore() {}

    public ClientKeystore(SignatureKeyPair identityKey,
                          KemKeyPair signedPrekey,
                          byte[] signedPrekeySignature,
                          Map<Long, KemKeyPair> oneTimePrekeys) {
        this.identityKey = identityKey;
        this.signedPrekey = signedPrekey;
        this.signedPrekeySignature = signedPrekeySignature;
        if (oneTimePrekeys != null) {
            this.oneTimePrekeys.putAll(oneTimePrekeys);
        }
    }

    /**
     * Generates a complete fresh post-quantum key bundle for a new user:
     * - ML-DSA-65 identity key
     * - ML-KEM-768 signed prekey, signed by identity key
     * - Specified count of ML-KEM-768 one-time prekeys
     */
    public static ClientKeystore generateNew(int oneTimePrekeyCount) {
        SignatureService dsaService = new MlDsaSignatureService();
        KeyExchangeService kemService = new MlKemKeyExchangeService();

        SignatureKeyPair identityKey = dsaService.generateKeyPair();
        KemKeyPair signedPrekey = kemService.generateKeyPair();
        byte[] spkSig = dsaService.sign(signedPrekey.publicKey(), identityKey.privateKey());

        Map<Long, KemKeyPair> opks = new HashMap<>();
        for (long i = 1; i <= oneTimePrekeyCount; i++) {
            opks.put(i, kemService.generateKeyPair());
        }

        return new ClientKeystore(identityKey, signedPrekey, spkSig, opks);
    }

    public SignatureKeyPair getIdentityKey() {
        return identityKey;
    }

    public KemKeyPair getSignedPrekey() {
        return signedPrekey;
    }

    public byte[] getSignedPrekeySignature() {
        return signedPrekeySignature;
    }

    public Map<Long, KemKeyPair> getOneTimePrekeys() {
        return Collections.unmodifiableMap(oneTimePrekeys);
    }

    public KemKeyPair getOneTimePrekey(long prekeyId) {
        return oneTimePrekeys.get(prekeyId);
    }

    public void addOneTimePrekey(long id, KemKeyPair keyPair) {
        oneTimePrekeys.put(id, keyPair);
    }

    public KemKeyPair consumeOneTimePrekey(long prekeyId) {
        return oneTimePrekeys.remove(prekeyId);
    }

    /**
     * Rotates the signed prekey (ML-KEM-768): generates a fresh KEM keypair,
     * signs it with the permanent ML-DSA-65 identity key, and updates internal state.
     */
    public KemKeyPair rotateSignedPrekey() {
        KeyExchangeService kemService = new MlKemKeyExchangeService();
        SignatureService dsaService = new MlDsaSignatureService();

        KemKeyPair newSpk = kemService.generateKeyPair();
        byte[] newSig = dsaService.sign(newSpk.publicKey(), this.identityKey.privateKey());

        this.signedPrekey = newSpk;
        this.signedPrekeySignature = newSig;

        return newSpk;
    }


    /**
     * Encrypts and saves this keystore to disk using master password.
     */
    public void saveToFile(File file, char[] password) throws Exception {
        SecureRandom random = new SecureRandom();
        byte[] salt = new byte[SALT_LENGTH_BYTES];
        random.nextBytes(salt);

        byte[] aesKey = deriveAesKey(password, salt);
        KeystoreJsonData data = toData();
        byte[] plaintext = MAPPER.writeValueAsBytes(data);

        AesGcmEncryptionService encryptionService = new AesGcmEncryptionService();
        byte[] encryptedPackage = encryptionService.encrypt(plaintext, aesKey, null);

        if (file.getParentFile() != null) {
            file.getParentFile().mkdirs();
        }

        try (FileOutputStream fos = new FileOutputStream(file)) {
            fos.write(salt);
            fos.write(encryptedPackage);
        }
    }

    /**
     * Loads and decrypts this keystore from disk using master password.
     */
    public static ClientKeystore loadFromFile(File file, char[] password) throws Exception {
        byte[] allBytes = Files.readAllBytes(file.toPath());
        if (allBytes.length < SALT_LENGTH_BYTES + 28) {
            throw new IllegalArgumentException("Keystore file corrupted or truncated");
        }

        byte[] salt = Arrays.copyOfRange(allBytes, 0, SALT_LENGTH_BYTES);
        byte[] encryptedPackage = Arrays.copyOfRange(allBytes, SALT_LENGTH_BYTES, allBytes.length);

        byte[] aesKey = deriveAesKey(password, salt);
        AesGcmEncryptionService encryptionService = new AesGcmEncryptionService();
        byte[] plaintext = encryptionService.decrypt(encryptedPackage, aesKey, null);

        KeystoreJsonData data = MAPPER.readValue(plaintext, KeystoreJsonData.class);
        return fromData(data);
    }

    private static byte[] deriveAesKey(char[] password, byte[] salt) throws Exception {
        PBEKeySpec spec = new PBEKeySpec(password, salt, PBKDF2_ITERATIONS, 256);
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        return factory.generateSecret(spec).getEncoded();
    }

    private KeystoreJsonData toData() {
        KeystoreJsonData data = new KeystoreJsonData();
        data.identityPub = Base64.getEncoder().encodeToString(identityKey.publicKey());
        data.identityPriv = Base64.getEncoder().encodeToString(identityKey.privateKey());
        data.identityParam = identityKey.parameterSet();

        data.spkPub = Base64.getEncoder().encodeToString(signedPrekey.publicKey());
        data.spkPriv = Base64.getEncoder().encodeToString(signedPrekey.privateKey());
        data.spkParam = signedPrekey.parameterSet();
        data.spkSig = Base64.getEncoder().encodeToString(signedPrekeySignature);

        for (Map.Entry<Long, KemKeyPair> entry : oneTimePrekeys.entrySet()) {
            OpkJsonData opk = new OpkJsonData();
            opk.id = entry.getKey();
            opk.pub = Base64.getEncoder().encodeToString(entry.getValue().publicKey());
            opk.priv = Base64.getEncoder().encodeToString(entry.getValue().privateKey());
            opk.param = entry.getValue().parameterSet();
            data.opks.add(opk);
        }
        return data;
    }

    private static ClientKeystore fromData(KeystoreJsonData data) {
        SignatureKeyPair ik = new SignatureKeyPair(
                Base64.getDecoder().decode(data.identityPub),
                Base64.getDecoder().decode(data.identityPriv),
                data.identityParam
        );

        KemKeyPair spk = new KemKeyPair(
                Base64.getDecoder().decode(data.spkPub),
                Base64.getDecoder().decode(data.spkPriv),
                data.spkParam
        );

        byte[] spkSig = Base64.getDecoder().decode(data.spkSig);

        Map<Long, KemKeyPair> opks = new HashMap<>();
        if (data.opks != null) {
            for (OpkJsonData opk : data.opks) {
                opks.put(opk.id, new KemKeyPair(
                        Base64.getDecoder().decode(opk.pub),
                        Base64.getDecoder().decode(opk.priv),
                        opk.param
                ));
            }
        }

        return new ClientKeystore(ik, spk, spkSig, opks);
    }

    private static class KeystoreJsonData {
        public String identityPub;
        public String identityPriv;
        public String identityParam;

        public String spkPub;
        public String spkPriv;
        public String spkParam;
        public String spkSig;

        public List<OpkJsonData> opks = new ArrayList<>();
    }

    private static class OpkJsonData {
        public long id;
        public String pub;
        public String priv;
        public String param;
    }
}
