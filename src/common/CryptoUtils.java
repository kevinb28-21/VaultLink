package vaultlink.common;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;

/**
 * Cryptographic utilities: AES-128-CBC encryption, HMAC-SHA256, key derivation.
 * All operations use the primitives required by the protocol (no TLS).
 */
public final class CryptoUtils {

    private static final SecureRandom RNG = new SecureRandom();

    private CryptoUtils() {}

    /**
     * Generate a random nonce (16 bytes for N_client / N_server).
     */
    public static byte[] generateNonce() {
        byte[] nonce = new byte[ProtocolConstants.IV_SIZE_BYTES];
        RNG.nextBytes(nonce);
        return nonce;
    }

    /**
     * Generate a random IV for AES-CBC (16 bytes).
     */
    public static byte[] generateIV() {
        return generateNonce();
    }

    /**
     * AES-128-CBC encrypt. IV is prepended to ciphertext in protocol messages.
     */
    public static byte[] aesEncrypt(byte[] key, byte[] plaintext) throws Exception {
        byte[] iv = generateIV();
        Cipher cipher = Cipher.getInstance(ProtocolConstants.AES_ALGORITHM);
        SecretKey keySpec = new SecretKeySpec(key, 0, Math.min(key.length, ProtocolConstants.AES_KEY_SIZE_BYTES), ProtocolConstants.AES_KEY_ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, new IvParameterSpec(iv));
        byte[] ciphertext = cipher.doFinal(plaintext);
        // Return IV || ciphertext (caller may send this; MAC is over IV||ciphertext)
        byte[] result = new byte[iv.length + ciphertext.length];
        System.arraycopy(iv, 0, result, 0, iv.length);
        System.arraycopy(ciphertext, 0, result, iv.length, ciphertext.length);
        return result;
    }

    /**
     * AES-128-CBC decrypt. Input is IV || ciphertext.
     */
    public static byte[] aesDecrypt(byte[] key, byte[] ivAndCiphertext) throws Exception {
        byte[] iv = Arrays.copyOfRange(ivAndCiphertext, 0, ProtocolConstants.IV_SIZE_BYTES);
        byte[] ciphertext = Arrays.copyOfRange(ivAndCiphertext, ProtocolConstants.IV_SIZE_BYTES, ivAndCiphertext.length);
        Cipher cipher = Cipher.getInstance(ProtocolConstants.AES_ALGORITHM);
        SecretKey keySpec = new SecretKeySpec(key, 0, Math.min(key.length, ProtocolConstants.AES_KEY_SIZE_BYTES), ProtocolConstants.AES_KEY_ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, keySpec, new IvParameterSpec(iv));
        return cipher.doFinal(ciphertext);
    }

    /**
     * AES-128-CBC encrypt with a given IV (used for audit log where we store IV explicitly).
     */
    public static byte[] aesEncryptWithIV(byte[] key, byte[] iv, byte[] plaintext) throws Exception {
        Cipher cipher = Cipher.getInstance(ProtocolConstants.AES_ALGORITHM);
        SecretKey keySpec = new SecretKeySpec(key, 0, Math.min(key.length, ProtocolConstants.AES_KEY_SIZE_BYTES), ProtocolConstants.AES_KEY_ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, new IvParameterSpec(iv));
        return cipher.doFinal(plaintext);
    }

    /**
     * AES-128-CBC decrypt with explicit IV.
     */
    public static byte[] aesDecryptWithIV(byte[] key, byte[] iv, byte[] ciphertext) throws Exception {
        Cipher cipher = Cipher.getInstance(ProtocolConstants.AES_ALGORITHM);
        SecretKey keySpec = new SecretKeySpec(key, 0, Math.min(key.length, ProtocolConstants.AES_KEY_SIZE_BYTES), ProtocolConstants.AES_KEY_ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, keySpec, new IvParameterSpec(iv));
        return cipher.doFinal(ciphertext);
    }

    /**
     * HMAC-SHA256( key, data ). Returns full 32-byte MAC.
     */
    public static byte[] hmacSha256(byte[] key, byte[] data) throws Exception {
        Mac mac = Mac.getInstance(ProtocolConstants.HMAC_ALGORITHM);
        SecretKey keySpec = new SecretKeySpec(key, 0, Math.min(key.length, 64), ProtocolConstants.HMAC_ALGORITHM);
        mac.init(keySpec);
        return mac.doFinal(data);
    }

    /**
     * Master Secret = HMAC-SHA256(K_pre, N_client || N_server)
     */
    public static byte[] computeMasterSecret(byte[] kPre, byte[] nClient, byte[] nServer) throws Exception {
        byte[] combined = new byte[nClient.length + nServer.length];
        System.arraycopy(nClient, 0, combined, 0, nClient.length);
        System.arraycopy(nServer, 0, combined, nClient.length, nServer.length);
        return hmacSha256(kPre, combined);
    }

    /**
     * HKDF-style key derivation: K_enc = first 16 bytes of HMAC-SHA256(MasterSecret, label || salt)
     * K_mac = full 32 bytes of HMAC-SHA256(MasterSecret, "integrity" || 0x02)
     */
    public static byte[] deriveKey(byte[] masterSecret, String label, byte salt) throws Exception {
        byte[] info = new byte[label.length() + 1];
        System.arraycopy(label.getBytes(java.nio.charset.StandardCharsets.UTF_8), 0, info, 0, label.length());
        info[label.length()] = salt;
        return hmacSha256(masterSecret, info);
    }

    /**
     * K_enc: first 16 bytes of HMAC-SHA256(MasterSecret, "encryption" || 0x01)
     */
    public static byte[] deriveKenc(byte[] masterSecret) throws Exception {
        byte[] full = deriveKey(masterSecret, ProtocolConstants.KDF_LABEL_ENCRYPTION, ProtocolConstants.KDF_SALT_ENCRYPTION);
        return Arrays.copyOf(full, ProtocolConstants.AES_KEY_SIZE_BYTES);
    }

    /**
     * K_mac: full 32 bytes of HMAC-SHA256(MasterSecret, "integrity" || 0x02)
     */
    public static byte[] deriveKmac(byte[] masterSecret) throws Exception {
        return deriveKey(masterSecret, ProtocolConstants.KDF_LABEL_INTEGRITY, ProtocolConstants.KDF_SALT_INTEGRITY);
    }

    /**
     * PBKDF2 with SHA-256 for password hashing on server (store hashes, never plaintext).
     */
    public static byte[] pbkdf2(char[] password, byte[] salt, int iterations, int keyLength) throws Exception {
        javax.crypto.spec.PBEKeySpec spec = new javax.crypto.spec.PBEKeySpec(password, salt, iterations, keyLength * 8);
        javax.crypto.SecretKeyFactory factory = javax.crypto.SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        return factory.generateSecret(spec).getEncoded();
    }

    public static byte[] generateSalt() {
        byte[] salt = new byte[16];
        RNG.nextBytes(salt);
        return salt;
    }

    /**
     * Constant-time comparison to avoid timing attacks on MAC verification.
     */
    public static boolean constantTimeEquals(byte[] a, byte[] b) {
        if (a == null || b == null || a.length != b.length) return false;
        int diff = 0;
        for (int i = 0; i < a.length; i++) diff |= (a[i] ^ b[i]);
        return diff == 0;
    }
}
