package vaultlink.common;

/**
 * Protocol constants for the Secure Banking System.
 * All crypto uses AES-128-CBC and HMAC-SHA256.
 */
public final class ProtocolConstants {
    public static final int SERVER_PORT = 9000;
    public static final String AES_ALGORITHM = "AES/CBC/PKCS5Padding";
    public static final String AES_KEY_ALGORITHM = "AES";
    public static final int AES_KEY_SIZE_BYTES = 16;
    public static final int IV_SIZE_BYTES = 16;
    public static final String HMAC_ALGORITHM = "HmacSHA256";
    public static final int HMAC_KEY_SIZE_BYTES = 32;
    public static final String KDF_LABEL_ENCRYPTION = "encryption";
    public static final byte KDF_SALT_ENCRYPTION = 0x01;
    public static final String KDF_LABEL_INTEGRITY = "integrity";
    public static final byte KDF_SALT_INTEGRITY = 0x02;
    public static final String AUDIT_LOG_FILENAME = "audit_log.bin";
    public static final String ACCOUNTS_FILENAME = "accounts.json";

    private ProtocolConstants() {}
}
