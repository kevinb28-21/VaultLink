package vaultlink.server;

import vaultlink.common.CryptoUtils;
import vaultlink.common.MessageFormat;
import vaultlink.common.ProtocolConstants;

import java.io.*;
import java.nio.file.Files;
import java.nio.file.StandardOpenOption;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.locks.ReentrantLock;

/**
 * Encrypted audit log: each entry is IV + AES-CBC(K_enc, "CustomerID|Action|Timestamp") + HMAC.
 * Stored in audit_log.bin. Append-only. K_enc is the session encryption key (same for all entries
 * in a run; we use a fixed server-side log key derived from a constant for simplicity so admin can decrypt).
 */
public final class AuditLogger {

    private final ReentrantLock lock = new ReentrantLock();
    private final File logFile;
    private final byte[] kEnc;
    private final byte[] kMac;

    /**
     * @param logFilePath path to audit_log.bin
     * @param kEnc 16-byte AES key for log encryption
     * @param kMac 32-byte HMAC key for log integrity
     */
    public AuditLogger(String logFilePath, byte[] kEnc, byte[] kMac) {
        this.logFile = new File(logFilePath);
        this.kEnc = kEnc;
        this.kMac = kMac;
    }

    /**
     * Append one entry: IV + AES-CBC(entry_plaintext) + HMAC(K_mac, IV || ciphertext).
     */
    public void append(String customerId, String action, long timestamp) throws Exception {
        String plaintext = MessageFormat.formatAuditEntry(customerId, action, timestamp);
        byte[] plainBytes = plaintext.getBytes(java.nio.charset.StandardCharsets.UTF_8);
        byte[] iv = CryptoUtils.generateIV();
        byte[] ciphertext = CryptoUtils.aesEncryptWithIV(kEnc, iv, plainBytes);
        byte[] macInput = new byte[iv.length + ciphertext.length];
        System.arraycopy(iv, 0, macInput, 0, iv.length);
        System.arraycopy(ciphertext, 0, macInput, iv.length, ciphertext.length);
        byte[] mac = CryptoUtils.hmacSha256(kMac, macInput);
        lock.lock();
        try (OutputStream os = Files.newOutputStream(logFile.toPath(), StandardOpenOption.CREATE, StandardOpenOption.APPEND)) {
            os.write(iv);
            os.write(ciphertext);
            os.write(mac);
        } finally {
            lock.unlock();
        }
    }

    /**
     * Read and decrypt all entries (for admin "View Audit Log"). Format per entry: 4-byte cipherLen, IV, ciphertext, MAC.
     */
    public List<String> readAndDecryptAll() throws Exception {
        lock.lock();
        try {
            if (!logFile.exists()) return new ArrayList<>();
            byte[] all = Files.readAllBytes(logFile.toPath());
            List<String> entries = new ArrayList<>();
            DataInputStream dis = new DataInputStream(new ByteArrayInputStream(all));
            while (dis.available() >= 4 + ProtocolConstants.IV_SIZE_BYTES + 1 + 32) {
                int cipherLen = dis.readInt();
                if (cipherLen <= 0 || cipherLen > 1024) break;
                if (dis.available() < ProtocolConstants.IV_SIZE_BYTES + cipherLen + 32) break;
                byte[] iv = new byte[ProtocolConstants.IV_SIZE_BYTES];
                dis.readFully(iv);
                byte[] ciphertext = new byte[cipherLen];
                dis.readFully(ciphertext);
                byte[] mac = new byte[32];
                dis.readFully(mac);
                byte[] macInput = new byte[iv.length + ciphertext.length];
                System.arraycopy(iv, 0, macInput, 0, iv.length);
                System.arraycopy(ciphertext, 0, macInput, iv.length, ciphertext.length);
                byte[] computedMac = CryptoUtils.hmacSha256(kMac, macInput);
                if (!CryptoUtils.constantTimeEquals(computedMac, mac)) continue; // skip corrupted entry
                byte[] plainBytes = CryptoUtils.aesDecryptWithIV(kEnc, iv, ciphertext);
                entries.add(new String(plainBytes, java.nio.charset.StandardCharsets.UTF_8));
            }
            return entries;
        } finally {
            lock.unlock();
        }
    }

    /**
     * Store format: per entry: 4-byte ciphertext length, IV (16), ciphertext, MAC (32).
     * So we can read variable-length entries.
     */
    public void appendWithLength(String customerId, String action, long timestamp) throws Exception {
        String plaintext = MessageFormat.formatAuditEntry(customerId, action, timestamp);
        byte[] plainBytes = plaintext.getBytes(java.nio.charset.StandardCharsets.UTF_8);
        byte[] iv = CryptoUtils.generateIV();
        byte[] ciphertext = CryptoUtils.aesEncryptWithIV(kEnc, iv, plainBytes);
        byte[] macInput = new byte[iv.length + ciphertext.length];
        System.arraycopy(iv, 0, macInput, 0, iv.length);
        System.arraycopy(ciphertext, 0, macInput, iv.length, ciphertext.length);
        byte[] mac = CryptoUtils.hmacSha256(kMac, macInput);
        lock.lock();
        try (DataOutputStream dos = new DataOutputStream(Files.newOutputStream(logFile.toPath(), StandardOpenOption.CREATE, StandardOpenOption.APPEND))) {
            dos.writeInt(ciphertext.length);
            dos.write(iv);
            dos.write(ciphertext);
            dos.write(mac);
        } finally {
            lock.unlock();
        }
    }

    /** Use appendWithLength for new entries so readAndDecryptAll can parse. */
    public void appendEntry(String customerId, String action, long timestamp) throws Exception {
        appendWithLength(customerId, action, timestamp);
    }
}
