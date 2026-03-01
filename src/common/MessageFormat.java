package vaultlink.common;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

/**
 * Serialization helpers for protocol messages (plaintext and wire format).
 */
public final class MessageFormat {

    private static final String DELIM = "|";
    private static final String DELIM_REGEX = "\\|";

    /**
     * Decode pre-shared key from config. Accepts hex (32 hex chars = 16 bytes) or Base64.
     */
    public static byte[] decodeKpre(String kPreStr) {
        if (kPreStr == null || (kPreStr = kPreStr.trim()).isEmpty()) throw new IllegalArgumentException("K_pre is empty");
        byte[] decoded;
        if (kPreStr.length() == 32 && kPreStr.matches("[0-9A-Fa-f]+")) {
            decoded = hexDecode(kPreStr);
        } else {
            decoded = Base64.getDecoder().decode(kPreStr);
        }
        if (decoded.length < ProtocolConstants.AES_KEY_SIZE_BYTES)
            throw new IllegalArgumentException("K_pre must be at least 16 bytes");
        byte[] key = new byte[ProtocolConstants.AES_KEY_SIZE_BYTES];
        System.arraycopy(decoded, 0, key, 0, ProtocolConstants.AES_KEY_SIZE_BYTES);
        return key;
    }

    private static byte[] hexDecode(String hex) {
        int len = hex.length();
        byte[] out = new byte[len / 2];
        for (int i = 0; i < len; i += 2)
            out[i / 2] = (byte) Integer.parseInt(hex.substring(i, i + 2), 16);
        return out;
    }

    /**
     * Audit log entry plaintext: CustomerID | Action | Timestamp
     */
    public static String formatAuditEntry(String customerId, String action, long timestamp) {
        return customerId + DELIM + action + DELIM + timestamp;
    }

    public static String[] parseAuditEntry(String line) {
        if (line == null || line.isEmpty()) return new String[0];
        return line.split(DELIM_REGEX, -1);
    }

    /**
     * Transaction plaintext: customer_id | action | amount | timestamp | nonce
     * action: DEPOSIT, WITHDRAW, BALANCE
     */
    public static byte[] encodeTransactionPlaintext(String customerId, String action, double amount, long timestamp, byte[] nonce) {
        String s = customerId + DELIM + action + DELIM + amount + DELIM + timestamp + DELIM + Base64.getEncoder().encodeToString(nonce);
        return s.getBytes(StandardCharsets.UTF_8);
    }

    public static TransactionPlaintext decodeTransactionPlaintext(byte[] plaintext) {
        String s = new String(plaintext, StandardCharsets.UTF_8);
        String[] parts = s.split(DELIM_REGEX, -1);
        if (parts.length < 5) throw new IllegalArgumentException("Invalid transaction plaintext");
        String customerId = parts[0];
        String action = parts[1];
        double amount = Double.parseDouble(parts[2]);
        long timestamp = Long.parseLong(parts[3]);
        byte[] nonce = Base64.getDecoder().decode(parts[4]);
        return new TransactionPlaintext(customerId, action, amount, timestamp, nonce);
    }

    /**
     * Response plaintext: success | message | balance
     */
    public static byte[] encodeResponsePlaintext(boolean success, String message, double balance) {
        String s = success + DELIM + (message != null ? message : "") + DELIM + balance;
        return s.getBytes(StandardCharsets.UTF_8);
    }

    public static ResponsePlaintext decodeResponsePlaintext(byte[] plaintext) {
        String s = new String(plaintext, StandardCharsets.UTF_8);
        String[] parts = s.split(DELIM_REGEX, -1);
        if (parts.length < 3) throw new IllegalArgumentException("Invalid response plaintext");
        boolean success = Boolean.parseBoolean(parts[0]);
        String message = parts[1];
        double balance = Double.parseDouble(parts[2]);
        return new ResponsePlaintext(success, message, balance);
    }

    public static final class TransactionPlaintext {
        public final String customerId;
        public final String action;
        public final double amount;
        public final long timestamp;
        public final byte[] nonce;

        public TransactionPlaintext(String customerId, String action, double amount, long timestamp, byte[] nonce) {
            this.customerId = customerId;
            this.action = action;
            this.amount = amount;
            this.timestamp = timestamp;
            this.nonce = nonce;
        }
    }

    public static final class ResponsePlaintext {
        public final boolean success;
        public final String message;
        public final double balance;

        public ResponsePlaintext(boolean success, String message, double balance) {
            this.success = success;
            this.message = message;
            this.balance = balance;
        }
    }
}
