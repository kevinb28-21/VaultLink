package vaultlink.server;

import vaultlink.common.CryptoUtils;
import vaultlink.common.ProtocolConstants;

import java.nio.charset.StandardCharsets;

/**
 * Generates a sample audit_log.bin for inclusion in deliverables.
 * Uses the same key derivation as BankServer so "View Audit Log" can decrypt it.
 */
public class GenerateAuditLogSample {

    public static void main(String[] args) throws Exception {
        String path = args.length > 0 ? args[0] : ProtocolConstants.AUDIT_LOG_FILENAME;
        byte[] auditSecret = "VaultLinkAuditLogKey2024".getBytes(StandardCharsets.UTF_8);
        byte[] kEncLog = CryptoUtils.deriveKey(auditSecret, "audit_enc", (byte) 0x01);
        if (kEncLog.length > 16) kEncLog = java.util.Arrays.copyOf(kEncLog, 16);
        byte[] kMacLog = CryptoUtils.deriveKey(auditSecret, "audit_mac", (byte) 0x02);
        AuditLogger logger = new AuditLogger(path, kEncLog, kMacLog);
        long t = System.currentTimeMillis();
        logger.appendEntry("user1", "DEPOSIT 100.0", t);
        logger.appendEntry("user2", "WITHDRAW 50.0", t + 1);
        logger.appendEntry("user1", "BALANCE_INQUIRY", t + 2);
        logger.appendEntry("user3", "DEPOSIT 200.0", t + 3);
        System.out.println("Sample audit log written to " + path);
    }
}
