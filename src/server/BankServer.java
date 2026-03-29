package vaultlink.server;

import vaultlink.common.CryptoUtils;
import vaultlink.common.ProtocolConstants;

import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * Main server: listens on port 9000, spawns per-client threads for key exchange and transactions.
 * Loads server.properties for username->K_pre, creates AuditLogger with fixed server key for log decryption.
 */
public class BankServer {

    private static final String AUDIT_KEY_SALT = "VaultLinkAuditLogKey2024";

    public static void main(String[] args) throws Exception {
        String configDir = "src/config";
        if (args.length > 0) configDir = args[0];
        File keyFile = new File(configDir, "server.properties");
        ServerKeyStore serverKeys = new ServerKeyStore(keyFile);
        AccountManager accountManager = new AccountManager(ProtocolConstants.ACCOUNTS_FILENAME);
        accountManager.loadFromFile();
        accountManager.seedDefaultUsersIfNeeded();

        // Fixed key for audit log so admin can always decrypt (derive from constant)
        byte[] auditSecret = AUDIT_KEY_SALT.getBytes(StandardCharsets.UTF_8);
        byte[] kEncLog = CryptoUtils.deriveKey(auditSecret, "audit_enc", (byte) 0x01);
        if (kEncLog.length > 16) kEncLog = java.util.Arrays.copyOf(kEncLog, 16);
        byte[] kMacLog = CryptoUtils.deriveKey(auditSecret, "audit_mac", (byte) 0x02);
        AuditLogger auditLogger = new AuditLogger(ProtocolConstants.AUDIT_LOG_FILENAME, kEncLog, kMacLog);

        ServerGUI gui = new ServerGUI(auditLogger, accountManager, serverKeys, keyFile);
        gui.setVisible(true);

        ExecutorService executor = Executors.newCachedThreadPool();
        try (ServerSocket serverSocket = new ServerSocket(ProtocolConstants.SERVER_PORT)) {
            gui.log("Server listening on port " + ProtocolConstants.SERVER_PORT);
            while (true) {
                Socket client = serverSocket.accept();
                gui.log("New connection from " + client.getRemoteSocketAddress());
                executor.submit(new ClientHandler(client, accountManager, auditLogger, serverKeys, gui));
            }
        } finally {
            executor.shutdown();
            try {
                accountManager.saveToFile();
            } catch (IOException e) {
                gui.log("Failed to save accounts: " + e.getMessage());
            }
        }
    }
}