package vaultlink.server;

import vaultlink.common.CryptoUtils;
import vaultlink.common.MessageFormat;
import vaultlink.common.ProtocolConstants;

import java.io.*;
import java.net.Socket;
import java.util.Properties;

/**
 * Per-client thread: full session lifecycle — key exchange, then transaction loop.
 * Reads username from message 1, looks up K_pre, completes key exchange, then handles
 * encrypted transactions until disconnect or logout.
 */
public class ClientHandler implements Runnable {

    private final Socket socket;
    private final AccountManager accountManager;
    private final AuditLogger auditLogger;
    private final Properties serverKeys; // username -> K_pre hex
    private final ServerGUICallback guiCallback;

    public interface ServerGUICallback {
        void log(String message);
        void connectionJoined(String id);
        void connectionLeft(String id);
    }

    public ClientHandler(Socket socket, AccountManager accountManager, AuditLogger auditLogger,
                         Properties serverKeys, ServerGUICallback guiCallback) {
        this.socket = socket;
        this.accountManager = accountManager;
        this.auditLogger = auditLogger;
        this.serverKeys = serverKeys;
        this.guiCallback = guiCallback;
    }

    @Override
    public void run() {
        String clientId = socket.getRemoteSocketAddress().toString();
        if (guiCallback != null) guiCallback.connectionJoined(clientId);
        try (DataInputStream in = new DataInputStream(socket.getInputStream());
             DataOutputStream out = new DataOutputStream(socket.getOutputStream())) {

            // --- Key exchange ---
            KeyExchangeServer.KeyExchangeMessage1 msg1 = KeyExchangeServer.readMessage1(in);
            String username = msg1.username;
            byte[] nClient = msg1.nClient;
            String kPreHex = serverKeys.getProperty(username);
            if (kPreHex == null || kPreHex.isEmpty()) {
                if (guiCallback != null) guiCallback.log("Auth failed: unknown user " + username);
                return;
            }
            byte[] kPre = MessageFormat.decodeKpre(kPreHex.trim());
            byte[] nServer = CryptoUtils.generateNonce();
            KeyExchangeServer.sendMessage2(out, kPre, nClient, nServer);
            if (!KeyExchangeServer.verifyMessage3(in, kPre, nServer)) {
                if (guiCallback != null) guiCallback.log("Auth failed: client did not prove K_pre for " + username);
                return;
            }
            byte[] masterSecret = CryptoUtils.computeMasterSecret(kPre, nClient, nServer);
            KeyExchangeServer.SessionKeys keys = KeyExchangeServer.deriveSessionKeys(masterSecret);
            if (guiCallback != null) guiCallback.log("Authenticated: " + username + " from " + clientId);

            // --- Login: client sends encrypted LOGIN|username|password; server verifies PBKDF2 hash ---
            byte[] loginPlain = TransactionProtocolServer.receiveAndDecrypt(in, keys.kEnc, keys.kMac);
            if (loginPlain == null) {
                if (guiCallback != null) guiCallback.log("MAC failed on login from " + username);
                return;
            }
            String loginStr = new String(loginPlain, java.nio.charset.StandardCharsets.UTF_8);
            String[] loginParts = loginStr.split("\\|", -1);
            if (loginParts.length < 3 || !"LOGIN".equals(loginParts[0])) {
                if (guiCallback != null) guiCallback.log("Invalid login message from " + username);
                return;
            }
            String loginUser = loginParts[1];
            String password = loginParts[2];
            boolean loginOk = false;
            try {
                loginOk = accountManager.verifyPassword(loginUser, password.toCharArray());
            } catch (Exception ignored) {}
            byte[] loginResponse = (loginOk ? "LOGIN_OK" : "LOGIN_FAIL").getBytes(java.nio.charset.StandardCharsets.UTF_8);
            TransactionProtocolServer.encryptAndSend(out, keys.kEnc, keys.kMac, loginResponse);
            if (!loginOk) {
                if (guiCallback != null) guiCallback.log("Login failed (bad password): " + loginUser);
                return;
            }
            if (guiCallback != null) guiCallback.log("User logged in: " + loginUser);

            // --- Transaction loop ---
            while (true) {
                byte[] plaintext = TransactionProtocolServer.receiveAndDecrypt(in, keys.kEnc, keys.kMac);
                if (plaintext == null) {
                    if (guiCallback != null) guiCallback.log("MAC verification failed from " + username);
                    break;
                }
                MessageFormat.TransactionPlaintext tx;
                try {
                    tx = MessageFormat.decodeTransactionPlaintext(plaintext);
                } catch (Exception e) {
                    if (guiCallback != null) guiCallback.log("Invalid transaction format from " + username);
                    break;
                }
                // Ensure customer account exists
                accountManager.ensureAccount(tx.customerId, 0);
                double newBalance;
                String actionDesc;
                switch (tx.action.toUpperCase()) {
                    case "DEPOSIT":
                        newBalance = accountManager.deposit(tx.customerId, tx.amount);
                        actionDesc = "DEPOSIT " + tx.amount;
                        break;
                    case "WITHDRAW":
                        newBalance = accountManager.withdraw(tx.customerId, tx.amount);
                        actionDesc = "WITHDRAW " + tx.amount;
                        break;
                    case "BALANCE":
                        newBalance = accountManager.getBalance(tx.customerId);
                        actionDesc = "BALANCE";
                        break;
                    case "LOGOUT":
                        if (guiCallback != null) guiCallback.log("Logout: " + username);
                        return;
                    default:
                        newBalance = -1;
                        actionDesc = "UNKNOWN";
                }
                boolean success = newBalance >= 0;
                String message = success ? "OK" : (tx.action.equalsIgnoreCase("WITHDRAW") ? "Insufficient funds" : "Error");
                if (success && !"BALANCE".equalsIgnoreCase(tx.action)) {
                    try {
                        auditLogger.appendEntry(tx.customerId, actionDesc, tx.timestamp);
                    } catch (Exception e) {
                        if (guiCallback != null) guiCallback.log("Audit log error: " + e.getMessage());
                    }
                }
                if ("BALANCE".equalsIgnoreCase(tx.action) && success) {
                    try {
                        auditLogger.appendEntry(tx.customerId, "BALANCE_INQUIRY", tx.timestamp);
                    } catch (Exception e) { /* ignore */ }
                }
                double balanceToSend = newBalance >= 0 ? newBalance : accountManager.getBalance(tx.customerId);
                byte[] responsePlain = MessageFormat.encodeResponsePlaintext(success, message, balanceToSend);
                TransactionProtocolServer.encryptAndSend(out, keys.kEnc, keys.kMac, responsePlain);
            }
        } catch (IOException e) {
            if (guiCallback != null) guiCallback.log("Client disconnected: " + clientId + " - " + e.getMessage());
        } catch (Exception e) {
            if (guiCallback != null) guiCallback.log("Error: " + e.getMessage());
        } finally {
            if (guiCallback != null) guiCallback.connectionLeft(clientId);
            try { socket.close(); } catch (IOException ignored) {}
        }
    }
}
