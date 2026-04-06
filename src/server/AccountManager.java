package vaultlink.server;

import vaultlink.common.CryptoUtils;
import vaultlink.common.ProtocolConstants;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Thread-safe in-memory account store. Balances keyed by customer_id.
 * Passwords stored as PBKDF2 hashes (salt||hash). Optionally persist to accounts.json on shutdown.
 */
public final class AccountManager {

    private final ConcurrentHashMap<String, Double> balances = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, String> passwordHashes = new ConcurrentHashMap<>(); // base64(salt) + ":" + base64(hash)
    private final String accountsPath;

    public AccountManager(String accountsPath) {
        this.accountsPath = accountsPath != null ? accountsPath : ProtocolConstants.ACCOUNTS_FILENAME;
    }

    /** Register or update password (store PBKDF2 hash). */
    public void setPassword(String username, char[] password) throws Exception {
        byte[] salt = CryptoUtils.generateSalt();
        byte[] hash = CryptoUtils.pbkdf2(password, salt, 10000, 32);
        String encoded = java.util.Base64.getEncoder().encodeToString(salt) + ":" + java.util.Base64.getEncoder().encodeToString(hash);
        passwordHashes.put(username, encoded);
    }

    /** Verify password against stored hash. */
    public boolean verifyPassword(String username, char[] password) throws Exception {
        String stored = passwordHashes.get(username);
        if (stored == null) return false;
        int colon = stored.indexOf(':');
        if (colon <= 0) return false;
        byte[] salt = java.util.Base64.getDecoder().decode(stored.substring(0, colon));
        byte[] expectedHash = java.util.Base64.getDecoder().decode(stored.substring(colon + 1));
        byte[] actualHash = CryptoUtils.pbkdf2(password, salt, 10000, 32);
        return CryptoUtils.constantTimeEquals(expectedHash, actualHash);
    }

    /** Ensure account exists with initial balance. */
    public void ensureAccount(String customerId, double initialBalance) {
        balances.putIfAbsent(customerId, initialBalance);
    }

    public double getBalance(String customerId) {
        return balances.getOrDefault(customerId, 0.0);
    }

    /** Deposit: add amount, return new balance or -1 on error. */
    public synchronized double deposit(String customerId, double amount) {
        if (amount <= 0) return -1;
        ensureAccount(customerId, 0);
        double prev = balances.get(customerId);
        double next = prev + amount;
        balances.put(customerId, next);
        return next;
    }

    /** Withdraw: subtract amount if sufficient funds. Return new balance or -1 if insufficient. */
    public synchronized double withdraw(String customerId, double amount) {
        if (amount <= 0) return -1;
        ensureAccount(customerId, 0);
        double prev = balances.get(customerId);
        if (prev < amount) return -1;
        double next = prev - amount;
        balances.put(customerId, next);
        return next;
    }

    public void loadFromFile() throws IOException {
        File f = new File(accountsPath);
        if (!f.exists()) return;
        try (BufferedReader r = Files.newBufferedReader(f.toPath(), StandardCharsets.UTF_8)) {
            String line;
            while ((line = r.readLine()) != null) {
                line = line.trim();
                if (line.isEmpty() || line.startsWith("#")) continue;
                String[] parts = line.split("\\|");
                if (parts.length >= 2) {
                    String customerId = parts[0].trim();
                    double bal = Double.parseDouble(parts[1].trim());
                    balances.put(customerId, bal);
                    if (parts.length >= 3) passwordHashes.put(customerId, parts[2].trim());
                }
            }
        }
    }

    /** Persist balances (and optionally hashes) to accounts.json. Format: customerId|balance|passwordHash per line. */
    public void saveToFile() throws IOException {
        try (PrintWriter w = new PrintWriter(Files.newBufferedWriter(new File(accountsPath).toPath(), StandardCharsets.UTF_8))) {
            for (String customerId : balances.keySet()) {
                double bal = balances.get(customerId);
                String hash = passwordHashes.getOrDefault(customerId, "");
                w.println(customerId + "|" + bal + "|" + hash);
            }
        }
    }

    /** Remove balance and password hash for a user. Returns true if anything was removed. */
    public synchronized boolean removeAccount(String username) {
        if (username == null || (username = username.trim()).isEmpty()) return false;
        boolean hadBalance = balances.remove(username) != null;
        boolean hadPassword = passwordHashes.remove(username) != null;
        return hadBalance || hadPassword;
    }

    /** Seed user1, user2, user3 with default passwords if not already present (for demo). */
    public void seedDefaultUsersIfNeeded() throws Exception {
        String[] users = { "user1", "user2", "user3" };
        String[] passw = { "password1", "password2", "password3" };
        for (int i = 0; i < users.length; i++) {
            if (!passwordHashes.containsKey(users[i])) {
                setPassword(users[i], passw[i].toCharArray());
                ensureAccount(users[i], 1000.0);
            }
        }
    }
}
