package vaultlink.server;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.Properties;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Thread-safe username -> K_pre (hex) map for key exchange. Loaded from server.properties;
 * new registrations persist the full map back to disk.
 */
public final class ServerKeyStore {

    private final ConcurrentHashMap<String, String> keys = new ConcurrentHashMap<>();
    private final File keyFile;

    public ServerKeyStore(File keyFile) throws IOException {
        this.keyFile = keyFile;
        if (keyFile.exists()) {
            Properties p = new Properties();
            try (Reader r = new InputStreamReader(Files.newInputStream(keyFile.toPath()), StandardCharsets.UTF_8)) {
                p.load(r);
            }
            for (String name : p.stringPropertyNames()) {
                if (!name.startsWith("#") && !name.trim().isEmpty())
                    keys.put(name.trim(), p.getProperty(name).trim());
            }
        }
    }

    public String getKpreHex(String username) {
        return keys.get(username);
    }

    /** Register or update K_pre for a username and persist to server.properties. */
    public synchronized void putKpreAndSave(String username, String kPreHex) throws IOException {
        keys.put(username.trim(), kPreHex.trim());
        save();
    }

    /** Remove K_pre for a username and persist. Returns true if an entry existed. */
    public synchronized boolean removeKpreAndSave(String username) throws IOException {
        if (username == null) return false;
        if (keys.remove(username.trim()) == null) return false;
        save();
        return true;
    }

    private void save() throws IOException {
        try (PrintWriter w = new PrintWriter(Files.newBufferedWriter(keyFile.toPath(), StandardCharsets.UTF_8))) {
            w.println("# Server mapping: username -> K_pre (32 hex chars = 16 bytes)");
            for (java.util.Map.Entry<String, String> e : keys.entrySet()) {
                w.println(e.getKey() + "=" + e.getValue());
            }
        }
    }
}
