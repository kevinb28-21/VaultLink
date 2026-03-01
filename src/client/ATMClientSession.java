package vaultlink.client;

import vaultlink.common.MessageFormat;
import vaultlink.common.ProtocolConstants;

import java.io.*;
import java.net.Socket;
import java.nio.charset.StandardCharsets;

/**
 * ATM client: connects to server, performs key exchange, login, then provides session for transactions.
 * Session keys and streams are held for the lifetime of the connection.
 */
public class ATMClientSession {

    private final Socket socket;
    private final DataInputStream in;
    private final DataOutputStream out;
    private final vaultlink.server.KeyExchangeServer.SessionKeys keys;
    private final String customerId;
    private volatile boolean closed;

    private ATMClientSession(Socket socket, DataInputStream in, DataOutputStream out,
                             vaultlink.server.KeyExchangeServer.SessionKeys keys, String customerId) {
        this.socket = socket;
        this.in = in;
        this.out = out;
        this.keys = keys;
        this.customerId = customerId;
    }

    public String getCustomerId() { return customerId; }
    public boolean isClosed() { return closed; }

    /**
     * Connect, key exchange, login. Returns session or null on failure.
     */
    public static ATMClientSession connect(String host, int port, String username, String password, byte[] kPre) throws Exception {
        Socket socket = new Socket(host, port);
        DataInputStream in = new DataInputStream(socket.getInputStream());
        DataOutputStream out = new DataOutputStream(socket.getOutputStream());

        // Step 1: send username + N_client
        byte[] nClient = KeyExchangeClient.sendMessage1(out, username);
        // Step 2: receive N_client, N_server, E(K_pre, token)
        byte[] nServer = KeyExchangeClient.readMessage2(in, kPre, nClient);
        // Step 3: send E(K_pre, N_server)
        KeyExchangeClient.sendMessage3(out, kPre, nServer);
        // Derive session keys
        vaultlink.server.KeyExchangeServer.SessionKeys keys = KeyExchangeClient.deriveSessionKeys(kPre, nClient, nServer);

        // Login over secure channel
        String loginMsg = "LOGIN|" + username + "|" + password;
        TransactionProtocolClient.encryptAndSend(out, keys.kEnc, keys.kMac, loginMsg.getBytes(StandardCharsets.UTF_8));
        byte[] loginResponse = TransactionProtocolClient.receiveAndDecrypt(in, keys.kEnc, keys.kMac);
        if (loginResponse == null || !"LOGIN_OK".equals(new String(loginResponse, StandardCharsets.UTF_8))) {
            socket.close();
            return null;
        }

        return new ATMClientSession(socket, in, out, keys, username);
    }

    /** Send transaction and return response plaintext; null on error or MAC failure. */
    public MessageFormat.ResponsePlaintext request(String action, double amount) throws Exception {
        if (closed) return null;
        long timestamp = System.currentTimeMillis();
        byte[] nonce = vaultlink.common.CryptoUtils.generateNonce();
        byte[] plaintext = MessageFormat.encodeTransactionPlaintext(customerId, action, amount, timestamp, nonce);
        TransactionProtocolClient.encryptAndSend(out, keys.kEnc, keys.kMac, plaintext);
        byte[] response = TransactionProtocolClient.receiveAndDecrypt(in, keys.kEnc, keys.kMac);
        if (response == null) return null;
        return MessageFormat.decodeResponsePlaintext(response);
    }

    /** Send LOGOUT and close. */
    public void logout() {
        if (closed) return;
        try {
            byte[] plaintext = MessageFormat.encodeTransactionPlaintext(customerId, "LOGOUT", 0, System.currentTimeMillis(), vaultlink.common.CryptoUtils.generateNonce());
            TransactionProtocolClient.encryptAndSend(out, keys.kEnc, keys.kMac, plaintext);
        } catch (Exception ignored) {}
        closed = true;
        try { socket.close(); } catch (IOException ignored) {}
    }
}
