package vaultlink.client;

import vaultlink.common.CryptoUtils;
import vaultlink.common.ProtocolConstants;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;

/**
 * Client-side authenticated key distribution.
 * Step 1: Send {username, N_client}
 * Step 2: Receive {N_client, N_server, E(K_pre, session_token)}, verify N_client, decrypt token
 * Step 3: Send E(K_pre, N_server)
 * Then derive Master Secret = HMAC-SHA256(K_pre, N_client || N_server) and K_enc, K_mac.
 */
public class KeyExchangeClient {

    /**
     * Send message 1: username + N_client (random nonce).
     */
    public static byte[] sendMessage1(DataOutputStream out, String username) throws Exception {
        byte[] nClient = CryptoUtils.generateNonce();
        out.writeUTF(username);
        out.write(nClient);
        out.flush();
        return nClient;
    }

    /**
     * Read message 2: N_client, N_server, E(K_pre, session_token). Verify N_client matches, decrypt token.
     */
    public static byte[] readMessage2(DataInputStream in, byte[] kPre, byte[] nClientSent) throws Exception {
        byte[] nClientRecv = new byte[ProtocolConstants.IV_SIZE_BYTES];
        in.readFully(nClientRecv);
        byte[] nServer = new byte[ProtocolConstants.IV_SIZE_BYTES];
        in.readFully(nServer);
        int encLen = in.readInt();
        byte[] encryptedToken = new byte[encLen];
        in.readFully(encryptedToken);
        // Verify server echoed our nonce
        if (!java.util.Arrays.equals(nClientRecv, nClientSent))
            throw new SecurityException("Server did not echo N_client");
        // Decrypt session token (server proves knowledge of K_pre)
        byte[] token = CryptoUtils.aesDecrypt(kPre, encryptedToken);
        if (!java.util.Arrays.equals(token, nServer))
            throw new SecurityException("Session token mismatch");
        return nServer;
    }

    /**
     * Send message 3: E(K_pre, N_server) — client proves knowledge of K_pre.
     */
    public static void sendMessage3(DataOutputStream out, byte[] kPre, byte[] nServer) throws Exception {
        byte[] encrypted = CryptoUtils.aesEncrypt(kPre, nServer);
        out.writeInt(encrypted.length);
        out.write(encrypted);
        out.flush();
    }

    /**
     * Derive Master Secret and session keys (K_enc, K_mac).
     */
    public static vaultlink.server.KeyExchangeServer.SessionKeys deriveSessionKeys(byte[] kPre, byte[] nClient, byte[] nServer) throws Exception {
        byte[] masterSecret = CryptoUtils.computeMasterSecret(kPre, nClient, nServer);
        byte[] kEnc = CryptoUtils.deriveKenc(masterSecret);
        byte[] kMac = CryptoUtils.deriveKmac(masterSecret);
        return new vaultlink.server.KeyExchangeServer.SessionKeys(kEnc, kMac);
    }
}
