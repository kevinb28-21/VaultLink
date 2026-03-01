package vaultlink.server;

import vaultlink.common.CryptoUtils;
import vaultlink.common.ProtocolConstants;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.util.Arrays;

/**
 * Server-side authenticated key distribution.
 * Protocol: ATM sends {username, N_client}; Server replies {N_client, N_server, E(K_pre, session_token)};
 * ATM replies {E(K_pre, N_server)}; both derive Master Secret = HMAC(K_pre, N_client || N_server).
 */
public class KeyExchangeServer {

    /**
     * Read message 1 from ATM: username (UTF string) + N_client (16 bytes).
     */
    public static KeyExchangeMessage1 readMessage1(DataInputStream in) throws IOException {
        String username = in.readUTF();
        byte[] nClient = new byte[ProtocolConstants.IV_SIZE_BYTES];
        in.readFully(nClient);
        return new KeyExchangeMessage1(username, nClient);
    }

    /**
     * Send message 2 to ATM: N_client, N_server, E(K_pre, session_token).
     * Session token is N_server for simplicity (proves server knows K_pre).
     */
    public static void sendMessage2(DataOutputStream out, byte[] kPre, byte[] nClient, byte[] nServer) throws Exception {
        out.write(nClient);
        out.write(nServer);
        // E(K_pre, session_token) where session_token = nServer
        byte[] encryptedToken = CryptoUtils.aesEncrypt(kPre, nServer);
        out.writeInt(encryptedToken.length);
        out.write(encryptedToken);
        out.flush();
    }

    /**
     * Read message 3 from ATM: E(K_pre, N_server). Verify by decrypting and comparing to nServer.
     */
    public static boolean verifyMessage3(DataInputStream in, byte[] kPre, byte[] nServer) throws Exception {
        int len = in.readInt();
        byte[] encrypted = new byte[len];
        in.readFully(encrypted);
        byte[] decrypted = CryptoUtils.aesDecrypt(kPre, encrypted);
        return Arrays.equals(decrypted, nServer);
    }

    /**
     * Derive session keys from Master Secret (same as client).
     */
    public static SessionKeys deriveSessionKeys(byte[] masterSecret) throws Exception {
        byte[] kEnc = CryptoUtils.deriveKenc(masterSecret);
        byte[] kMac = CryptoUtils.deriveKmac(masterSecret);
        return new SessionKeys(kEnc, kMac);
    }

    public static final class KeyExchangeMessage1 {
        public final String username;
        public final byte[] nClient;

        public KeyExchangeMessage1(String username, byte[] nClient) {
            this.username = username;
            this.nClient = nClient;
        }
    }

    public static final class SessionKeys {
        public final byte[] kEnc;
        public final byte[] kMac;

        public SessionKeys(byte[] kEnc, byte[] kMac) {
            this.kEnc = kEnc;
            this.kMac = kMac;
        }
    }
}
