package vaultlink.server;

import vaultlink.common.CryptoUtils;
import vaultlink.common.MessageFormat;
import vaultlink.common.ProtocolConstants;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.util.Arrays;

/**
 * Secure transaction protocol (server side).
 * Receive: IV + AES-CBC(K_enc, plaintext) + HMAC(K_mac, IV || ciphertext).
 * Verify HMAC first (encrypt-then-MAC), then decrypt, process, respond with same format.
 */
public final class TransactionProtocolServer {

    /**
     * Read protected message: 4-byte len, then IV (16), ciphertext, MAC (32).
     * Returns decrypted plaintext or null if verification fails.
     */
    public static byte[] receiveAndDecrypt(DataInputStream in, byte[] kEnc, byte[] kMac) throws Exception {
        int totalLen = in.readInt();
        if (totalLen <= 0 || totalLen > 1024 * 1024) throw new IOException("Invalid message length");
        byte[] iv = new byte[ProtocolConstants.IV_SIZE_BYTES];
        in.readFully(iv);
        int cipherLen = totalLen - ProtocolConstants.IV_SIZE_BYTES - ProtocolConstants.HMAC_KEY_SIZE_BYTES; // MAC is 32 bytes
        if (cipherLen < 0) throw new IOException("Invalid message structure");
        byte[] ciphertext = new byte[cipherLen];
        in.readFully(ciphertext);
        byte[] receivedMac = new byte[ProtocolConstants.HMAC_KEY_SIZE_BYTES];
        in.readFully(receivedMac);
        // Encrypt-then-MAC: verify HMAC over IV || ciphertext
        byte[] macInput = new byte[iv.length + ciphertext.length];
        System.arraycopy(iv, 0, macInput, 0, iv.length);
        System.arraycopy(ciphertext, 0, macInput, iv.length, ciphertext.length);
        byte[] computedMac = CryptoUtils.hmacSha256(kMac, macInput);
        if (!CryptoUtils.constantTimeEquals(computedMac, receivedMac))
            return null; // Integrity check failed
        return CryptoUtils.aesDecryptWithIV(kEnc, iv, ciphertext);
    }

    /**
     * Encrypt plaintext and MAC, then send: 4-byte total length, IV, ciphertext, MAC.
     */
    public static void encryptAndSend(DataOutputStream out, byte[] kEnc, byte[] kMac, byte[] plaintext) throws Exception {
        byte[] iv = CryptoUtils.generateIV();
        byte[] ciphertext = CryptoUtils.aesEncryptWithIV(kEnc, iv, plaintext);
        byte[] macInput = new byte[iv.length + ciphertext.length];
        System.arraycopy(iv, 0, macInput, 0, iv.length);
        System.arraycopy(ciphertext, 0, macInput, iv.length, ciphertext.length);
        byte[] mac = CryptoUtils.hmacSha256(kMac, macInput);
        int totalLen = iv.length + ciphertext.length + mac.length;
        out.writeInt(totalLen);
        out.write(iv);
        out.write(ciphertext);
        out.write(mac);
        out.flush();
    }
}
